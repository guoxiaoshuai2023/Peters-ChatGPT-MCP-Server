"""Explicitly started loopback listener. The existing human origin is separate."""

from argparse import ArgumentParser
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import stat

import uvicorn

from .agent_file_access import create_agent_file_app
from .agent_file_auth import MachineAccessVerifier
from .agent_file_policy import AgentFilePolicy
from .agent_file_protection import build_protections, canonical, protection_arguments


def _read_operator_config(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > 65536):
            raise ValueError('Use a private, owned Access configuration.')
        payload = stream.read(65537)
        if len(payload) != before.st_size or _stamp(before) != _stamp(os.fstat(stream.fileno())):
            raise ValueError('Access configuration changed.')
        return payload


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class AccessConfigProtection:
    def __init__(self, base, path):
        self.base = base
        self.path = path
        self.digest = hashlib.sha256(_read_operator_config(path)).digest()
        self.protected_paths = base.protected_paths

    def health(self):
        if hashlib.sha256(_read_operator_config(self.path)).digest() != self.digest:
            raise ValueError('Restart to change the Agent Access configuration.')
        return self.base.health(), self.digest

    def excludes(self, path):
        return self.base.excludes(path)


def _audit(path):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Audit path must be an owned private file.')
    finally:
        os.close(fd)
    logger = logging.getLogger('peters.agent_file_read')
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(path, maxBytes=1048576, backupCount=3, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    return logger, handler


def main():
    parser = ArgumentParser(description=__doc__)
    for flag in ('projects', 'state-directory', 'access-config'):
        parser.add_argument('--' + flag, type=canonical, required=True)
    protection_arguments(parser)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        if not 1 <= args.port <= 65535:
            raise ValueError('Invalid port.')
        access = json.loads(_read_operator_config(args.access_config))
        if set(access) != {'issuer', 'audience', 'public_hostname'}:
            raise ValueError('Invalid Agent Access configuration.')
        hostname = access['public_hostname']
        if not isinstance(hostname, str) or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', hostname):
            raise ValueError('Invalid dedicated hostname.')
        verifier = MachineAccessVerifier(access['issuer'], access['audience'])
        policy = AgentFilePolicy(args.projects, args.state_directory)
        active = policy.snapshot()
        registry, base = build_protections(args)
        if not args.access_config.is_relative_to(args.state_directory):
            raise ValueError('Agent Access configuration belongs under Agent state.')
        protections = AccessConfigProtection(base, args.access_config)
        catalog = policy.catalog_for(active, private_registry=registry, agent_history_policy=protections)
        with registry.read_guard():
            listed = catalog.list_projects()['projects']
            if {p['id'] for p in listed} != {p['id'] for p in active.projects['projects']}:
                raise ValueError('An approved project could not be verified.')
            for project_id, worktree_id in active.roots:
                policy.verify_root_scope(active, project_id, worktree_id, private_registry=registry,
                                         agent_history_policy=protections)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f'Agent file origin configuration failed ({getattr(error, "code", "configuration_invalid")}).\n')
    if args.check:
        print('Agent file origin configuration verified. No server started.')
        return

    previous_umask = os.umask(0o077)
    audit, handler = _audit(args.state_directory / 'agent-remote-audit.jsonl')
    try:
        app = create_agent_file_app(policy, verifier, hostname, registry=registry, protections=protections, audit=audit)
        uvicorn.run(app, host='127.0.0.1', port=args.port, proxy_headers=False, access_log=False,
                    log_level='warning', limit_concurrency=16, timeout_keep_alive=10)
    finally:
        audit.removeHandler(handler)
        handler.close()
        os.umask(previous_umask)


if __name__ == '__main__':
    main()
