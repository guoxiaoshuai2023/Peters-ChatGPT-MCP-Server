"""Bounded local receiver processes; no publication or source persistence.

macOS libproc structures are private ABI, NOT stable public API. This adapter is
validated on the supported host; wrong ABI size or unknown observation fails
closed. No numeric PID signals are sent to non-child processes.
"""
import ctypes
import errno
import hashlib
import hmac
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import sys
import threading
import time

from .catalog import AccessError
from .file_source import receive_file, SourceError
from .private_roots import _directory

MAX_MESSAGE = 128 * 1024  # Policy JSON <=64 KiB plus native URL <=16 KiB and bounded metadata.

class Isolated(AccessError):
    def __init__(self, message):
        super().__init__(message, code='writer_stop_pending')

class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid',
        'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in
                 ('nfiles', 'pgid', 'jobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
                 ('start_usec', ctypes.c_uint64)]


def boot_session():
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.sysctlbyname
    function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                         ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    buf = ctypes.create_string_buffer(128)
    size = ctypes.c_size_t(len(buf))
    if function(b'kern.bootsessionuuid', buf, ctypes.byref(size), None, 0):
        raise Isolated('boot_identity_unavailable')
    return buf.value.decode('ascii')


def process_identity(pid):
    if sys.platform != 'darwin' or not hasattr(select, 'kqueue'):
        raise Isolated('unsupported_platform')
    if type(pid) is not int or pid <= 0:
        raise Isolated('invalid_process_identity')
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    function = lib.proc_pidinfo
    function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                         ctypes.c_void_p, ctypes.c_int]
    function.restype = ctypes.c_int
    info = BsdInfo()
    result = function(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if result != ctypes.sizeof(info) or info.pid != pid or info.uid != os.getuid():
        raise Isolated('process_identity_unavailable')
    return {'boot': boot_session(), 'pid': pid, 'uid': info.uid,
            'start_sec': info.start_sec, 'start_usec': info.start_usec}


class ExitBarrier:
    def __init__(self, identity, *, observe=process_identity, queue_factory=None):
        self.identity = identity
        self.queue = None
        self.exited = False
        try:
            if queue_factory is None:
                if not hasattr(select, 'kqueue'):
                    raise Isolated('unsupported_platform')
                queue_factory = select.kqueue
            if observe(identity['pid']) != identity:
                raise Isolated('process_instance_mismatch')
            self.queue = queue_factory()
            event = select.kevent(identity['pid'], filter=select.KQ_FILTER_PROC,
                                  flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                                  fflags=select.KQ_NOTE_EXIT)
            self.queue.control([event], 0, 0)
            if observe(identity['pid']) != identity:
                raise Isolated('process_instance_changed_during_registration')
        except Exception as exc:
            self.close()
            if isinstance(exc, Isolated):
                raise
            raise Isolated('exit_observation_unavailable') from None

    def wait(self, timeout):
        if self.exited:
            return True
        if self.queue is None:
            raise Isolated('exit_observation_closed')
        try:
            events = self.queue.control(None, 1, timeout)
        except OSError:
            raise Isolated('exit_observation_failed') from None
        for event in events:
            if event.flags & select.KQ_EV_ERROR:
                raise Isolated('exit_observation_failed')
            if (event.ident == self.identity['pid'] and event.filter == select.KQ_FILTER_PROC
                    and event.fflags & select.KQ_NOTE_EXIT):
                self.exited = True
        return self.exited

    def close(self):
        if self.queue is not None:
            self.queue.close()
            self.queue = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _send(sock, value):
    raw = _json(value) + b'\n'
    if len(raw) > MAX_MESSAGE:
        raise Isolated('receiver_message_limit')
    sock.sendall(raw)


def _recv(sock):
    raw = bytearray()
    while b'\n' not in raw:
        chunk = sock.recv(min(4096, MAX_MESSAGE + 1 - len(raw)))
        if not chunk or len(raw) + len(chunk) > MAX_MESSAGE:
            raise Isolated('receiver_message_invalid')
        raw.extend(chunk)
    value = json.loads(bytes(raw).split(b'\n', 1)[0])
    if not isinstance(value, dict):
        raise Isolated('receiver_message_invalid')
    return value


def atomic_json(directory, name, value):
    fd = _directory(directory)
    temporary = '.record-' + secrets.token_hex(16)
    try:
        writer = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(writer, 'wb') as stream:
            stream.write(_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def _permission(directory):
    parent = _directory(directory)
    try:
        fd = os.open('permit.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_MESSAGE:
                raise Isolated('receiver_permission_invalid')
            return json.loads(os.read(fd, MAX_MESSAGE))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _child(directory, nonce, attempt, generation, revision, spool_identity, boot_pipe,
           receiver, min_free_bytes):
    identity = process_identity(os.getpid())
    state_lock = threading.Lock()
    stop = threading.Event()
    state = {'state': 'awaiting_permission', 'checkpoint': None, 'writer_closed': True}
    worker = None
    born = time.monotonic()

    def run_transfer(request):
        output = root = None
        try:
            permit = _permission(directory)
            expected = {'identity': identity, 'attempt': attempt, 'generation': generation,
                        'revision': revision, 'nonce': nonce, 'spool_identity': spool_identity}
            if permit != expected:
                raise Isolated('receiver_permission_mismatch')
            root = _directory(directory)
            output = os.open('payload', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=root)
            info = os.fstat(output)
            if ([info.st_dev, info.st_ino] != spool_identity or info.st_nlink != 1
                    or not stat.S_ISREG(info.st_mode) or info.st_size != 0):
                raise Isolated('spool_identity_changed')

            def check_stop():
                if stop.is_set():
                    return True
                space = os.fstatvfs(output)
                if space.f_bavail * space.f_frsize < min_free_bytes:
                    raise SourceError('insufficient_space')
                return False

            def checkpoint(value):
                with state_lock:
                    state['checkpoint'] = value

            receipt = receiver(request['file'], output, request['sources'],
                               expected_sha256=request.get('expected_sha256'),
                               expected_size_bytes=request.get('expected_size_bytes'),
                               stop=check_stop, on_checkpoint=checkpoint)
            os.close(output)
            output = None
            os.fsync(root)
            with state_lock:
                state.update(state='received', receipt=receipt, writer_closed=True)
        except BaseException as exc:
            # Never retain raw exception text, request fields, or provider URLs.
            code = exc.code if isinstance(exc, (SourceError, AccessError)) else 'receiver_failed'
            with state_lock:
                state.update(state='failed', error_code=code)
        finally:
            request.clear()
            if output is not None:
                os.close(output)
            if root is not None:
                os.close(root)
            with state_lock:
                state['writer_closed'] = True

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(.2)
        boot_pipe.send({'identity': identity, 'port': listener.getsockname()[1]})
        boot_pipe.close()
        while True:
            if worker is None and time.monotonic() - born > 30:
                return  # Never-permitted orphan owns no write FD or source bytes.
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(1)
                try:
                    message = _recv(client)
                    if (not hmac.compare_digest(str(message.get('nonce', '')), nonce)
                            or message.get('attempt') != attempt):
                        _send(client, {'state': 'denied'})
                        continue
                    action = message.get('action')
                    if action == 'start' and worker is None:
                        # Thread belongs only to this disposable receiver process.
                        worker = threading.Thread(target=run_transfer, args=(message['request'],),
                                                  name='file-writer', daemon=False)
                        with state_lock:
                            state['state'] = 'receiving'
                            state['writer_closed'] = False
                        worker.start()
                    elif action == 'stop':
                        stop.set()
                    elif action == 'release':
                        if worker is None or not worker.is_alive():
                            _send(client, {'state': 'exiting', 'identity': identity, 'attempt': attempt})
                            return
                    with state_lock:
                        answer = dict(state, identity=identity, attempt=attempt)
                    _send(client, answer)
                except (OSError, ValueError, KeyError, Isolated):
                    continue


class ReceiverHandle:
    def __init__(self, ticket, process=None):
        self.ticket, self.process = ticket, process
        self.barrier = None

    @classmethod
    def spawn(cls, directory, attempt, generation, revision, spool_identity,
              *, receiver=receive_file, min_free_bytes=64 * 1024 * 1024):
        parent, child = multiprocessing.get_context('spawn').Pipe(duplex=False)
        nonce = secrets.token_hex(32)
        process = multiprocessing.get_context('spawn').Process(
            target=_child, args=(str(directory), nonce, attempt, generation, revision,
                                spool_identity, child, receiver, min_free_bytes), name='file-receiver')
        process.start()
        child.close()
        try:
            if not parent.poll(10):
                raise Isolated('receiver_boot_timeout')
            boot = parent.recv()
            if process_identity(process.pid) != boot['identity']:
                raise Isolated('receiver_boot_identity_mismatch')
            ticket = dict(boot, directory=str(directory), attempt=attempt, generation=generation,
                          revision=revision, spool_identity=spool_identity, nonce=nonce)
            handle = cls(ticket, process)
            handle.barrier = ExitBarrier(ticket['identity'])
            return handle
        except BaseException:
            if process.is_alive():
                process.terminate()
            process.join(3)
            process.close()
            raise
        finally:
            parent.close()

    def permit(self, file, sources, expected_sha256, expected_size_bytes):
        t = self.ticket
        atomic_json(t['directory'], 'permit.json', {key: t[key] for key in
                    ('identity', 'attempt', 'generation', 'revision', 'nonce', 'spool_identity')})
        return self.command('start', request={'file': file, 'sources': sources,
                            'expected_sha256': expected_sha256, 'expected_size_bytes': expected_size_bytes})

    def command(self, action, **fields):
        t = self.ticket
        if process_identity(t['identity']['pid']) != t['identity']:
            raise Isolated('receiver_instance_mismatch')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(('127.0.0.1', t['port']))
            _send(sock, dict(fields, action=action, nonce=t['nonce'], attempt=t['attempt']))
            result = _recv(sock)
        if result.get('identity') != t['identity'] or result.get('attempt') != t['attempt']:
            raise Isolated('receiver_endpoint_mismatch')
        return result

    def exited(self):
        if self.process is not None and not self.process.is_alive():
            self.process.join(0)
            return True
        if self.barrier is None:
            # An orphan already gone before observation is deliberately unknown.
            self.barrier = ExitBarrier(self.ticket['identity'])
        return self.barrier.wait(0)

    def release(self, timeout=3):
        if self.exited():
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.command('release')
            if result['state'] == 'exiting':
                return self.barrier.wait(max(0, deadline - time.monotonic()))
            time.sleep(.01)
        return False

    def stop(self, timeout=3, force_owned=False):
        if self.exited():
            return True
        self.command('stop')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.command('status')
            if status.get('writer_closed'):
                return self.release(max(0, deadline - time.monotonic()))
            time.sleep(.02)
        if force_owned and self.process is not None and self.process.is_alive():
            self.process.terminate()  # Only our still-unreaped child, not an orphan PID.
            self.process.join(max(0.1, timeout))
            return not self.process.is_alive()
        return False

    def dispose(self):
        if self.barrier is not None:
            self.barrier.close()
        if self.process is not None and not self.process.is_alive():
            self.process.join(0)
            self.process.close()
            self.process = None
