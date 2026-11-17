import argparse
from logging.handlers import RotatingFileHandler
import logging
from pathlib import Path
import sys

from .catalog import Catalog
from .history import HistoryAccess


def main():
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Read-only local project MCP server.")
    parser.add_argument("--config", type=Path, default=base / "projects.json")
    parser.add_argument("--history-config", type=Path,
                        help="History policy file; absent default history-access.json disables history.")
    parser.add_argument("--file-config", type=Path,
                        help="Explicit original-file policy; remote writes require verified request identity.")
    parser.add_argument("--file-export-config", type=Path,
                        help="Independent default-off original export policy; authenticated HTTP delivery only.")
    parser.add_argument("--chunked-export-config", type=Path,
                        help="Validate a raw-parts-v1 policy; serving it requires the authenticated Cloudflare entrypoint.")
    parser.add_argument("--file-inspection-only", action="store_true",
                        help="Load private protection and inspect saved jobs without starting file writers.")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--check", action="store_true", help="Validate configuration without serving files.")
    parser.add_argument("--audit-log", type=Path, default=base / "work" / "audit.jsonl")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    files = exports = None
    try:
        catalog = Catalog.from_config(args.config)
        default_history = base / "history-access.json"
        history_path = args.history_config
        if history_path is None and (default_history.exists() or default_history.is_symlink()):
            history_path = default_history
        history = HistoryAccess(history_path, catalog.projects, catalog=catalog)
        history._configuration()
        if args.chunked_export_config is not None:
            from .chunked_export_config import read_chunked_export_config
            chunked_config = read_chunked_export_config(args.chunked_export_config)
            if chunked_config.enabled and not args.check:
                raise ValueError('chunked_authenticated_http_required')
        from .file_config import load_file_service
        _, files = load_file_service(args.file_config, catalog, history,
                                     inspection_only=args.file_inspection_only or args.check)
        from .file_export import load_export_service
        exports = load_export_service(args.file_export_config, catalog, history, files=files,
            protected_paths=(args.config, args.audit_log), inspection_only=args.file_inspection_only or args.check,
            chunked_config_path=args.chunked_export_config if args.check else None)
    except (ValueError, OSError):
        if exports is not None:
            exports.close()
        if files is not None:
            files.close()
        parser.error("Invalid or inaccessible configuration. Create projects.json from projects.example.json, "
                     "set local roots, and check any history policy. See README.md.")
    if args.check:
        if exports is not None:
            exports.close()
        if files is not None:
            files.close()
        print(f"Configuration valid: {', '.join(catalog.projects)}. "
              f"History policy: {'configured' if history_path else 'disabled'}. No server started.")
        return

    from mcp.server.transport_security import TransportSecuritySettings
    from .server import create_server

    args.audit_log.parent.mkdir(parents=True, exist_ok=True)
    audit = logging.getLogger("peters.audit")
    audit.propagate = False
    audit.setLevel(logging.INFO)
    handler = RotatingFileHandler(args.audit_log, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit.addHandler(handler)
    server = create_server(catalog, audit, history, files=files,
                           file_inspection_only=args.file_inspection_only or
                           bool(getattr(files, 'inspection_only', False)), exports=exports)
    try:
        if args.transport == "stdio":
            server.run(transport="stdio")
        else:
            print(f"Local-only MCP: http://127.0.0.1:{args.port}/mcp (no remote authentication)", file=sys.stderr)
            options = dict(
                host="127.0.0.1", port=args.port,
                stateless_http=True, json_response=True, max_request_body_size=262144,
                transport_security=TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=["127.0.0.1:*", "localhost:*"],
                    allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
                ),
            )
            if exports is None:
                server.run(transport="streamable-http", **options)
            else:
                import uvicorn
                http_options = {key: value for key, value in options.items() if key != 'port'}
                app = server.streamable_http_app(**http_options)
                uvicorn.run(exports.protocol.wrap(app), host="127.0.0.1", port=args.port,
                            proxy_headers=False, access_log=False)
    finally:
        export_stop = exports.close() if exports is not None else None
        if files is not None:
            files.close()
        handler.close()
        audit.removeHandler(handler)
        if export_stop is not None and export_stop['state'] != 'stopped':
            raise SystemExit('Original export shutdown_pending; wait for actual process exit before restart.')


if __name__ == "__main__":
    main()
