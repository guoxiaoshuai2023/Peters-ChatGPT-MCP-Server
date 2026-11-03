"""Install or stop this project's two macOS user services without root access."""

import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent.parent
LABELS = ("com.peters.chatgpt-mcp.origin", "com.peters.chatgpt-mcp.tunnel")


def unload_service(user_domain, label):
    target = f"{user_domain}/{label}"
    subprocess.run(["launchctl", "bootout", target],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # bootout can return while launchd is still reaping the old process. A new
    # bootstrap during that window fails with an unhelpful I/O error.
    deadline = time.monotonic() + 30
    while subprocess.run(["launchctl", "print", target],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Service is still stopping: {label}. Retry after shutdown completes.")
        time.sleep(0.2)


def service_definitions(project_config):
    commands = [
        [str(BASE / ".venv/bin/python"), "-m", "peters_mcp.cloudflare",
         "--access-config", str(BASE / "deployment/access.local.json"),
         "--config", str(project_config), "--port", "8766"],
        [str(BASE / "tools/cloudflared"), "tunnel", "--no-autoupdate", "--loglevel", "warn",
         "run", "--token-file", str(BASE / "deployment/cloudflare.token")],
    ]
    return [{"Label": label, "ProgramArguments": command, "WorkingDirectory": str(BASE),
             "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
             "Umask": 0o077, "ProcessType": "Background",
             "StandardOutPath": str(BASE / "work" / (label + ".out.log")),
             "StandardErrorPath": str(BASE / "work" / (label + ".err.log"))}
            for label, command in zip(LABELS, commands)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "stop", "uninstall", "status"))
    parser.add_argument("--projects", choices=("test", "real"), default="test")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This service helper requires macOS.")
    user_domain = f"gui/{os.getuid()}"
    agent_dir = Path.home() / "Library" / "LaunchAgents"
    project_config = BASE / ("deployment/projects-test.json" if args.projects == "test" else "projects.json")
    definitions = service_definitions(project_config)
    paths = [agent_dir / (label + ".plist") for label in LABELS]

    if args.action == "status":
        for label in LABELS:
            result = subprocess.run(["launchctl", "print", f"{user_domain}/{label}"],
                                    capture_output=True, text=True)
            lines = [line.strip() for line in result.stdout.splitlines()
                     if line.strip().startswith(("state =", "pid =", "last exit code ="))]
            print(label, "; ".join(lines) if result.returncode == 0 else "not loaded")
        return

    # Refuse to replace or stop an unrelated user's service with the same label.
    for definition, path in zip(definitions, paths):
        if path.is_symlink():
            parser.error("Refusing to replace a linked service file.")
        if path.exists():
            saved = plistlib.loads(path.read_bytes())
            if saved.get("Label") != definition["Label"] or saved.get("WorkingDirectory") != str(BASE):
                parser.error("An unrelated service already uses this label.")

    if args.action in ("stop", "uninstall"):
        for label in LABELS:
            unload_service(user_domain, label)
        if args.action == "uninstall":
            for path in paths:
                path.unlink(missing_ok=True)
            print("Stopped both services and removed their login startup entries. Project files retained.")
        else:
            print("Stopped both services for this login. LaunchAgent files are retained.")
        return

    check = subprocess.run(definitions[0]["ProgramArguments"] + ["--check"], cwd=BASE)
    if check.returncode:
        parser.error("Origin configuration did not validate.")
    if not (BASE / "tools/cloudflared").is_file() or not (BASE / "deployment/cloudflare.token").is_file():
        parser.error("Install cloudflared and save the approved tunnel credential first.")
    agent_dir.mkdir(parents=True, exist_ok=True)
    (BASE / "work").mkdir(exist_ok=True)
    for definition, path in zip(definitions, paths):
        unload_service(user_domain, definition["Label"])
        path.write_bytes(plistlib.dumps(definition))
        path.chmod(0o600)
        subprocess.run(["launchctl", "bootstrap", user_domain, str(path)], check=True)
    print(f"Installed login services with {args.projects} project access. No root privileges used.")


if __name__ == "__main__":
    main()
