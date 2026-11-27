"""Read-only DNS/TLS/OAuth readiness check; never prints credentials or body data."""

import argparse
import json
import re
import ssl
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True, help="Your MCP DNS hostname, without scheme, port or path.")
    args = parser.parse_args()
    host = args.hostname
    if len(host) > 253 or not re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", host):
        parser.error("Use a DNS hostname such as mcp.example.com.")
    result = {"url": f"https://{host}/mcp", "ready_for_oauth": False}
    try:
        with urllib.request.urlopen(f"https://dns.google/resolve?name={host}&type=A", timeout=10) as response:
            dns = json.load(response)
        result["dns_status"] = dns.get("Status")
        result["dns_has_answers"] = bool(dns.get("Answer"))
    except (OSError, ValueError):
        result["dns_check"] = "unavailable"
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(result["url"], headers={
        "Accept": "application/json", "User-Agent": "Peters-ChatGPT-MCP-Readiness/0.1",
    })
    response = None
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    except urllib.error.URLError:
        result["tls_or_connection"] = "not_ready"
    if response is not None:
        with response:
            challenge = response.headers.get("WWW-Authenticate", "")
            result["https_status"] = response.status
            result["has_oauth_challenge"] = "resource_metadata=" in challenge
            result["ready_for_oauth"] = response.status == 401 and result["has_oauth_challenge"]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
