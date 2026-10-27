"""Azure CLI-backed, paginated management-plane GET requests."""

import json
import re
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def cli_json(arguments, timeout=120):
    result = subprocess.run(
        ["az", *arguments, "--only-show-errors", "--output", "json"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if result.returncode:
        # Do not persist CLI stderr: it may contain authentication details.
        code = (re.search(r'"code"\s*:\s*"([A-Za-z][A-Za-z0-9_.-]*)"', result.stderr)
                or re.search(r"\b(?:ERROR: )?\(([A-Za-z][A-Za-z0-9_.-]+)\)", result.stderr))
        raise RuntimeError(
            f"Azure CLI failed ({code.group(1) if code else 'exit ' + str(result.returncode)}). "
            "Check authentication, Reader permissions, provider availability and network access."
        )
    return json.loads(result.stdout)


def safe_url(value):
    """Keep routing evidence, but omit userinfo, fragments and secret query values."""
    if not value:
        return ""
    if value.startswith("{{"):
        # Named-value placeholders are evidence, not secrets resolved by this scanner.
        return value.split("?", 1)[0].split("#", 1)[0]
    try:
        parts = urlsplit(value)
        if not parts.hostname:
            return ""
        host = parts.hostname
        if ":" in host:
            host = "[" + host + "]"
        if parts.port:
            host += ":" + str(parts.port)
        query = [(key, val) for key, val in parse_qsl(parts.query)
                 if key.lower() in ("deployment", "deployment-name", "api-version")]
        return urlunsplit((parts.scheme, host, parts.path, urlencode(query), ""))
    except ValueError:
        return ""


class AzureClient:
    def __init__(self, endpoint):
        self.endpoint = endpoint.rstrip("/")
        self.errors = []
        self.requests = []

    def error(self, scope, operation, message):
        row = {"scope": scope, "operation": operation, "message": message}
        self.errors.append(row)
        print(f"WARNING: {operation}: {scope}: {message}", file=sys.stderr, flush=True)

    def get(self, path, api_version=None):
        url = path if path.startswith("https://") else self.endpoint + path
        parsed = urlsplit(url)
        expected = urlsplit(self.endpoint)
        if parsed.scheme != "https" or parsed.netloc.lower() != expected.netloc.lower():
            self.error(path, "GET", "Rejected URL outside the configured ARM endpoint")
            return None
        if api_version and "api-version" not in dict(parse_qsl(parsed.query)):
            url += ("&" if parsed.query else "?") + urlencode({"api-version": api_version})
        for attempt in range(3):
            try:
                value = cli_json(["rest", "--method", "get", "--url", url])
                if not isinstance(value, dict):
                    raise ValueError("ARM response was not a JSON object")
                self.requests.append({"scope": path, "status": "ok"})
                return value
            except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
                transient = isinstance(exc, subprocess.TimeoutExpired) or any(
                    code in str(exc) for code in ("TooManyRequests", "InternalServerError",
                                                 "ServiceUnavailable", "GatewayTimeout")
                )
                if transient and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                message = "Request timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
                self.error(path, "GET", message)
                self.requests.append({"scope": path, "status": "failed"})
                return None

    def list(self, path, api_version):
        rows, visited = [], set()
        while path:
            if path in visited:
                self.error(path, "LIST", "Repeated pagination link; inventory is incomplete")
                break
            visited.add(path)
            data = self.get(path, api_version)
            if data is None:
                break
            if not isinstance(data.get("value"), list):
                self.error(path, "LIST", "Missing value array; inventory is incomplete")
                break
            rows.extend(data["value"])
            path = data.get("nextLink")
        return rows
