"""Audit exact CMake dependency commits and published repository advisories."""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def fetch_json(url, payload=None):
    request = urllib.request.Request(url,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def affected(version, expression):
    actual = tuple(map(int, version.split(".")))
    for term in expression.split(","):
        match = re.fullmatch(r"\s*(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)\s*", term)
        if not match:
            raise ValueError("Unsupported advisory range; manual review required: " + expression)
        operator = match[1] or "="
        reference = tuple(map(int, match[2].split(".")))
        if not {">=": actual >= reference, "<=": actual <= reference,
                ">": actual > reference, "<": actual < reference, "=": actual == reference}[operator]:
            return False
    return True


def audit(build_directory):
    pins = re.findall(r"GIT_TAG\s+([a-f0-9]{40})\s+# v(\d+\.\d+\.\d+)",
                      (ROOT / "CMakeLists.txt").read_text())
    if len(pins) != 2:
        raise ValueError("Expected exactly two immutable, versioned CMake dependency pins")
    exceptions = json.loads((ROOT / "security/advisory-exceptions.json").read_text())
    findings = []
    for (dependency, repository), (pin, version) in zip(
            (("crow", "CrowCpp/Crow"), ("googletest", "google/googletest")), pins):
        path = str(Path(build_directory) / "_deps" / (dependency + "-src"))
        def revision(value):
            return subprocess.check_output(["git", "-C", path, "rev-parse", value], text=True).strip()
        commit = revision("HEAD")
        if commit != revision(pin + "^{commit}"):
            raise ValueError("Fetched dependency does not match its CMake pin")
        vulnerabilities = fetch_json("https://api.osv.dev/v1/query", {"commit": commit}).get("vulns", [])
        for vulnerability in vulnerabilities:
            if not vulnerability.get("withdrawn"):
                findings.append((dependency, commit, vulnerability["id"]))
        advisories = fetch_json("https://api.github.com/repos/" + repository + "/security-advisories?per_page=100")
        if len(advisories) >= 100:
            raise ValueError("Advisory pagination requires review")
        for advisory in advisories:
            if advisory.get("withdrawn_at"):
                continue
            if not any(affected(version, item["vulnerable_version_range"])
                       for item in advisory.get("vulnerabilities", [])):
                continue
            identifier = advisory["ghsa_id"]
            exception = exceptions.get(identifier)
            if exception and exception["version"] == version:
                if datetime.date.fromisoformat(exception["expires"]) < datetime.date.today():
                    raise ValueError("Advisory exception expired: " + identifier)
                # This exception only applies while Gatehouse defines no WebSocket routes.
                if exception["condition"] != "no-websocket-routes" or any(
                        re.search(r"\bwebsocket\b", path.read_text(), re.I)
                        for directory in ("src", "include")
                        for path in (ROOT / directory).rglob("*")
                        if path.suffix in (".h", ".hpp", ".cc", ".cpp")):
                    raise ValueError("Advisory exception no longer applies: " + identifier)
                print("Reviewed exception:", identifier, exception["reason"])
            else:
                findings.append((dependency, commit, identifier))
    for dependency, commit, advisory in findings:
        print(f"{dependency} {commit}: {advisory}")
    return bool(findings)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_directory")
    options = parser.parse_args()
    raise SystemExit(audit(options.build_directory))
