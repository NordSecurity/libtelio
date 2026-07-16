#!/usr/bin/env python3

import json
import re
import subprocess
import urllib.error
import urllib.request

REQUEST_TIMEOUT = 30


def _redact(text: str) -> str:
    # Hide credentials in URLs (https://user:token@...) so tokens don't reach logs
    return re.sub(r"(https://)[^@/\s]+@", r"\1***@", text)


def run(*cmd, cwd=None, check=True):
    print("$ " + _redact(" ".join(cmd)))
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.stdout:
        print(_redact(res.stdout))
    if check and res.returncode != 0:
        raise RuntimeError(
            _redact(f"Command failed ({res.returncode}): {' '.join(cmd)}\n{res.stderr}")
        )
    return res.stdout.strip()


def repo_url(repo: str, token: str) -> str:
    if not token:
        return f"https://github.com/{repo}.git"
    return f"https://{token}@github.com/{repo}.git"


def git_clone(repo: str, branch: str, dest: str, token: str) -> None:
    run("git", "clone", "--depth", "1", "-b", branch, repo_url(repo, token), dest)
    run("git", "config", "user.email", "ci@nordsec.com", cwd=dest)
    run("git", "config", "user.name", "ci", cwd=dest)


def has_changes(cwd: str) -> bool:
    return bool(run("git", "status", "--porcelain", cwd=cwd))


def github_api_request(method, repo, path, token, payload=None):
    """Call the GitHub REST API and return (status_code, json). Returns (0, {...}) on failure."""
    url = f"https://api.github.com/repos/{repo}/{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode() or "{}")
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, {"error": str(err)}
