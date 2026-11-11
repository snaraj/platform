#!/usr/bin/env python3
"""Re-derive one Dependabot action-pin PR as a signed branch with its fragment.

Usage:
    python3 -I -B scripts/adopt_dependabot.py <PR> --lane <lane[-effort]> \
        --signature '- <Agent>'

Dependabot commits carry a bot identity and no release fragment, so they fail
the publication-history and one-fragment release gates by construction
(delivery-lane requirements 3 and 8). This tool turns such a PR into a change
those gates accept without trusting anything the PR carries:

- the diff is read with ``gh pr diff`` as TEXT; nothing from the PR is checked
  out, applied, fetched, imported or executed;
- only workflow files under ``.github/workflows/`` may change, and only by
  replacing one action-pin ``uses:`` line with the same action at another
  commit; every other path, header or line is refused;
- each new commit is peeled from the upstream tag its version comment names
  and must equal the pinned SHA exactly;
- the substitutions are re-applied by exact line text to the current
  protected ``main``, so a moved base is re-derived rather than patched;
- one commit is written with Git plumbing under the owner's noreply identity
  and an SSH signature, carrying the one ``changelog.d`` fragment, and is
  pointed to by a NEW branch. No working tree, index or checkout is touched.

It prints the branch name and nothing else on success. Pushing (through the
pre-push gate) and opening the Draft PR stay with the caller.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    """The fragment grammar and branch grammar come from their one owner each."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through it
    spec.loader.exec_module(module)
    return module


RELEASE = _load("adopt_release_contract", ROOT / "scripts/ci/platform_release_contract.py")
FLOW = _load("adopt_pr_flow", ROOT / "scripts/validate_pr_flow.py")

REPOSITORY = "snaraj/platform"
# Dependabot's immutable bot account; a login alone could be any user's name.
DEPENDABOT = ("dependabot[bot]", 49699333, "Bot")
SHA = re.compile(r"[0-9a-f]{40}")
# The one manifest family Dependabot updates here (.github/dependabot.yml).
WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.ya?ml")
PIN_LINE = re.compile(
    r"(?P<lead> +(?:- )?)uses: (?P<action>[A-Za-z0-9-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
    r"@(?P<sha>[0-9a-f]{40}) # (?P<version>v[0-9]+(?:\.[0-9]+){0,2})"
)
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?")
# Characters a Dependabot title may carry into a commit subject and fragment:
# no backtick, dollar sign, brace, quote, angle bracket or control character.
TITLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._/()#:+-]{0,119}")
SIGNATURE = re.compile(r"- [A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")


class Refused(ValueError):
    """Every reason is a literal in this file, so printing it leaks no input."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


@dataclasses.dataclass(frozen=True)
class PinChange:
    path: str
    old_line: str
    new_line: str
    action: str
    old_version: str
    new_version: str
    new_sha: str


def _pin(line):
    match = PIN_LINE.fullmatch(line)
    require(match is not None, "a changed line is not an action pin")
    require(all(part not in {".", ".."} for part in match["action"].split("/")), "an action path is not canonical")
    return match


def _pair(path, old_line, new_line):
    old, new = _pin(old_line), _pin(new_line)
    require(old["lead"] == new["lead"] and old["action"] == new["action"],
            "a pin change moves the line or swaps the action")
    require(old["sha"] != new["sha"], "a pin change keeps the same commit")
    return PinChange(path, old_line, new_line, new["action"], old["version"], new["version"], new["sha"])


def _file_path(header):
    match = re.fullmatch(r"diff --git a/(\S+) b/(\S+)", header)
    require(match is not None and match[1] == match[2], "a file header renames or is malformed")
    path = match[1]
    require(WORKFLOW_PATH.fullmatch(path) is not None and ".." not in path.split("/"),
            "a changed path is outside the workflow pins")
    return path


def parse_diff(text):
    """Return every pin change in a unified diff, or refuse the whole diff."""
    require(isinstance(text, str) and text.endswith("\n") and "\r" not in text, "the diff is not LF text")
    lines = text[:-1].split("\n")
    require(lines and lines[0].startswith("diff --git "), "the diff does not start with a file header")
    changes, index = [], 0
    while index < len(lines):
        path = _file_path(lines[index])
        index += 1
        require(index < len(lines) and re.fullmatch(r"index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}(?: 100644)?", lines[index]),
                "a file header carries a mode, rename, creation, deletion or binary change")
        require(lines[index + 1:index + 3] == [f"--- a/{path}", f"+++ b/{path}"], "a file header names other paths")
        index += 3
        require(index < len(lines) and lines[index].startswith("@@ "), "a file has no hunk")
        while index < len(lines) and lines[index].startswith("@@ "):
            hunk = HUNK.fullmatch(lines[index])
            require(hunk is not None, "a hunk header is malformed")
            old_left = 1 if hunk[2] is None else int(hunk[2])
            new_left = 1 if hunk[4] is None else int(hunk[4])
            index += 1
            removed, added = [], []
            while old_left or new_left:
                require(index < len(lines), "a hunk is shorter than its header")
                line = lines[index]
                index += 1
                if line.startswith("-") and not added:
                    removed.append(line[1:])
                    old_left -= 1
                elif line.startswith("+"):
                    added.append(line[1:])
                    new_left -= 1
                elif line.startswith(" ") and len(removed) == len(added):
                    changes += [_pair(path, a, b) for a, b in zip(removed, added)]
                    removed, added = [], []
                    old_left -= 1
                    new_left -= 1
                else:
                    raise Refused("a hunk adds or removes a line without replacing one pin")
                require(old_left >= 0 and new_left >= 0, "a hunk is longer than its header")
            require(len(removed) == len(added), "a hunk adds or removes a line without replacing one pin")
            changes += [_pair(path, a, b) for a, b in zip(removed, added)]
        require(index == len(lines) or lines[index].startswith("diff --git "), "unexpected text follows a hunk")
    require(changes, "the diff changes no action pin")
    return changes


def apply_changes(path, text, changes):
    """Replace each pinned line in the protected file by its exact text."""
    lines = text.split("\n")
    for change in {(c.old_line, c.new_line) for c in changes if c.path == path}:
        expected = sum(c.path == path and (c.old_line, c.new_line) == change for c in changes)
        require(lines.count(change[0]) == expected, "the protected file no longer carries the pinned lines")
        lines = [change[1] if line == change[0] else line for line in lines]
    return "\n".join(lines)


def slug(title):
    """The fragment slug: the title's words without the conventional prefix."""
    require(TITLE.fullmatch(title) is not None, "the pull request title has unsupported characters")
    words = re.findall(r"[a-z0-9]+", re.sub(r"^[a-z]+\(deps\): ", "", title.lower()))
    out = ""
    for word in words:
        if len(out) + len(word) + 1 > 60:
            break
        out = f"{out}-{word}" if out else word
    require(out, "the pull request title yields no fragment slug")
    return out


def fragment(number, title, changes):
    moved = sorted({(c.action, c.old_version, c.new_version) for c in changes})
    lines = ["### Changed", "",
             f"- Adopt Dependabot PR #{number} ({title}) as a signed change carrying its release fragment."]
    lines += [f"- Advance `{action}` from {old} to {new} at the commit peeled from the upstream tag."
              for action, old, new in moved]
    path = f"changelog.d/{number}-{slug(title)}.md"
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    try:
        RELEASE.validate_fragment_bytes(path, payload)
    except RELEASE.ContractError as error:
        raise Refused("the derived fragment does not satisfy the release contract") from error
    return path, payload


def message(number, title, changes, fragment_path, signature):
    body = [f"Adopt Dependabot #{number}: {title}", "",
            "Dependabot's commit carries a bot identity and no release fragment, so",
            "it fails the publication-history and one-fragment release gates by",
            "construction. This commit re-derives its action-pin changes onto current",
            "protected main from the PR diff, read as data and limited to workflow",
            "`uses:` pins, each peeled from its upstream tag:", ""]
    body += [f"- {c.path}: {c.action} {c.old_version} -> {c.new_version} ({c.new_sha})"
             for c in sorted(set(changes), key=lambda c: (c.path, c.action))]
    body += [f"- {fragment_path}: the one release fragment.", "",
             f"Supersedes Dependabot PR #{number}.", "", signature]
    return "\n".join(body) + "\n"


def environment():
    """Ambient GIT_* variables could redirect the repository, index or identity."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def run(argv, *, env=None, stdin=None, root=ROOT):
    done = subprocess.run(argv, cwd=root, input=stdin, capture_output=True, timeout=120,
                          env=environment() if env is None else env)
    if done.returncode != 0:
        raise Refused(f"`{argv[0]} {argv[1]}` failed")
    return done.stdout.decode("utf-8")


def gh_json(*arguments):
    value = json.loads(run(["gh", *arguments]))
    require(isinstance(value, (dict, list)), "GitHub answered with an unexpected shape")
    return value


def gh_object(*arguments):
    value = gh_json(*arguments)
    require(isinstance(value, dict), "GitHub answered with an unexpected shape")
    return value


def pull_request(number):
    pull = gh_object("api", f"repos/{REPOSITORY}/pulls/{number}")
    user = pull.get("user") or {}
    require((user.get("login"), user.get("id"), user.get("type")) == DEPENDABOT,
            "the pull request is not Dependabot's")
    require(pull.get("state") == "open" and (pull.get("base") or {}).get("ref") == "main",
            "the pull request is not open against main")
    head = (pull.get("head") or {}).get("sha", "")
    require(SHA.fullmatch(head) is not None, "the pull request head is not one exact commit")
    return pull["title"], head


def peel(action, version):
    """The upstream tag's commit, through one annotated tag object at most."""
    owner_repo = "/".join(action.split("/")[:2])
    target = gh_object("api", f"repos/{owner_repo}/git/ref/tags/{version}").get("object") or {}
    if isinstance(target, dict) and target.get("type") == "tag" and SHA.fullmatch(str(target.get("sha"))):
        target = gh_object("api", f"repos/{owner_repo}/git/tags/{target['sha']}").get("object") or {}
    require(isinstance(target, dict) and target.get("type") == "commit" and SHA.fullmatch(str(target.get("sha"))),
            "an upstream tag does not name one commit")
    return target["sha"]


def signing_key():
    """The one owner-registered signing key the agent holds (AGENTS.md)."""
    login = gh_object("api", "user")["login"]
    registered = {" ".join(item["key"].split()[:2]) for item in gh_json("api", f"users/{login}/ssh_signing_keys")}
    loaded = {" ".join(line.split()[:2]) for line in run(["ssh-add", "-L"]).splitlines() if line.strip()}
    matches = registered & loaded
    require(len(matches) == 1, "expected exactly one registered signing key in the agent")
    return matches.pop()


def protected_base(root):
    base = run(["git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], root=root).strip()
    advertised = run(["git", "ls-remote", "--exit-code", "origin", "refs/heads/main"], root=root).split()
    require(advertised[:1] == [base], "origin/main is not the advertised main; fetch origin first")
    return base


def write_branch(root, base, files, text, branch, key):
    """One commit on ``base`` with ``files`` replaced; no checkout is touched."""
    name = run(["git", "log", "-1", "--format=%an", base], root=root).strip()
    email = run(["git", "log", "-1", "--format=%ae", base], root=root).strip()
    with tempfile.TemporaryDirectory(prefix="adopt-dependabot-") as scratch:
        env = dict(environment(), GIT_INDEX_FILE=str(Path(scratch) / "index"),
                   GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                   GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
        run(["git", "read-tree", base], env=env, root=root)
        for path, payload in sorted(files.items()):
            listed = run(["git", "ls-tree", base, "--", path], root=root)
            require(listed == "" or listed.startswith("100644 blob "), "a changed file is not an ordinary file on main")
            blob = run(["git", "hash-object", "-w", "--stdin"], env=env, stdin=payload, root=root).strip()
            run(["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"], env=env, root=root)
        tree = run(["git", "write-tree"], env=env, root=root).strip()
        signing = ["-c", "gpg.format=ssh", "-c", f"user.signingkey=key::{key}"] if key else []
        commit = run(["git", *signing, "commit-tree", tree, "-p", base, *(["-S"] if key else []), "-F", "-"],
                     env=env, stdin=text.encode("utf-8"), root=root).strip()
    require(run(["git", "show", "-s", "--format=%P%n%an%n%ae%n%cn%n%ce", commit], root=root).split("\n")[:5]
            == [base, name, email, name, email], "the written commit has another parent or identity")
    require(not key or "\ngpgsig " in run(["git", "cat-file", "commit", commit], root=root),
            "the written commit is not signed")
    run(["git", "branch", "--no-track", branch, commit], root=root)
    return commit


def adopt(number, lane, signature, root=ROOT, key=None):
    require(SIGNATURE.fullmatch(signature) is not None, "the signature must be one '- <Agent>' line")
    title, head = pull_request(number)
    changes = parse_diff(run(["gh", "pr", "diff", str(number), "--repo", REPOSITORY, "--color", "never"]))
    require(pull_request(number) == (title, head), "the pull request moved while it was read")
    for change in changes:
        require(peel(change.action, change.new_version) == change.new_sha,
                "a new pin is not the commit its upstream tag names")
    base = protected_base(root)
    files = {}
    for path in sorted({c.path for c in changes}):
        files[path] = apply_changes(path, run(["git", "show", f"{base}:{path}"], root=root), changes).encode("utf-8")
    fragment_path, payload = fragment(number, title, changes)
    require(subprocess.run(["git", "cat-file", "-e", f"{base}:{fragment_path}"], cwd=root, env=environment(),
                           capture_output=True).returncode != 0, "the fragment already exists on main")
    files[fragment_path] = payload
    branch = f"{lane}/{number}-dependabot-{slug(title)}"[:120]
    require(FLOW.branch_denial(branch) is None and FLOW.parse_lane(branch) is not None,
            "the branch name is outside the lane grammar")
    write_branch(root, base, files, message(number, title, changes, fragment_path, signature), branch,
                 key or signing_key())
    return branch


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("pull_request", type=int)
    parser.add_argument("--lane", required=True, help="agent label, optionally -<effort>, e.g. opus5.5-high")
    parser.add_argument("--signature", required=True, help="the lane's signature line, e.g. '- Opus5.5'")
    args = parser.parse_args(argv)
    try:
        require(args.pull_request > 0, "the pull request number must be positive")
        print(adopt(args.pull_request, args.lane, args.signature))
        return 0
    except Refused as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        print(f"DENY: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
