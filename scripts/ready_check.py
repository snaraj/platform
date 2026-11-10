#!/usr/bin/env python3
"""AGENTS.md's Ready rule, evaluated read-only: ELIGIBLE or every blocker.

The rule's one expression in code (issue #295), extracted from the promoter's
deleted auto-Ready machinery so no second copy can drift. It NEVER writes, so
running it is never an action: the coordinator reads it and flips. Exit 0
eligible, 3 blocked, 1 refused.

What it proves is exactly: the pull request is open, targets its repository's
default branch, is not behind that branch, carries an App-posted exact-head
APPROVE with no REQUEST-CHANGES at the same head, has every required check
green, and still carries the metadata AGENTS.md requires. One receipt may
cover a later head (issue #456): a re-cut on a moved base keeps the App's
APPROVE only when the change is byte-identical, which ``carry_verdict`` and
``patch_identity`` decide from App-posted, GitHub-recorded and local Git data,
never from text the pull request's author wrote. What it does NOT
decide is whether the lanes that approved are the right lanes for this change's
risk tier: AGENTS.md pins no model roster and binds independence to the posting
actor rather than the signature wording, so this prints the approving lanes and
the tier labels side by side and leaves that judgment to the coordinator.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = "snaraj/website-infrastructure"
# A receipt binds to the review App's immutable identity, never to a login or
# a signature line alone: the bot user's id and type, and the App id it was
# performed through. A check from another writer is never the required check.
REVIEWS_APP = "snaraj-agent-reviews[bot]"
REVIEWS_APP_USER_ID = 318424677
REVIEWS_APP_ID = 4641855
REQUIRED_CHECKS = ("dependency-review", "repository-and-infrastructure")
REQUIRED_CHECK_APP = "github-actions"
REQUIRED_SECURITY_CHECKS = {
    "analyze (python, none)": "github-actions",
    "CodeQL": "github-advanced-security",
}
ACCEPTABLE_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
# AGENTS.md: every agent-created pull request carries the umbrella label, and
# one taxonomy label is what tells a reader which review tier the change earns.
# A pull request wearing neither cannot have its tier judged, so it fails closed.
UMBRELLA_LABEL = "agent-authored"
TIER_LABELS = frozenset({
    "production-readiness", "conventions", "security", "tests", "ci", "docs",
    "release", "fix", "provider-neutrality", "delivery-lane", "features",
    "platform", "extraction",
})
REVIEW_ATTENTION_LABEL = "requires-review"
# A receipt may bind the pull request BODY it audited as well as the head: the
# promoter's APPROVE states the SHA-256 of the body its claim audit compared
# (issue #309). The body is same-head-mutable metadata, so this rule recomputes
# the digest from the live body and withholds Ready when it differs — a body
# edited after the receipt is a different subject, whatever the head says.
BODY_BINDING = "BODY-SHA256: "
# The security-surface tier and the label that arms its reviewer travel
# together; exactly one of them is a metadata contradiction, not a tier.
SECURITY_TIER_LABEL = "security"
SECURITY_REVIEW_LABEL = "cybersecurity-review-requested"
REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
# Whole-file context: git patch-id ignores hunk line numbers, so with the
# default three lines the same hunk replayed at another spot with the same
# context would match. With every file's full pre-image in the hunk it cannot.
WHOLE_FILE_CONTEXT = "--unified=100000000"
FORCE_PUSHES = (
    "query($owner: String!, $name: String!, $number: Int!) { repository(owner: $owner, name: $name) {"
    " pullRequest(number: $number) { headRefOid timelineItems(itemTypes: [HEAD_REF_FORCE_PUSHED_EVENT], first: 100) {"
    " totalCount nodes { ... on HeadRefForcePushedEvent { beforeCommit { oid } afterCommit { oid } } } } } } }"
)


class Refusal(Exception):
    """A fail-closed judgment. The message names the check that failed."""


# The canonical shape: a receipt counted here is one the validator accepts.
_SPEC = importlib.util.spec_from_file_location("ready_check_review_receipt", Path(__file__).resolve().parent / "validate_review_receipt.py")
RECEIPTS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RECEIPTS)
_EPOCH_SPEC = importlib.util.spec_from_file_location("ready_check_release_epoch", Path(__file__).resolve().parent / "ci/platform_release_epoch.py")
EPOCH = importlib.util.module_from_spec(_EPOCH_SPEC)
_EPOCH_SPEC.loader.exec_module(EPOCH)


def gh(path, listing=False):
    """One bounded READ through the owner's own gh credential."""
    argv = ["gh", "api", "-H", "Accept: application/vnd.github+json", path]
    if listing:
        argv[2:2] = ["--paginate", "--slurp"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"`gh api {path}` could not be run: {type(error).__name__}") from None
    if done.returncode != 0:
        raise Refusal(f"`gh api {path}` exited {done.returncode}")
    decoded = json.loads(done.stdout) if done.stdout.strip() else {}
    return [item for page in decoded for item in page] if listing else decoded


def gh_graphql(query, **variables):
    """One bounded GraphQL READ; force-push history exists only there."""
    argv = ["gh", "api", "graphql", "-f", f"query={query}"]
    for key, value in variables.items():
        argv += ["-F" if isinstance(value, int) else "-f", f"{key}={value}"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"`gh api graphql` could not be run: {type(error).__name__}") from None
    if done.returncode != 0:
        raise Refusal(f"`gh api graphql` exited {done.returncode}")
    return json.loads(done.stdout)


def git(*argv, stdin=None, root=REPO_ROOT):
    """Local Git with no ambient GIT_* redirection of repository or index."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        done = subprocess.run(["git", "-C", str(root), *argv], input=stdin, capture_output=True,
                              timeout=120, env=environment)
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"`git {argv[0]}` could not be run: {type(error).__name__}") from None
    if done.returncode != 0:
        raise Refusal(f"`git {argv[0]}` exited {done.returncode}")
    return done.stdout


def app_receipt(comment):
    """``(head, verdict, lane, binds_body)`` for a shape-valid receipt the review
    App itself posted, else None. Only the App's immutable identity counts:
    ``Opus 5`` and ``opus-5`` are the one lane opus5."""

    user = comment.get("user") or {}
    if ((user.get("login"), user.get("id"), user.get("type"), (comment.get("performed_via_github_app") or {}).get("id"))
            != (REVIEWS_APP, REVIEWS_APP_USER_ID, "Bot", REVIEWS_APP_ID)):
        return None
    body = comment.get("body") or ""
    lines = body.replace("\r\n", "\n").splitlines()
    heads = [line[6:] for line in lines if line.startswith("HEAD: ")]
    if len(heads) != 1 or RECEIPTS.denial(body, heads[0], "pull-request") is not None:
        return None
    lane = RECEIPTS.SIGNATURE.fullmatch([line for line in lines if line.strip()][-1]).group(1)
    verdict = [line[9:] for line in lines if line.startswith("VERDICT: ")][0]
    return heads[0], verdict, re.sub(r"[^a-z0-9]", "", lane.lower()), any(line.startswith(BODY_BINDING) for line in lines)


def patch_identity(base, head, root=REPO_ROOT):
    """Whitespace-exact, whole-file patch-id of ``base..head``, or None if empty.

    ``--verbatim`` is git's stable (file-order independent) patch-id that does
    not strip whitespace: plain ``--stable`` gives a re-indented Python or YAML
    line the same id. ``--binary`` hashes binary content instead of the
    "Binary files differ" stub, and mode lines are hashed too.
    """

    for sha in (base, head):
        if SHA.fullmatch(sha or "") is None:
            raise Refusal("a carried patch bound is not one exact commit")
        try:
            git("cat-file", "-e", f"{sha}^{{commit}}", root=root)
        except Refusal:
            raise Refusal(f"commit {sha} is not available locally; run `git fetch origin {sha}`") from None
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "--full-index",
               "--no-renames", "--diff-algorithm=myers", WHOLE_FILE_CONTEXT, base, head, root=root)
    if not diff:
        return None
    fields = git("patch-id", "--verbatim", stdin=diff, root=root).decode("ascii").split()
    if len(fields) != 2 or SHA.fullmatch(fields[0]) is None:
        raise Refusal("git patch-id returned no single identity")
    return fields[0]


def carry_verdict(head, last, recorded_heads, old_patch, new_patch):
    """Why the App's last receipt on a source pull request may NOT cover
    ``head``, or None when it may. Every input is App-posted (``last``),
    GitHub-recorded (``recorded_heads``) or computed from local Git objects
    (the patch identities); nothing the pull request's author wrote decides it.
    """

    if last is None:
        return "no App-posted receipt to carry"
    old, verdict, _lane, binds_body = last
    if old == head:
        return "the latest receipt already binds this head"
    if verdict != "APPROVE":
        return "the latest App receipt is not an APPROVE"
    if binds_body:
        return "the receipt binds a pull request body, which a re-cut changes"
    if old not in recorded_heads:
        return "the receipt's head is not in the source pull request's recorded head history"
    if not new_patch or old_patch != new_patch:
        return "the change at this head is not byte-identical to the approved change"
    return None


def body_digest(text):
    """SHA-256 of a pull request body after the newline normalisation the
    promoter's claim audit applies, so the receipt and this rule hash the same
    bytes: CRLF becomes LF and surrounding newlines are dropped."""

    return hashlib.sha256((text or "").replace("\r\n", "\n").strip("\n").encode("utf-8")).hexdigest()


def ready_decision(head, labels, comments, checks, behind_by, state=None, base_ref=None, default_branch=None, body=None,
                   carried=()):
    """Return ``(approving lanes, blockers)`` for one exact head.

    ``state``, ``base_ref`` and ``default_branch`` are read from the pull
    request itself; a missing or unreadable one is a blocker rather than an
    omission, because every one of them decides WHICH pull request this is.
    ``carried`` names lanes whose APPROVE ``carry_verdict`` accepted for a
    byte-identical earlier head; they count only when no receipt binds this
    head, and every other blocker below still applies to this head.
    """
    blockers, verdicts = [], []
    pull_body = body
    if state != "open":
        blockers.append(f"the pull request is not open (state: {state or 'unreadable'})")
    if not base_ref or not default_branch:
        blockers.append("the pull request's base branch is missing or unreadable")
    elif base_ref != default_branch:
        blockers.append(f"the pull request targets {base_ref}, not the default branch {default_branch}")
    if labels is None:
        blockers.append("the pull request's labels are missing or unreadable")
        labels = []
    receipts_here = 0
    for c in comments:
        receipt = app_receipt(c)
        if receipt is None or receipt[0] != head:
            continue
        receipts_here += 1
        lines = (c.get("body") or "").replace("\r\n", "\n").splitlines()
        bound = [line[len(BODY_BINDING):] for line in lines if line.startswith(BODY_BINDING)]
        if bound and bound != [body_digest(pull_body)]:
            # A receipt that binds a body this pull request no longer carries is
            # neither an APPROVE nor a REQUEST-CHANGES here: it is a blocker,
            # because the reviewed subject was edited under it.
            blockers.append("a receipt at this head binds a different pull request body; the body was edited after the receipt")
            continue
        verdicts.append(receipt[1:3])
    lanes = sorted({lane for verdict, lane in verdicts if verdict == "APPROVE" and lane})
    if not receipts_here:
        lanes = sorted(set(carried))
    tiers = sorted(TIER_LABELS.intersection(labels))
    if any(verdict == "REQUEST-CHANGES" for verdict, _ in verdicts):
        blockers.append("a REQUEST-CHANGES receipt binds this head")
    if not lanes:
        blockers.append("no adversarial APPROVE receipt binds this head")
    if REVIEW_ATTENTION_LABEL in labels:
        blockers.append(f"{REVIEW_ATTENTION_LABEL} is still armed")
    for name in REQUIRED_CHECKS:
        found = [check for check in checks if check.get("name") == name]
        if len(found) != 1:
            blockers.append(f"required check {name} appears {len(found)} times at this head; exactly one authoritative run is required")
        elif (found[0].get("app") or {}).get("slug") != REQUIRED_CHECK_APP:
            blockers.append(f"required check {name} was not produced by {REQUIRED_CHECK_APP}")
        elif found[0].get("status") != "completed" or found[0].get("conclusion") != "success":
            blockers.append(f"required check {name} has not succeeded at this head")
    for name, app in REQUIRED_SECURITY_CHECKS.items():
        found = [check for check in checks if check.get("name") == name]
        if len(found) != 1:
            blockers.append(f"required security check {name} appears {len(found)} times at this head; exactly one authoritative run is required")
        elif (found[0].get("app") or {}).get("slug") != app:
            blockers.append(f"required security check {name} was not produced by {app}")
        elif found[0].get("status") != "completed" or found[0].get("conclusion") != "success":
            blockers.append(f"required security check {name} has not succeeded at this head")
    # Every check at the head, required or not, must have FINISHED and ended in
    # a conclusion meaning "nothing went wrong". A queued or in-progress run has
    # no verdict yet, so it cannot be green: AGENTS.md permits the flip only
    # when every check is green at the exact head, and a run still executing can
    # still fail. Every other terminal conclusion, and any status or conclusion
    # value this code has never seen, fails closed the same way.
    for check in checks:
        if check.get("status") != "completed":
            blockers.append(f"a check at this head has not finished: {check.get('name')} is {check.get('status')}")
        elif check.get("conclusion") not in ACCEPTABLE_CONCLUSIONS:
            blockers.append(f"a check at this head did not succeed: {check.get('name')} ended {check.get('conclusion')}")
    if not tiers:
        blockers.append("the pull request carries no tier label, so its review depth cannot be judged")
    if UMBRELLA_LABEL not in labels:
        blockers.append(f"the pull request is missing the {UMBRELLA_LABEL} umbrella label")
    if (SECURITY_TIER_LABEL in labels) != (SECURITY_REVIEW_LABEL in labels):
        blockers.append(f"conflicting tier labels: exactly one of {SECURITY_TIER_LABEL} and {SECURITY_REVIEW_LABEL} is present")
    if behind_by is None:
        blockers.append("base freshness is unknown")
    elif behind_by:
        blockers.append(f"branch is {behind_by} commit(s) behind {base_ref or 'its base'}")
    return lanes, tiers, blockers


def verify_repository(repository, record):
    """The name change cannot redirect local delivery authority to a new object."""
    try:
        EPOCH.repository(record.get("full_name"), record.get("id"))
        if record["full_name"] != repository:
            raise ValueError("configured repository name is stale")
    except (KeyError, TypeError, ValueError) as error:
        raise Refusal("delivery repository name or object is foreign") from error


def snapshot(repository, number):
    """Every input the rule reads, bound to the pull request's exact head."""
    pull = gh(f"repos/{repository}/pulls/{number}")
    head = (pull.get("head") or {}).get("sha") or ""
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise Refusal(f"PR #{number}: GitHub answered without one exact head")
    base = pull.get("base") or {}
    base_ref = base.get("ref")
    default_branch = ((base.get("repo") or {}).get("default_branch"))
    # Freshness is measured against the branch this pull request actually
    # targets. Comparing a fixed name would answer about a different branch.
    behind_by, merge_base = None, None
    if base_ref:
        compared = gh(f"repos/{repository}/compare/{base_ref}...{head}")
        behind_by = compared.get("behind_by")
        merge_base = (compared.get("merge_base_commit") or {}).get("sha")
    runs = gh(f"repos/{repository}/commits/{head}/check-runs?per_page=100")
    if runs.get("total_count") != len(runs.get("check_runs", [])):
        raise Refusal(f"PR #{number}: the check-run listing is truncated; refusing to judge a partial view")
    raw_labels = pull.get("labels")
    return {"head": head, "draft": pull.get("draft"), "behind_by": behind_by if isinstance(behind_by, int) else None,
            "mergeBase": merge_base,
            "state": pull.get("state"), "baseRef": base_ref, "defaultBranch": default_branch, "body": pull.get("body") or "",
            "labels": None if raw_labels is None else [label.get("name") for label in raw_labels],
            "checks": runs["check_runs"],
            "comments": gh(f"repos/{repository}/issues/{number}/comments?per_page=100", listing=True)}


def recorded_heads(repository, number):
    """Every head GitHub recorded for a pull request: its current head and
    both sides of each force-push (an owner rebase update records one)."""

    owner, name = repository.split("/")
    pull = ((gh_graphql(FORCE_PUSHES, owner=owner, name=name, number=number).get("data") or {})
            .get("repository") or {}).get("pullRequest") or {}
    items = pull.get("timelineItems") or {}
    nodes = items.get("nodes")
    if not isinstance(nodes, list) or items.get("totalCount") != len(nodes):
        raise Refusal(f"PR #{number}: the force-push history is missing or truncated")
    heads = {pull.get("headRefOid")}
    for node in nodes:
        heads.update((node.get(side) or {}).get("oid") for side in ("beforeCommit", "afterCommit"))
    return {sha for sha in heads if isinstance(sha, str) and SHA.fullmatch(sha)}


def carried_lanes(repository, number, pull, sources):
    """Lanes whose APPROVE carries to this head, and why each source did not.

    Sources are this pull request (an owner "Update with rebase" moves its head)
    and the pull request a re-cut superseded, named by the coordinator.
    """

    lanes, notes = [], []
    for source in sources:
        try:
            comments = pull["comments"] if source == number else gh(
                f"repos/{repository}/issues/{source}/comments?per_page=100", listing=True)
            receipts = [receipt for receipt in map(app_receipt, comments) if receipt]
            last = receipts[-1] if receipts else None
            heads, old_patch, new_patch = set(), None, None
            # Read history and Git only for a candidate worth judging; the
            # verdict below is still made by carry_verdict alone.
            if last and last[0] != pull["head"] and last[1] == "APPROVE" and not last[3]:
                compared = gh(f"repos/{repository}/compare/{pull['baseRef']}...{last[0]}")
                heads = recorded_heads(repository, source)
                old_patch = patch_identity((compared.get("merge_base_commit") or {}).get("sha"), last[0])
                new_patch = patch_identity(pull["mergeBase"], pull["head"])
            reason = carry_verdict(pull["head"], last, heads, old_patch, new_patch)
        except Refusal as error:
            reason = str(error)
        if reason is None:
            lanes.append(last[2])
            notes.append(f"PR #{source}: APPROVE at {last[0]} carried; the change is byte-identical")
        else:
            notes.append(f"PR #{source}: {reason}")
    return lanes, notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("pull_request", type=int)
    parser.add_argument("--carried-from", type=int, metavar="PR",
                        help="the pull request a re-cut superseded, whose App APPROVE may carry")
    parser.add_argument("--repo", choices=(EPOCH.OLD_REPOSITORY, EPOCH.NEW_REPOSITORY), default=REPOSITORY)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        verify_repository(args.repo, gh(f"repos/{args.repo}"))
        if args.carried_from is not None and (args.carried_from < 1 or args.carried_from == args.pull_request):
            raise Refusal("--carried-from must name another pull request")
        pull = snapshot(args.repo, args.pull_request)
        carried, notes = [], []
        if not any(receipt and receipt[0] == pull["head"] for receipt in map(app_receipt, pull["comments"])):
            sources = [args.pull_request] + ([args.carried_from] if args.carried_from else [])
            carried, notes = carried_lanes(args.repo, args.pull_request, pull, sources)
        lanes, tiers, blockers = ready_decision(pull["head"], pull["labels"], pull["comments"], pull["checks"],
                                                pull["behind_by"], pull["state"], pull["baseRef"], pull["defaultBranch"],
                                                body=pull["body"], carried=carried)
    except Refusal as error:
        print(f"DENY: {error}", file=sys.stderr)
        return 1
    report = {"head": pull["head"], "draft": pull["draft"], "state": pull["state"], "baseRef": pull["baseRef"],
              "approvingLanes": lanes, "tierLabels": tiers, "blockers": blockers, "carry": notes}
    # Lanes and tiers are printed side by side deliberately: whether these
    # lanes are the right reviewers for this tier is the coordinator's call.
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else
          f"HEAD: {pull['head']}\nSTATE: {pull['state']} -> {pull['baseRef']}\nDRAFT: {pull['draft']}\n"
          f"LANES: {', '.join(lanes) or 'none'}\nTIERS: {', '.join(tiers) or 'none'}\n"
          + "".join(f"CARRY: {note}\n" for note in notes)
          + "(whether these lanes suit these tiers is the coordinator's judgment, not this tool's)\n"
          + ("ELIGIBLE" if not blockers else "BLOCKED\n" + "\n".join(f"- {b}" for b in blockers)))
    return 3 if blockers else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
