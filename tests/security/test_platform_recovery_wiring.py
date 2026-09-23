"""Executable local controls for recovery credential, payload and write phases."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from . import test_platform_release_contract as legacy
from . import test_platform_release_recovery as recovery

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-release-recovery.yml"
TRANSACTION = ROOT / "scripts/ci/publish-platform-release.sh"
WRAPPER = ROOT / "scripts/ci/publish-platform-recovery.sh"


def function(source, name):
    start = source.index(name + "() {\n")
    return source[start:source.index("\n}\n", start) + 3]


def workflow_contract(source):
    """Independently inventory the intentionally small no-input workflow."""
    def require(value):
        if not value:
            raise ValueError("recovery workflow authority or binding differs")
    require(re.search(r"^on:\n(.*?)^permissions:", source, re.M | re.S).group(1).strip() == "workflow_dispatch:")
    require(re.findall(r"^permissions:.*$", source, re.M) == ["permissions: {}"])
    require(re.search(r"^concurrency:\n(.*?)^jobs:", source, re.M | re.S).group(1).strip() ==
            "group: platform-source-recovery\n  cancel-in-progress: false")
    names = re.findall(r"^  ([a-z-]+):$", source.split("jobs:\n", 1)[1], re.M)
    require(names == ["prepare", "immutable-settings", "publish"])
    parts = re.split(r"^  (?:prepare|immutable-settings|publish):\n", source, flags=re.M)[1:]
    for index, part in enumerate(parts):
        predicate = " ".join(re.search(r"    if: (.*?)    runs-on:", part, re.S).group(1).removeprefix(">-").split())
        expected = "github.ref == 'refs/heads/main' && github.run_attempt == 1"
        if index > 0:
            expected += " && needs.prepare.outputs.selection != ''"
        if index == 2:
            expected += (" && needs.immutable-settings.outputs.attestation == format('PASS:{0}:{1}:{2}:{3}',"
                         " github.repository, github.run_id, github.run_attempt, needs.prepare.outputs.source_sha)")
        require(predicate == expected)
        # The publish job's budget is derived, not chosen: fixed setup plus the
        # measured per-edge publish cost for every edge `prepare` can admit.
        require(f"timeout-minutes: {recovery.R.publish_timeout_minutes() if index == 2 else 15}" in part)
        require(part.count("ref: ${{ github.sha }}") == 1 and part.count("persist-credentials: false") == 1
                and part.count("fetch-depth: 0") == 1 and part.count("runs-on: ubuntu-24.04") == 1)
        permissions = re.search(r"    permissions:\n((?:      [a-z-]+: [a-z]+\n)+)", part).group(1)
        expected = "      actions: read\n      contents: " + ("write\n      id-token: write\n" if index == 2 else "read\n")
        require(permissions == expected)
        require(part.count("./scripts/ci/install-tools.sh") == 1)
    prepare, settings, publish = parts
    require("needs:" not in prepare and "environment:" not in prepare and "PLATFORM_RELEASE_APP" not in prepare)
    require("needs: prepare" in settings and "needs: [prepare, immutable-settings]" in publish)
    require("name: platform-release\n      deployment: false" in settings and "environment:" not in publish)
    require(source.count("${{ secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY }}") == 1
            and source.count("${{ vars.PLATFORM_RELEASE_APP_ID }}") == 1)
    require("owner: snaraj\n          repositories: platform\n          permission-administration: read" in settings
            and "skip-token-revoke: false" in settings)
    require(settings.index("platform_release_recovery.py verify") < settings.index("create-github-app-token@"))
    require("selection: ${{ steps.selection.outputs.selection }}" in prepare
            and "source_sha: ${{ steps.selection.outputs.source_sha }}" in prepare
            and "RECOVERY_READ_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in prepare
            and "platform_release_recovery.py prepare" in prepare)
    require("RECOVERY_SELECTION: ${{ needs.prepare.outputs.selection }}" in settings
            and "SOURCE_SHA: ${{ needs.prepare.outputs.source_sha }}" in settings
            and "attestation: ${{ steps.settings.outputs.attestation }}" in settings)
    require("needs.immutable-settings.outputs.attestation ==" in publish
            and "format('PASS:{0}:{1}:{2}:{3}', github.repository, github.run_id," in publish
            and "github.run_attempt, needs.prepare.outputs.source_sha)" in publish)
    require("RECOVERY_SELECTION: ${{ needs.prepare.outputs.selection }}" in publish
            and "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in publish
            and "bash scripts/ci/publish-platform-recovery.sh" in publish
            and "PLATFORM_RELEASE_APP" not in publish and "IMMUTABLE_SETTINGS_TOKEN" not in publish)
    actions = re.findall(r"uses: ([^\n]+)", source)
    require(actions == ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0",
                        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"])


class RecoveryWiringTests(unittest.TestCase):
    def test_owner_boundaries_survive_the_table_removal(self):
        """The tables are gone; every owner boundary sentence is not.

        The runbook must no longer carry a hand-maintained window: a table of
        sources is exactly the artefact issue #395 removed, and a stale one is
        a false map of a window nothing can re-publish.
        """
        runbook = (ROOT / "docs/runbooks/platform-source-releases.md").read_text()
        self.assertEqual(re.findall(r"^\| `(v[0-9.]+)` \| `([0-9a-f]{40})` \|$", runbook, re.M), [])
        self.assertEqual(re.findall(r"^\| `([0-9a-f]{40})`", runbook, re.M), [])
        self.assertNotIn("HISTORICAL_RELEASES", runbook)
        self.assertNotIn("PINNED_EXECUTIONS", runbook)
        for text in ("Only the owner may prepare", "Agents never create tag objects or refs.",
                     "The owner must not create the Release or its assets.",
                     "No token-scope expansion or automatic tag fallback is permitted.",
                     "python3 -I -B scripts/prepare_recovery_tags.py --repository . --head origin/main --push",
                     "gh workflow run platform-release-recovery.yml --ref main"):
            self.assertIn(text, runbook)
        controls = (ROOT / "docs/runbooks/github-controls.md").read_text()
        self.assertIn("platform-source-releases.md#owner-prepared-historical-tags", controls)
        self.assertIn("Agents never create tag objects or refs.", controls)

    def test_main_only_first_attempt_jobs_and_exact_authority(self):
        source = WORKFLOW.read_text()
        workflow_contract(source)
        mutations = (
            ("workflow_dispatch:", "workflow_dispatch:\n    inputs:\n      source:\n        required: true"),
            ("permissions: {}", "permissions:\n  contents: write"),
            ("group: platform-source-recovery", "group: recovery-${{ github.run_id }}"),
            ("cancel-in-progress: false", "cancel-in-progress: true"),
            ("github.ref == 'refs/heads/main' && ", ""), (" && github.run_attempt == 1", ""),
            ("ref: ${{ github.sha }}", "ref: main"), ("persist-credentials: false", "persist-credentials: true"),
            ("fetch-depth: 0", "fetch-depth: 1"), ("actions: read", "actions: write"),
            ("needs: prepare", "needs: []"), ("needs: [prepare, immutable-settings]", "needs: prepare"),
            ("repositories: platform", "repositories: other"), ("permission-administration: read", "permission-administration: write"),
            ("skip-token-revoke: false", "skip-token-revoke: true"),
            ("RECOVERY_SELECTION: ${{ needs.prepare.outputs.selection }}", "RECOVERY_SELECTION: '{}'"),
            ("github.run_attempt, needs.prepare.outputs.source_sha)", "github.run_attempt, github.sha)"),
            ("platform_release_recovery.py verify", "true"), ("platform_release_recovery.py prepare", "true"),
            ("bash scripts/ci/publish-platform-recovery.sh", "bash scripts/ci/publish-platform-release.sh"),
            (f"timeout-minutes: {recovery.R.publish_timeout_minutes()}", "timeout-minutes: 360"),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises((ValueError, AttributeError)):
                workflow_contract(source.replace(before, after, 1))

    def execute(self, code, environment=None, files=None):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".recovery-shell-") as directory:
            root = Path(directory)
            for name, data in (files or {}).items():
                (root / name).write_text(data)
            env = os.environ.copy()
            for name in ("GH_TOKEN", "GITHUB_TOKEN", "RECOVERY_READ_TOKEN", "IMMUTABLE_SETTINGS_TOKEN",
                         "ACTIONS_READ_TOKEN", "CONTENTS_READ_TOKEN"):
                env.pop(name, None)
            env.update({"RUNNER_TEMP": legacy.PublicationTransactionShellTests.bash_path(root), **(environment or {})})
            completed = subprocess.run([legacy.PublicationTransactionShellTests.bash_executable(), "-c", "set -euo pipefail\n" + code],
                                       cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
            return completed, {path.name: path.read_text() for path in root.iterdir() if path.is_file()}

    def test_exact_recovery_payloads_and_ordinary_unchanged_payloads(self):
        source = function(TRANSACTION.read_text(), "restrict_recovery_request")
        original = {"tag_name": "v0.1.81", "name": "Platform v0.1.81", "body": "bound notes",
                    "draft": True, "prerelease": False, "target_commitish": "a" * 40}
        for phase, expected in (("create", {k: v for k, v in original.items() if k != "target_commitish"}),
                                ("body", {"body": "bound notes"}),
                                ("publish", {"tag_name": "v0.1.81", "draft": False})):
            for historical in ("true", "false"):
                code = source + '\nhistorical_recovery="' + historical + '"\nrestrict_recovery_request "' + phase + '" "${RUNNER_TEMP}/request.json"\n'
                completed, files = self.execute(code, files={"request.json": json.dumps(original)})
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(files["request.json"]), expected if historical == "true" else original)
                self.assertNotIn("request.json.scoped", files)
        completed, _ = self.execute(source + '\nhistorical_recovery=true\nrestrict_recovery_request unknown "${RUNNER_TEMP}/request.json"', files={"request.json": json.dumps(original)})
        self.assertNotEqual(completed.returncode, 0)

    def test_publish_selects_each_existing_historical_tag_without_target_or_extra_fields(self):
        source = function(TRANSACTION.read_text(), "restrict_recovery_request")
        for tag in ("v0.1.81", "v0.1.82", "v0.1.83"):
            original = {"tag_name": tag, "draft": True, "target_commitish": "a" * 40,
                        "name": "ignored", "body": "ignored", "prerelease": True}
            code = source + '\nhistorical_recovery=true\nrestrict_recovery_request publish "${RUNNER_TEMP}/request.json"\n'
            with self.subTest(tag=tag):
                completed, files = self.execute(code, files={"request.json": json.dumps(original)})
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(files["request.json"]), {"tag_name": tag, "draft": False})

    def test_wrapper_drains_every_edge_in_order_and_stops_at_the_first_refusal(self):
        """One dispatch, one publisher invocation per edge, in ledger order.

        The wrapper is the loop issue #395 asks for: it settles the read proof
        once, then per edge binds exactly that edge's context, publishes, reads
        the new Release back independently, and logs the decision. A refusal
        stops the run with nothing after it attempted.
        """
        preamble = r'''
python3() {
  test -z "${GH_TOKEN-}"
  case "${4-}" in
    verify)
      test "${RECOVERY_READ_TOKEN-}" = synthetic-write-value
      printf 'verify\n' >> "${RUNNER_TEMP}/calls"
      ;;
    readback)
      test "${RECOVERY_READ_TOKEN-}" = synthetic-write-value
      test "${RECOVERY_EDGE_TAG}" = "${TAG}"
      printf 'readback:%s\n' "${TAG}" >> "${RUNNER_TEMP}/calls"
      if [ "${TEST_REFUSE_READBACK-}" = "${TAG}" ]; then return 1; fi
      ;;
    *) return 90 ;;
  esac
}
bash() {
  test "$1" = scripts/ci/publish-platform-release.sh
  test "${GH_TOKEN-}" = synthetic-write-value
  test -z "${RECOVERY_READ_TOKEN-}"
  test -z "${IMMUTABLE_SETTINGS_TOKEN-}"
  printf 'publish:%s\n' "${TAG}" >> "${RUNNER_TEMP}/calls"
  printf '%s\n' "${SOURCE_SHA}" "${TAG}" "${BASE_SHA}" "${BASE_TAG}" "${MAIN_RUN_ID}" \
    "${MAIN_RUN_ATTEMPT}" "${EXECUTION_MAIN_RUN_ID}" "${EXECUTION_MAIN_RUN_ATTEMPT}" \
    "${RECOVERY_EDGE_TAG}" >> "${RUNNER_TEMP}/context"
  if [ "${TEST_REFUSE_PUBLISH-}" = "${TAG}" ]; then return 1; fi
}
'''
        edges = [{"tag": f"v0.1.9{index}", "source_sha": chr(97 + index) * 40,
                  "base_tag": f"v0.1.9{index - 1}" if index else "v0.1.89",
                  "base_sha": chr(96 + index) * 40 if index else "z" * 40,
                  "tree_sha": "1" * 40, "fragment_path": f"changelog.d/{index}-edge.md",
                  "fragment_sha256": "2" * 64, "main_run_id": 600 + index,
                  "main_run_attempt": 1, "codeql_run_id": 700 + index,
                  "codeql_run_attempt": 1, "workflows": {}}
                 for index in range(4)]
        value = {"edges": edges, "executor_main_run_id": 400, "executor_main_run_attempt": 2}
        env = {"GH_TOKEN": "synthetic-write-value", "RECOVERY_SELECTION": json.dumps(value)}
        completed, files = self.execute(preamble + WRAPPER.read_text(), env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(files["calls"].splitlines(),
                         ["verify", *[item for edge in edges
                                      for item in (f"publish:{edge['tag']}", f"readback:{edge['tag']}")]])
        context = files["context"].splitlines()
        self.assertEqual(len(context), 9 * len(edges))
        for index, edge in enumerate(edges):
            self.assertEqual(context[9 * index:9 * (index + 1)],
                             [edge["source_sha"], edge["tag"], edge["base_sha"], edge["base_tag"],
                              str(edge["main_run_id"]), "1", "400", "2", edge["tag"]])
        self.assertEqual(completed.stdout.count("RECOVERY_EDGE "), 4)
        self.assertIn("RECOVERY_SUMMARY pending=4 published=4 stopped_at=none", completed.stdout)
        for index, edge in enumerate(edges):
            for refusal, marker in (("TEST_REFUSE_PUBLISH", "publisher-exit"),
                                    ("TEST_REFUSE_READBACK", "readback-exit")):
                completed, files = self.execute(
                    preamble + WRAPPER.read_text(), {**env, refusal: edge["tag"]})
                with self.subTest(stop=edge["tag"], refusal=refusal):
                    self.assertNotEqual(completed.returncode, 0)
                    published = [line for line in files["calls"].splitlines()
                                 if line.startswith("publish:")]
                    self.assertEqual(published,
                                     [f"publish:{item['tag']}" for item in edges[:index + 1]])
                    self.assertIn(f"decision=refused:{marker}", completed.stderr)
                    self.assertIn(f"stopped_at={edge['tag']}", completed.stderr)
                    self.assertIn(f"published={index}", completed.stderr)
        completed, _ = self.execute(preamble + WRAPPER.read_text(),
                                    {**env, "RECOVERY_SELECTION": json.dumps({"edges": []})})
        self.assertNotEqual(completed.returncode, 0)

    def test_write_boundary_refuses_changed_executor_predecessor_and_tag(self):
        transaction = TRANSACTION.read_text()
        source = function(transaction, "boundary_refuse") + function(transaction, "release_write_boundary")
        preamble = r'''
epoch='{"version":4}'
historical_recovery=true
bound_tag_object=''
write_token=synthetic-write-value
api=https://api.github.test/repos/example/platform
SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
BASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
TAG=v0.1.81
BASE_TAG=v0.1.80
GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
ref_json="${RUNNER_TEMP}/ref.json"
git() { if [ "$1" = show ]; then printf '2026-09-11T00:00:00Z\n'; fi; }
python3() {
  test "${4-}" = bind || return 1
  if [ "${TEST_REFUSE-}" = binding ]; then return 1; fi
  printf 'binding\n' >> "${RUNNER_TEMP}/calls"
}
get_json() {
  printf '{"ref":"refs/heads/main","object":{"type":"commit","sha":"%s"}}' "${OBSERVED_MAIN}" > "$3"
  printf '%s' "${HTTP_STATUS}"
}
TAG=v0.1.81
classify_tag() {
  printf 'tag:%s\n' "$3" >> "${RUNNER_TEMP}/calls"
  if [ "${TEST_REFUSE-}" = "$3" ]; then return 1; fi
  printf '{"object":{"sha":"%s"}}' "${OBSERVED_TAG}" > "${ref_json}"
}
classify_predecessor_release() {
  printf 'predecessor\n' >> "${RUNNER_TEMP}/calls"
  if [ "${TEST_REFUSE-}" = predecessor ]; then return 1; fi
}
'''
        env = {"OBSERVED_MAIN": "e" * 40, "OBSERVED_TAG": "c" * 40, "HTTP_STATUS": "200"}
        completed, files = self.execute(preamble + source + "\nrelease_write_boundary\n", env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(files["calls"].splitlines(), ["binding", "tag:v0.1.80", "predecessor", "tag:v0.1.81"])
        for changed, check in (({"TEST_REFUSE": "binding"}, "selection-binding"),
                               ({"OBSERVED_MAIN": "d" * 40}, "executor-is-current-main"),
                               ({"HTTP_STATUS": "403"}, "current-main-read"),
                               ({"HTTP_STATUS": "404"}, "current-main-read"),
                               ({"TEST_REFUSE": "predecessor"}, "predecessor-release"),
                               ({"TEST_REFUSE": "v0.1.80"}, "predecessor-tag"),
                               ({"TEST_REFUSE": "v0.1.81"}, "current-tag")):
            completed, _ = self.execute(preamble + source + "\nrelease_write_boundary\n", {**env, **changed})
            self.assertNotEqual(completed.returncode, 0, changed)
            # Every refusal names the check that refused (failure-logging).
            self.assertIn(f"check={check}", completed.stderr, changed)
        completed, _ = self.execute(preamble + source + '\nrelease_write_boundary\nOBSERVED_TAG=dddddddddddddddddddddddddddddddddddddddd\nrelease_write_boundary\n', env)
        self.assertNotEqual(completed.returncode, 0)

    def test_every_release_and_asset_write_has_before_and_after_boundaries(self):
        source = TRANSACTION.read_text()
        publish = function(source, "publish_current_release")
        for phase, request in (("create", "draft_request"), ("body", "body_patch"), ("publish", "publish_patch")):
            position = publish.index(f'restrict_recovery_request {phase} "${{{request}}}"')
            after = publish[position:]
            mutation = after.index("run_write_gh api --method")
            end_write = after.index(f'--input "${{{request}}}"', mutation)
            end_line = after.index("\n", end_write)
            self.assertIn("release_write_boundary", after[:mutation])
            self.assertEqual(after[end_line + 1:].splitlines()[0].strip(), "release_write_boundary")
        upload = function(source, "upload_identity_asset")
        self.assertLess(upload.index("release_write_boundary"), upload.index("curl --silent"))
        self.assertGreater(upload.rindex("release_write_boundary"),
                           upload.index('if [ "${status}" != 201 ]'))
        # The upload that died silently now prints its status and a bounded
        # slice of the response body; neither carries the credential.
        self.assertIn("IDENTITY_ASSET_UPLOAD refused", upload)
        self.assertIn('head -c 512 "${asset_upload_json}"', upload)
        self.assertNotIn("write_token", upload.split("if [ \"${status}\" != 201 ]")[1])
        for name in ("complete_recovery_release", "retire_burned_partial_draft"):
            part = function(source, name)
            self.assertIn('if [ "${historical_recovery}" = true ]; then return; fi', part)
        self.assertIn('if [ "${historical_recovery}" = true ]; then test "${recovery_release_state}" = exact; fi',
                      function(source, "preflight_publication_state"))
        preflight = function(source, "preflight_publication_state")
        self.assertLess(preflight.index("platform_release_recovery.py bind"), preflight.index("get_json"))

    def test_shared_verifiers_bind_executor_signature_and_fetch_its_exact_ci(self):
        source = TRANSACTION.read_text()
        signature = function(source, "verify_identity_signature")
        preamble = r'''
epoch_contract=synthetic-epoch
identity_issuer=https://token.actions.githubusercontent.com
python3() { printf '%s' "${TEST_POLICY}"; }
env() { printf '%s\n' "$@" > "${RUNNER_TEMP}/arguments"; }
'''
        policy = {"version": 4, "publisher_event": "workflow_dispatch", "subject": "https://example.invalid/recovery"}
        completed, files = self.execute(preamble + signature + '\nverify_identity_signature "${RUNNER_TEMP}/identity" bundle v0.1.81',
            {"TEST_POLICY": json.dumps(policy)}, {"identity": json.dumps({"execution": {"source_sha": "e" * 40}})})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        args = files["arguments"].splitlines()
        for flag, expected in (("--certificate-identity", policy["subject"]), ("--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"),
                               ("--certificate-github-workflow-sha", "e" * 40), ("--certificate-github-workflow-trigger", "workflow_dispatch")):
            self.assertEqual(args[args.index(flag) + 1], expected)
        runs = function(source, "validate_identity_runs")
        value = {"schema": "https://snaraj.dev/schemas/platform-release-identity/v4",
                 "main_ci": {"run_id": 100, "run_attempt": 1}, "platform_release": {"run_id": 200, "run_attempt": 1},
                 "execution": {"main_ci": {"run_id": 300, "run_attempt": 2}}}
        preamble = r'''
api=https://api.github.test/repos/example/platform
contract=synthetic-contract
legacy_main_run_json="${RUNNER_TEMP}/main"
legacy_platform_run_json="${RUNNER_TEMP}/publisher"
get_public_json() { printf '%s\n' "$1" >> "${RUNNER_TEMP}/reads"; printf '%s' "${TEST_HTTP}"; }
python3() { printf '%s\n' "$@" > "${RUNNER_TEMP}/arguments"; }
'''
        for status in ("200", "403", "404"):
            completed, files = self.execute(preamble + runs + '\nvalidate_identity_runs "${RUNNER_TEMP}/identity"',
                                            {"TEST_HTTP": status}, {"identity": json.dumps(value)})
            self.assertEqual(completed.returncode == 0, status == "200", completed.stderr)
            if status == "200":
                self.assertEqual([line.rsplit("/runs/", 1)[1] for line in files["reads"].splitlines()],
                                 ["100/attempts/1", "200/attempts/1", "300/attempts/2"])
                args = files["arguments"].splitlines()
                self.assertTrue(args[args.index("--execution-main-run-json") + 1].endswith("platform-executor-main-run.json"))
            else:
                self.assertNotIn("arguments", files)

    def test_ordinary_executor_movement_and_historical_mode_refuse_before_reads(self):
        source = TRANSACTION.read_text()
        gate = source[source.index("historical_recovery=false"):source.index("\nget_json()")]
        preamble = r'''
git() { printf '%s' "${CHECKOUT_SHA}"; }
python3() { printf '%s\n' "${4-}" >> "${RUNNER_TEMP}/proofs"; test "${TEST_REFUSE-}" != "${4-}"; }
'''
        env = {"SOURCE_SHA": "a" * 40, "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
               "CHECKOUT_SHA": "a" * 40, "GITHUB_EVENT_NAME": "workflow_run", "epoch": '{"version":4}'}
        for change in ({}, {"GITHUB_SHA": "b" * 40}, {"GITHUB_WORKFLOW_SHA": "b" * 40},
                       {"CHECKOUT_SHA": "b" * 40}, {"GITHUB_EVENT_NAME": "workflow_dispatch"}, {"RECOVERY_SELECTION": "{}"}):
            completed, files = self.execute(preamble + gate + '\nprintf admitted > "${RUNNER_TEMP}/admitted"', {**env, **change})
            self.assertEqual(completed.returncode == 0, not change, completed.stderr)
            self.assertEqual("admitted" in files, not change)
        recovery = {**env, "epoch": '{"version":4,"publisher_event":"workflow_dispatch"}',
                    "RECOVERY_SELECTION": "{}", "write_token": "synthetic"}
        for refuse in ("", "verify", "bind"):
            completed, files = self.execute(preamble + gate, {**recovery, "TEST_REFUSE": refuse})
            self.assertEqual(completed.returncode == 0, not refuse, completed.stderr)
            self.assertEqual(files["proofs"].splitlines(), ["verify"] if refuse == "verify" else ["verify", "bind"])

    def test_predecessor_reader_keeps_pending_distinct_and_stops_failed_structural_proof(self):
        source = (ROOT / "scripts/ci/wait-platform-release-predecessor.sh").read_text()
        classifier = function(source, "classify_predecessor_release")
        preamble = r'''
contract=synthetic-contract
epoch_contract=synthetic-epoch
api=https://api.github.test/repos/example/platform
read_token=synthetic
transport_args=()
original_publisher_pending=false
for name in identity_json bundle_json release_json ref_json notes; do printf -v "$name" '%s/%s' "${RUNNER_TEMP}" "$name"; done
printf '{"object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' > "${ref_json}"
get_json() { printf '{"assets":[{"id":1,"name":"identity"},{"id":2,"name":"bundle"}]}' > "$2"; printf 200; }
get_asset() { printf '{}' > "$2"; printf 200; }
git() { printf aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; }
python3() {
  if [ "$3" = synthetic-epoch ]; then printf '{"asset":"identity","bundle":"bundle","version":%s}' "${TEST_VERSION}"; return; fi
  printf '%s\n' "$4" >> "${RUNNER_TEMP}/proofs"
  if [ "$4" = identity-release-state ]; then return "${TEST_STRUCTURAL}"; fi
  test "$4" = predecessor
  test "${RECOVERY_READ_TOKEN}" = synthetic
  return "${TEST_ORIGINAL}"
}
'''
        tail = '\nif classify_predecessor_release exact v0.1.81 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; then status=0; else status=$?; fi\nprintf "%s:%s" "${status}" "${original_publisher_pending}" > "${RUNNER_TEMP}/result"\n'
        for version, structural, original, expected, calls in (
            (4, 0, 0, "0:false", ["identity-release-state", "predecessor"]),
            (4, 0, 3, "3:true", ["identity-release-state", "predecessor"]),
            (4, 0, 1, "1:false", ["identity-release-state", "predecessor"]),
            (4, 1, 0, "1:false", ["identity-release-state"]),
            (3, 0, 1, "0:false", ["identity-release-state"]),
        ):
            completed, files = self.execute(preamble + classifier + tail,
                {"TEST_VERSION": str(version), "TEST_STRUCTURAL": str(structural), "TEST_ORIGINAL": str(original)})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(files["result"], expected)
            self.assertEqual(files["proofs"].splitlines(), calls)
        loop = source[source.index("for _attempt in {1..30}"):]
        self.assertEqual(loop.splitlines()[1].strip(), "original_publisher_pending=false")
        pending = loop.index('elif [ "${original_publisher_pending}" = true ]; then')
        absent = loop.index('elif classify_predecessor_release absent', pending)
        self.assertIn("sleep 10\n    continue", loop[pending:absent])

    def test_publication_writes_once_and_preserves_ambiguous_results(self):
        source = TRANSACTION.read_text()
        selected = "\n".join(function(source, name) for name in
                             ("restrict_recovery_request", "upload_identity_asset", "publish_current_release"))
        preamble = r'''
historical_recovery=true
contract=synthetic-contract
epoch='{"version":4}'
TAG=v0.1.81
SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GITHUB_REPOSITORY=example/platform
api=https://api.github.test/repos/example/platform
api_version=2026-03-10
write_token=synthetic
for name in ref_json release_json draft_marker notes draft_request body_patch publish_patch identity_asset identity_bundle \
  identity_download bundle_download asset_upload_json; do printf -v "$name" '%s/%s' "${RUNNER_TEMP}" "$name"; done
identity_asset_name=identity.json
identity_bundle_name=bundle.json
printf '{"object":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}' > "${ref_json}"
git() { printf '2026-09-11T00:00:00Z'; }
classify_tag() { test "$1" = exact; }
preflight_publication_state() { :; }
write_current_draft_marker() { printf 'marker' > "${draft_marker}"; }
write_current_notes() { printf 'notes' > "${notes}"; }
classify_current_release() {
  if [ -f "${RUNNER_TEMP}/published" ]; then test "$1" = exact; else test "$1" = absent; fi
}
classify_current_draft() {
  if [ -f "${RUNNER_TEMP}/created" ]; then test "$1" = exact; printf 300; else test "$1" = absent; fi
}
release_write_boundary() { printf 'boundary\n' >> "${RUNNER_TEMP}/calls"; }
get_json() { printf '{}' > "$3"; printf 200; }
python3() { if [ "${4-}" = release-draft-state ]; then printf 300; fi; }
write_current_identity() { printf '{}' > "${identity_asset}"; }
env() { test "$3" = cosign; printf '{}' > "${identity_bundle}"; }
verify_identity_signature() { :; }
download_identity_pair() { cp "${identity_asset}" "${identity_download}"; cp "${identity_bundle}" "${bundle_download}"; }
run_write_gh() {
  local input='' phase
  while [ "$#" -gt 0 ]; do if [ "$1" = --input ]; then input="$2"; shift 2; else shift; fi; done
  case "${input}" in
    */draft_request) phase=create ;;
    */body_patch) phase=body ;;
    */publish_patch) phase=publish ;;
    *) return 90 ;;
  esac
  printf '%s\n' "${phase}" >> "${RUNNER_TEMP}/calls"
  if [ "${TEST_REFUSE-}" = "${phase}" ]; then return 1; fi
  cp "${input}" "${RUNNER_TEMP}/${phase}-payload"
  if [ "${phase}" = create ]; then touch "${RUNNER_TEMP}/created"; printf 300; fi
  if [ "${phase}" = publish ]; then touch "${RUNNER_TEMP}/published"; fi
  if [ "${TEST_AMBIGUOUS-}" = "${phase}" ]; then return 1; fi
}
curl() {
  local argument phase=asset
  for argument in "$@"; do case "${argument}" in *name=bundle.json) phase=bundle ;; esac; done
  printf '%s\n' "${phase}" >> "${RUNNER_TEMP}/calls"
  if [ "${TEST_REFUSE-}" = "${phase}" ]; then printf '%s' "${TEST_HTTP-403}"; return; fi
  touch "${RUNNER_TEMP}/${phase}-uploaded"
  if [ "${TEST_AMBIGUOUS-}" = "${phase}" ]; then return 1; fi
  printf 201
}
sleep() { :; }
'''
        code = preamble + selected + "\npublish_current_release\n"
        completed, files = self.execute(code)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = files["calls"].splitlines()
        phases = ["create", "body", "asset", "bundle", "publish"]
        self.assertEqual(calls, [item for phase in phases for item in ("boundary", phase, "boundary")])
        self.assertEqual(json.loads(files["create-payload"]), {"tag_name": "v0.1.81", "name": "Platform v0.1.81",
                         "body": "marker", "draft": True, "prerelease": False})
        self.assertEqual(json.loads(files["body-payload"]), {"body": "notes"})
        self.assertEqual(json.loads(files["publish-payload"]), {"tag_name": "v0.1.81", "draft": False})
        for phase in phases:
            for failure in ({"TEST_REFUSE": phase, "TEST_HTTP": "403"},
                            {"TEST_REFUSE": phase, "TEST_HTTP": "404"}, {"TEST_AMBIGUOUS": phase}):
                completed, files = self.execute(code, failure)
                self.assertNotEqual(completed.returncode, 0, (phase, failure))
                observed = [item for item in files["calls"].splitlines() if item != "boundary"]
                self.assertEqual(observed, phases[:phases.index(phase) + 1])
                if failure.get("TEST_AMBIGUOUS") == "publish":
                    self.assertIn("published", files)

    def test_historical_absence_never_creates_objects_or_refs_but_ordinary_still_does(self):
        source = function(TRANSACTION.read_text(), "publish_current_release")
        preamble = r'''
historical_recovery="${TEST_HISTORICAL}"
TAG=v0.1.81
SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GITHUB_REPOSITORY=example/platform
api_version=2026-03-10
tagger_name=synthetic-tagger
tagger_email=synthetic-email
git() { printf '2026-09-11T00:00:00Z'; }
classify_tag() {
  if [ -f "${RUNNER_TEMP}/prepared" ]; then test "$1" = exact
  elif [ "${TEST_STATE}" = foreign ]; then return 1
  else test "$1" = absent; fi
}
classify_current_release() { test "$1" = absent; }
preflight_publication_state() { :; }
run_write_gh() {
  case "$*" in
    *git/tags*) printf 'object\n' >> "${RUNNER_TEMP}/writes"; printf bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    *git/refs*) printf 'ref\n' >> "${RUNNER_TEMP}/writes"; touch "${RUNNER_TEMP}/prepared" ;;
    *) printf 'unexpected\n' >> "${RUNNER_TEMP}/writes"; return 90 ;;
  esac
}
write_current_draft_marker() { touch "${RUNNER_TEMP}/release-phase"; exit 0; }
sleep() { :; }
'''
        code = preamble + source + "\npublish_current_release\n"
        for state in ("absent", "dangling", "foreign"):
            with self.subTest(state=state):
                completed, files = self.execute(code, {"TEST_HISTORICAL": "true", "TEST_STATE": state})
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("writes", files)
                self.assertNotIn("release-phase", files)
        completed, files = self.execute(code, {"TEST_HISTORICAL": "true", "TEST_STATE": "exact"},
                                        files={"prepared": ""})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("writes", files)
        self.assertIn("release-phase", files)
        completed, files = self.execute(code, {"TEST_HISTORICAL": "false", "TEST_STATE": "absent"})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(files["writes"].splitlines(), ["object", "ref"])
        self.assertIn("release-phase", files)


if __name__ == "__main__":
    unittest.main()
