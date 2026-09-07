"""Mutation checks for the installed Flux RBAC structural validator."""

import shutil
import re
import tempfile
import unittest
from pathlib import Path

from .support import load_script


ROOT = Path(__file__).resolve().parents[2]


class FluxRbacStructuralValidatorTests(unittest.TestCase):
    """The fast gate's own checks, each shown to fail on the thing it bans.

    A structural check written against one YAML sequence style is decorative on
    files written in the other, and this repository uses both: inline lists in
    the reviewed manifests, indented sequences in the generated export. Every
    mutation below is applied in the style the real file uses.
    """

    REQUIRED_PATHS = (
        "kubernetes/flux-system/access.yaml",
        "kubernetes/flux-system/controllers/kustomization.yaml",
        "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
        "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
        "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
        "kubernetes/flux-system/controllers/patches/source-controller.yaml",
        "kubernetes/flux-system/controllers/patches/kustomize-controller.yaml",
        "kubernetes/flux-system/controllers/patches/helm-controller.yaml",
        "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
    )

    @classmethod
    def setUpClass(cls):
        cls.validator = load_script("validate_repository.py", module_name="rbac_validator")

    def build_tree(self):
        directory = tempfile.mkdtemp(prefix="flux-rbac-contract.")
        self.addCleanup(shutil.rmtree, directory, True)
        # The validator refuses to read through a reparse point, and the
        # platform temporary root is a symlink on macOS, so the fixture root is
        # resolved before anything is written under it.
        root = Path(directory).resolve()
        for relative in self.REQUIRED_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
        return root

    def test_the_reviewed_tree_produces_no_finding(self):
        self.assertEqual(self.validator.flux_rbac_contract_errors(self.build_tree()), [])

    def mutate(self, relative, old, new):
        root = self.build_tree()
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        return self.validator.flux_rbac_contract_errors(root)

    def mutate_occurrence(self, relative, old, new, occurrence):
        root = self.build_tree()
        path = root / relative
        text = path.read_text(encoding="utf-8")
        starts = [match.start() for match in re.finditer(re.escape(old), text)]
        self.assertGreater(len(starts), occurrence)
        start = starts[occurrence]
        path.write_text(
            text[:start] + new + text[start + len(old):], encoding="utf-8"
        )
        return self.validator.flux_rbac_contract_errors(root)

    def test_a_wildcard_is_refused_in_both_yaml_styles(self):
        # Applied to all three authored RBAC files: namespaced access, the
        # shared-role patch, and the install root where the per-controller roles
        # now live (issue #98). A wildcard smuggled into any one must fail.
        for relative, anchor in (
            (
                "kubernetes/flux-system/access.yaml",
                "    resources: [leases]\n",
            ),
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "    resources: [namespaces, serviceaccounts, configmaps]\n",
            ),
            (
                "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
                "    resources: [kustomizations]\n",
            ),
        ):
            for replacement in ("    resources: ['*']\n", "    resources:\n      - '*'\n"):
                with self.subTest(file=Path(relative).name, style=replacement.strip()):
                    errors = self.mutate(relative, anchor, replacement)
                    self.assertTrue(
                        any("wildcard RBAC rule" in error for error in errors), errors
                    )

    def test_site_parent_default_deny_rule_is_name_scoped_without_delete(self):
        relative = "kubernetes/flux-system/access.yaml"
        rule = (
            "  - apiGroups: [networking.k8s.io]\n"
            "    resources: [networkpolicies]\n"
            "    resourceNames: [default-deny]\n"
            "    verbs: [get, update, patch]\n"
        )
        for label, replacement in (
            ("missing", ""),
            ("all names", rule.replace("    resourceNames: [default-deny]\n", "")),
            ("app policy", rule.replace("default-deny", "allow-app-ingress")),
            ("delete", rule.replace("patch]", "patch, delete]")),
            ("watch", rule.replace("patch]", "patch, watch]")),
            ("extra field", rule.replace("    verbs:", "    extra: true\n    verbs:")),
            ("duplicate", rule + rule),
        ):
            with self.subTest(mutation=label):
                errors = self.mutate(relative, rule, replacement)
                self.assertTrue(
                    any("exact direct-site grant" in error for error in errors),
                    errors,
                )

    def test_flux_system_secret_authority_cannot_reappear(self):
        """Even a read of one named Secret in flux-system is refused."""

        anchor = "rules:\n  # Leader election is per-controller"
        for verbs in ("[get]", "[get, update]"):
            injected = (
                "rules:\n"
                '  - apiGroups: [""]\n'
                "    resources: [secrets]\n"
                "    verbs: {}\n".format(verbs)
                + "  # Leader election is per-controller"
            )
            with self.subTest(verbs=verbs):
                errors = self.mutate(
                    "kubernetes/flux-system/access.yaml", anchor, injected
                )
                self.assertTrue(
                    any("must not grant Secret access" in error for error in errors),
                    errors,
                )

    def test_per_controller_roles_cannot_gain_cluster_secret_access(self):
        relative = "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
        rule = (
            '  - apiGroups: [""]\n'
            "    resources: [secrets]\n"
            "    verbs: [get, list, watch]\n"
        )
        for controller in ("source", "kustomize", "helm"):
            anchor = (
                "  name: crd-controller-{}-flux-system\nrules:\n".format(controller)
            )
            with self.subTest(controller=controller):
                errors = self.mutate(relative, anchor, anchor + rule)
                self.assertTrue(
                    any("must not grant cluster-wide Secret access"
                        in error for error in errors),
                    errors,
                )

    def test_shared_controller_role_cannot_regain_secret_access(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
            "    resources: [namespaces, serviceaccounts, configmaps]\n",
            "    resources: [namespaces, serviceaccounts, configmaps, secrets]\n",
        )
        self.assertTrue(
            any("shared crd-controller ClusterRole must not grant Secret access" in error
                for error in errors),
            errors,
        )

    def test_tenant_helm_readback_rules_are_required_and_cannot_write(self):
        relative = "kubernetes/flux-system/access.yaml"
        # Every namespace with a helm-reconciler Role, in the order access.yaml
        # declares them — `mutate_occurrence` addresses them positionally, so a
        # namespace appended to the file must be appended here too or its rules
        # are never mutated and its subtests silently prove nothing.
        tenants = ("naranjo-online", "lidersea-com", "obsidian")
        for tenant_index, namespace in enumerate(tenants):
            for group, resource in (("", "pods"), ("apps", "replicasets")):
                group_text = '""' if group == "" else group
                rule = (
                    "  - apiGroups: [{}]\n".format(group_text)
                    + "    resources: [{}]\n".format(resource)
                    + "    verbs: [get, list, watch]\n"
                )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="missing"
                ):
                    errors = self.mutate_occurrence(
                        relative, rule, "", tenant_index
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="write"
                ):
                    errors = self.mutate_occurrence(
                        relative,
                        rule,
                        rule.replace("get, list, watch", "get, list, watch, delete"),
                        tenant_index,
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )
                with self.subTest(
                    namespace=namespace, resource=resource, mutation="resourceNames"
                ):
                    errors = self.mutate_occurrence(
                        relative,
                        rule,
                        rule.replace(
                            "    verbs: [get, list, watch]\n",
                            "    verbs: [get, list, watch]\n"
                            "    resourceNames: [release]\n",
                        ),
                        tenant_index,
                    )
                    self.assertTrue(
                        any("exact pods and replicasets" in error for error in errors),
                        errors,
                    )

    def test_claim_lifecycle_rules_are_required_exact_and_namespace_local(self):
        """Issues #211 and #348: exactly the claim-owning namespaces, no others.

        Two namespaces hold claim lifecycle now — naranjo-online for its
        usage-export pair and obsync for the obsync blobs/journal pair — so
        every mutation is applied to EACH of them by position. A check that
        only ever mutated the first would pass unchanged if the second's rule
        were deleted outright, which is precisely the regression a second
        holder introduces.
        """

        relative = "kubernetes/flux-system/access.yaml"
        claim_namespaces = ("naranjo-online", "obsidian")
        rule = (
            '  - apiGroups: [""]\n'
            "    resources: [persistentvolumeclaims]\n"
            "    verbs: [get, list, watch, create, update, patch, delete]\n"
        )
        for occurrence, namespace in enumerate(claim_namespaces):
            for label, replacement in (
                ("missing", ""),
                (
                    "extra verb",
                    rule.replace("patch, delete", "patch, delete, deletecollection"),
                ),
                (
                    "combined backing resource",
                    rule.replace(
                        "resources: [persistentvolumeclaims]",
                        "resources: [persistentvolumeclaims, persistentvolumes]",
                    ),
                ),
            ):
                with self.subTest(namespace=namespace, mutation=label):
                    errors = self.mutate_occurrence(
                        relative, rule, replacement, occurrence
                    )
                    self.assertTrue(
                        any(
                            "exact helm-reconciler PVC lifecycle rule" in error
                            or "PVC lifecycle must be only" in error
                            for error in errors
                        ),
                        errors,
                    )

        # The other direction: a namespace with no claims of its own may not
        # acquire claim lifecycle by having the rule pasted into its Role.
        unentitled_role = (
            "kind: Role\n"
            "metadata:\n"
            "  name: helm-reconciler\n"
            "  namespace: lidersea-com\n"
            "rules:\n"
        )
        errors = self.mutate(relative, unentitled_role, unentitled_role + rule)
        self.assertTrue(
            any("PVC lifecycle must be only" in error for error in errors), errors
        )

    def test_an_unrestricted_impersonate_grant_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "    verbs: [impersonate]\n    resourceNames: [helm-reconciler]\n",
            "    verbs: [impersonate]\n",
        )
        self.assertTrue(
            any("unrestricted impersonate grant" in error for error in errors), errors
        )

    def test_token_creation_is_refused(self):
        for relative, anchor in (
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "    resources: [namespaces, serviceaccounts, configmaps]\n",
            ),
            (
                "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
                "    resources: [kustomizations]\n",
            ),
        ):
            with self.subTest(file=Path(relative).name):
                errors = self.mutate(
                    relative, anchor, "    resources:\n      - serviceaccounts/token\n"
                )
                self.assertTrue(
                    any("serviceaccounts/token" in error for error in errors), errors
                )

    def test_a_re_broadened_subject_list_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
            "  - kind: ServiceAccount\n    name: source-controller\n",
            "  - kind: ServiceAccount\n    name: image-automation-controller\n"
            "    namespace: flux-system\n  - kind: ServiceAccount\n    name: source-controller\n",
        )
        self.assertTrue(
            any("exactly the installed controllers" in error for error in errors), errors
        )

    def test_reconciler_config_watcher_gates_are_exact_and_unique(self):
        operation = (
            "- op: add\n"
            "  path: /spec/template/spec/containers/0/args/-\n"
            "  value: --feature-gates=DisableConfigWatchers=true\n"
        )
        for controller in ("kustomize", "helm"):
            relative = (
                "kubernetes/flux-system/controllers/patches/"
                + controller
                + "-controller.yaml"
            )
            for label, replacement in (
                ("missing", ""),
                ("false", operation.replace("=true", "=false")),
                ("combined", operation.replace("=true", "=true,ExternalArtifact=true")),
                (
                    "selector substitute",
                    operation.replace(
                        "--feature-gates=DisableConfigWatchers=true",
                        "--watch-configs-label-selector=flux-watch=enabled",
                    ),
                ),
                ("duplicate", operation + operation),
            ):
                with self.subTest(controller=controller, mutation=label):
                    errors = self.mutate(relative, operation, replacement)
                    self.assertTrue(
                        any("feature-gate args must be exactly" in error for error in errors),
                        errors,
                    )

    def test_secondary_source_rules_are_exact_read_only_and_closed(self):
        relative = "kubernetes/flux-system/controllers/per-controller-rbac.yaml"
        cases = (
            (
                "kustomize",
                "  - apiGroups: [source.toolkit.fluxcd.io]\n"
                "    resources: [buckets, gitrepositories, ocirepositories]\n"
                "    verbs: [get, list, watch]\n",
            ),
            (
                "helm",
                "  - apiGroups: [source.toolkit.fluxcd.io]\n"
                "    resources: [ocirepositories]\n"
                "    verbs: [get, list, watch]\n",
            ),
        )
        for controller, rule in cases:
            for label, replacement in (
                ("missing", ""),
                ("write", rule.replace("get, list, watch", "get, list, watch, patch")),
                (
                    "extra kind",
                    rule.replace(
                        "ocirepositories]",
                        "ocirepositories, externalartifacts]",
                    ),
                ),
                (
                    "extra field",
                    rule.replace(
                        "    verbs:",
                        "    resourceNames: [one]\n    verbs:",
                    ),
                ),
                ("duplicate", rule + rule),
            ):
                with self.subTest(controller=controller, mutation=label):
                    errors = self.mutate(relative, rule, replacement)
                    self.assertTrue(
                        any(
                            "secondary source" in error
                            for error in errors
                        ),
                        errors,
                    )

    def test_a_flux_api_group_in_the_shared_role_is_refused(self):
        """The split's structural guard, shown to fail on the thing it bans.

        Re-adding a Flux group to the shared role is the whole regression: the
        role is bound to all three controllers, so one rule there hands every
        controller authority over the others' objects again.
        """

        for group in (
            "source.toolkit.fluxcd.io",
            "kustomize.toolkit.fluxcd.io",
            "helm.toolkit.fluxcd.io",
        ):
            with self.subTest(group=group):
                errors = self.mutate(
                    "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                    '  - apiGroups: [""]\n    resources: [events]\n',
                    "  - apiGroups: [{}]\n    resources: [events]\n".format(group),
                )
                self.assertTrue(
                    any("must not name " + group in error for error in errors), errors
                )

    def test_a_second_subject_on_a_per_controller_binding_is_refused(self):
        """A split role bound twice is the shared role under a new name."""

        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "  name: crd-controller-source-flux-system\nsubjects:\n"
            "  - kind: ServiceAccount\n    name: source-controller\n",
            "  name: crd-controller-source-flux-system\nsubjects:\n"
            "  - kind: ServiceAccount\n    name: helm-controller\n    namespace: flux-system\n"
            "  - kind: ServiceAccount\n    name: source-controller\n",
        )
        self.assertTrue(
            any("must name only source-controller" in error for error in errors), errors
        )

    def test_a_missing_per_controller_role_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "  name: crd-controller-helm-flux-system\nrules:\n",
            "  name: crd-controller-renamed\nrules:\n",
        )
        self.assertTrue(
            any(
                "per-controller ClusterRole missing from the install root: "
                "crd-controller-helm-flux-system" in error
                for error in errors
            ),
            errors,
        )

    def test_a_repointed_per_controller_binding_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
            "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
            "  name: crd-controller-kustomize-flux-system\n",
            "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
            "  name: crd-controller-source-flux-system\n",
        )
        self.assertTrue(
            any(
                "crd-controller-kustomize-flux-system must bind ClusterRole" in error
                for error in errors
            ),
            errors,
        )

    def test_repointing_the_deletion_patch_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
            "$patch: delete\n",
            "",
        )
        self.assertTrue(
            any("delete the binding, not repoint it" in error for error in errors), errors
        )

    def test_an_unwired_patch_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/controllers/kustomization.yaml",
            "    path: patches/crd-controller-role.yaml\n",
            "",
        )
        self.assertTrue(
            any("does not apply patches/crd-controller-role.yaml" in error for error in errors),
            errors,
        )

    def test_a_missing_controller_identity_role_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "  name: flux-controller-runtime\n  namespace: flux-system\nrules:",
            "  name: flux-controller-renamed\n  namespace: flux-system\nrules:",
        )
        self.assertTrue(
            any("flux-system/flux-controller-runtime" in error for error in errors), errors
        )

    def test_a_reindented_rule_still_reaches_the_exact_grant_check(self):
        # P3-3, the same vacuity class as commit 2 one axis over: re-indenting a
        # rule is valid YAML that changes nothing about what it grants, and the
        # block splitter used to assume a maximum indent.
        root = self.build_tree()
        path = root / "kubernetes/flux-system/access.yaml"
        text = path.read_text(encoding="utf-8")
        old = (
            "rules:\n"
            '  - apiGroups: [""]\n'
            "    resources: [serviceaccounts]\n"
            "    verbs: [impersonate]\n"
            "    resourceNames: [helm-reconciler]"
        )
        self.assertIn(old, text)
        reindented = (
            "rules:\n"
            '      - apiGroups: [""]\n'
            "        resources: [serviceaccounts]\n"
            "        verbs: [impersonate, delete]\n"
            "        resourceNames: [helm-reconciler]"
        )
        path.write_text(text.replace(old, reindented, 1), encoding="utf-8")
        errors = self.validator.flux_rbac_contract_errors(root)
        self.assertTrue(any("exact direct-site grant" in error for error in errors), errors)

    def test_a_reordered_rule_still_reaches_the_exact_grant_check(self):
        """The same vacuity class as re-indentation, one axis over.

        `_rbac_rule_blocks` returned each rule with its `- ` item marker still
        in front of the first field, and `_rbac_rule_list` reads a field only
        where the marker is not. So the FIRST field of every rule was invisible
        to every check built on that helper, and RBAC does not care what order
        a rule's fields are written in: moving `resources:` to the front is
        valid YAML that grants exactly the same thing and used to evade the
        flux-system Secret-write check completely.

        Found while adding the shared-role apiGroups check for issue #98, whose
        field IS first on every rule — it would have been decorative for the
        same reason. The helper now substitutes the marker with the two spaces
        it occupied, and this is the proof.
        """

        root = self.build_tree()
        path = root / "kubernetes/flux-system/access.yaml"
        text = path.read_text(encoding="utf-8")
        old = (
            "rules:\n"
            '  - apiGroups: [""]\n'
            "    resources: [serviceaccounts]\n"
            "    verbs: [impersonate]\n"
            "    resourceNames: [helm-reconciler]"
        )
        self.assertIn(old, text)
        reordered = (
            "rules:\n"
            "  - resources: [serviceaccounts]\n"
            '    apiGroups: [""]\n'
            "    resourceNames: [helm-reconciler]\n"
            "    verbs: [impersonate, update]"
        )
        path.write_text(text.replace(old, reordered, 1), encoding="utf-8")
        errors = self.validator.flux_rbac_contract_errors(root)
        self.assertTrue(any("exact direct-site grant" in error for error in errors), errors)

    def test_a_patch_that_targets_the_wrong_object_is_refused(self):
        for relative, old, new, fragment in (
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
                "kind: ClusterRole\n",
                "kind: Role\n",
                "must target kind ClusterRole",
            ),
            (
                "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
                "  name: crd-controller-flux-system\n",
                "  name: crd-controller-renamed\n",
                "must name crd-controller-flux-system",
            ),
        ):
            with self.subTest(patch=Path(relative).name):
                errors = self.mutate(relative, old, new)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_a_missing_patch_or_install_root_or_authored_file_is_refused(self):
        for relative, fragment in (
            (
                "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
                "Flux RBAC narrowing patch is missing: cluster-reconciler.yaml",
            ),
            (
                "kubernetes/flux-system/controllers/kustomization.yaml",
                "Flux controller install root is missing",
            ),
            (
                "kubernetes/flux-system/access.yaml",
                "authored Flux RBAC file is missing",
            ),
        ):
            root = self.build_tree()
            (root / relative).unlink()
            with self.subTest(removed=relative):
                errors = self.validator.flux_rbac_contract_errors(root)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_a_hand_written_cluster_admin_binding_is_refused(self):
        errors = self.mutate(
            "kubernetes/flux-system/access.yaml",
            "  name: flux-controller-runtime\n  namespace: flux-system\nrules:",
            "  name: cluster-admin\n  namespace: flux-system\nrules:",
        )
        self.assertTrue(any("cluster-admin binding" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
