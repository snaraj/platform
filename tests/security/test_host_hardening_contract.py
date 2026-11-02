"""Contract tests for bootstrap/pi/hardening.

These tests pin the shipped configuration to the decisions in ADR 0018 so a
later edit cannot quietly weaken a fence. Every assertion names one line that
would make it fail; the adversarial review mutates those lines.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARDENING = ROOT / "bootstrap/pi/hardening"


def read(rel: str) -> str:
    return (HARDENING / rel).read_text(encoding="utf-8")


def directives(rel: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in read(rel).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        out.setdefault(key.strip(), []).append(value.strip())
    return out


class SysctlBaseline(unittest.TestCase):
    def test_required_keys_and_values(self) -> None:
        values = {}
        for line in read("sysctl/99-zz-platform-kernel-hardening.conf").splitlines():
            if line.strip() and not line.startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        expected = {
            "kernel.kptr_restrict": "2",
            "kernel.yama.ptrace_scope": "2",
            "kernel.kexec_load_disabled": "1",
            "kernel.unprivileged_bpf_disabled": "1",
            "kernel.io_uring_disabled": "2",
            "fs.suid_dumpable": "0",
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv6.conf.all.accept_ra": "0",
        }
        for key, value in expected.items():
            self.assertEqual(values.get(key), value, key)

    def test_sorts_after_distribution_defaults(self) -> None:
        name = next(HARDENING.glob("sysctl/*.conf")).name
        self.assertGreater(name, "99-protect-links.conf", "the distribution's 99-* files must not override ours")

    def test_does_not_touch_cluster_prerequisites(self) -> None:
        text = read("sysctl/99-zz-platform-kernel-hardening.conf")
        for key in ("net.ipv4.ip_forward", "net.bridge.bridge-nf-call-iptables", "vm.overcommit_memory"):
            self.assertNotIn(key, text, f"{key} belongs to host-prerequisites")


class KernelCommandLine(unittest.TestCase):
    def test_tokens(self) -> None:
        tokens = set(read("cmdline/platform-kernel-hardening.cmdline").split())
        for tok in (
            "lockdown=integrity",
            "module.sig_enforce=1",
            "init_on_alloc=1",
            "init_on_free=1",
            "slab_nomerge",
            "page_alloc.shuffle=1",
            "randomize_kstack_offset=on",
        ):
            self.assertIn(tok, tokens)
        self.assertNotIn("lockdown=none", tokens)
        self.assertFalse(any(t.startswith("lsm=") for t in tokens), "never override the LSM order")


class UnitSandboxing(unittest.TestCase):
    def test_cloudflared_is_fenced(self) -> None:
        d = directives("systemd/cloudflared.service.d/70-platform-sandbox.conf")
        for key in ("ProtectHome", "PrivateDevices", "MemoryDenyWriteExecute", "RestrictNamespaces", "LockPersonality"):
            self.assertEqual(d.get(key), ["yes"], key)
        self.assertIn("@system-service", " ".join(d.get("SystemCallFilter", [])))
        self.assertEqual(d.get("SystemCallArchitectures"), ["native"])

    def test_ntpsec_keeps_the_clock(self) -> None:
        d = directives("systemd/ntpsec.service.d/70-platform-sandbox.conf")
        self.assertNotIn("ProtectClock", d, "ntpd must be able to set the clock")
        self.assertIn("CAP_SYS_TIME", d["CapabilityBoundingSet"][0])
        self.assertEqual(d.get("NoNewPrivileges"), ["yes"])
        self.assertEqual(d.get("ProtectSystem"), ["strict"])

    def test_runtime_units_receive_only_safe_fences(self) -> None:
        for unit in ("containerd", "kubelet"):
            d = directives(f"systemd/{unit}.service.d/70-platform-sandbox.conf")
            for forbidden in ("ProtectSystem", "NoNewPrivileges", "CapabilityBoundingSet", "RestrictNamespaces", "PrivateDevices", "SystemCallFilter"):
                self.assertNotIn(forbidden, d, f"{forbidden} would break {unit}")

    def test_no_sshd_service_dropin(self) -> None:
        self.assertFalse((HARDENING / "systemd/ssh.service.d").exists(), "sshd sandboxing is inherited by admin sessions; ADR 0018")

    def test_ssh_socket_template_drops_wildcard(self) -> None:
        text = read("systemd/ssh.socket.d/70-platform-listen.conf.template")
        self.assertIn("ListenStream=\n", text, "the first ListenStream= must reset the inherited list")
        self.assertIn("ListenStream=127.0.0.1:22", text)
        self.assertIn("ListenStream=@ADMIN_TARGET@:22", text)
        self.assertNotRegex(text, r"ListenStream=(0\.0\.0\.0|\[::\]|\*):22")


class EgressAllowlist(unittest.TestCase):
    TEMPLATE = "nftables/egress-allowlist.nft.template"

    @staticmethod
    def code(text: str) -> list[str]:
        return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    def test_flushes_only_itself(self) -> None:
        self.assertFalse(any("flush" in ln for ln in self.code(read(self.TEMPLATE))), "only apply-hardening may flush, and only this table")

    def test_output_hook_ends_in_logged_drop(self) -> None:
        text = read(self.TEMPLATE)
        self.assertIn("type filter hook output priority -10", text)
        lines = self.code(text)
        body = lines[lines.index("chain output {") + 1 : lines.index("}")]
        self.assertTrue(body[-1].endswith("counter drop"))
        self.assertIn('log prefix "platform-egress-drop "', body[-2])
        self.assertNotIn("accept", body[-1])
        self.assertIn("meta skuid @LOGIN_UIDS@ tcp dport { 22, 80, 443 } accept", body)
        self.assertIn("@CLUSTER_CIDRS@", body)

    def test_no_wildcard_accept(self) -> None:
        for line in read(self.TEMPLATE).splitlines():
            s = line.strip()
            if s.endswith("accept") and not s.startswith("#"):
                self.assertTrue(
                    s.startswith(("oif lo", "ct state", "udp sport 68", "meta l4proto", "meta skuid", "@VPN_TRANSPORT@", "@CLUSTER_CIDRS@")),
                    f"unqualified accept: {s}",
                )

    def test_every_service_rule_is_uid_and_port_bound(self) -> None:
        for line in read(self.TEMPLATE).splitlines():
            s = line.strip()
            if s.startswith("meta skuid"):
                self.assertRegex(s, r'^meta skuid ("[a-z_-]+"|@LOGIN_UIDS@) (udp|tcp) dport (\{ [0-9, ]+ \}|[0-9]+) accept$', s)

    def test_unit_deletes_table_on_stop(self) -> None:
        d = directives("systemd/platform-egress-allowlist.service")
        self.assertEqual(d.get("ExecStop"), ["/usr/sbin/nft delete table inet platform_egress"])
        self.assertEqual(d.get("CapabilityBoundingSet"), ["CAP_NET_ADMIN"])


class PatchCadence(unittest.TestCase):
    def test_security_only_and_owner_reboots(self) -> None:
        text = read("apt/52-platform-unattended-security.conf")
        self.assertIn('"${distro_id}:${distro_codename}-security";', text)
        self.assertNotIn("-updates", text)
        self.assertIn('Automatic-Reboot "false"', text)

    def test_needrestart_never_restarts_the_runtime(self) -> None:
        text = read("needrestart/platform.conf")
        for unit in ("containerd", "kubelet", "cloudflared"):
            self.assertRegex(text, rf"override_rc\}}\{{q\(\^{unit}\\\.service\)\}} = 0;")

    def test_debsums_timer_daily(self) -> None:
        self.assertEqual(directives("systemd/platform-debsums.timer").get("OnCalendar"), ["daily"])


class AuditRules(unittest.TestCase):
    def test_minimal_rule_set(self) -> None:
        text = read("auditd/platform.rules")
        self.assertIn("-S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-exec", text)
        self.assertIn("-S init_module,finit_module,delete_module -k modules", text)
        self.assertIn("-w /etc/ -p wa -k etc", text)
        self.assertNotIn("-e 2", text, "immutable rules would need a reboot to change")


class Scripts(unittest.TestCase):
    SCRIPTS = ("apply-hardening.sh", "verify-hardening.sh", "remove-unneeded-surfaces.sh", "host-manifest.sh", "baseline-run.sh")

    def test_fail_closed_shell_options(self) -> None:
        for name in self.SCRIPTS:
            text = read(name)
            self.assertRegex(text, r"(?m)^set -[Eeuo]*u[Eeuo]*o pipefail$", name)

    def test_lockout_components_arm_a_revert(self) -> None:
        text = read("apply-hardening.sh")
        for comp in ("egress", "sshd-listen"):
            self.assertRegex(text, rf"arm_revert {comp} 600", f"{comp} must arm a 10-minute revert")
        self.assertIn("disarm_revert egress", text)

    def test_egress_probe_is_not_vacuous(self) -> None:
        text = read("verify-hardening.sh")
        self.assertRegex(text, r"sudo -u nobody timeout \d+ bash -c 'exec 3<>/dev/tcp/[a-z.]+/443'", "probe a destination that accepts connections, as a uid outside every rule")
        self.assertNotRegex(text, r"sudo -u nobody[^\n]*/dev/tcp/[0-9]+\.", "probe by name, never by a literal address")

    def test_cluster_files_component_targets_cis_paths(self) -> None:
        text = read("apply-hardening.sh")
        self.assertIn("chmod 0700 /var/lib/etcd", text)
        self.assertIn("chmod 0600 /etc/systemd/system/kubelet.service", text)
        self.assertNotRegex(text, r"chmod [0-7]*[2367][0-7]* /etc/kubernetes", "never widen cluster credentials")

    def test_cmdline_is_staged_not_activated(self) -> None:
        code = [ln for ln in read("apply-hardening.sh").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        for ln in code:
            self.assertNotRegex(ln, r"(^|[;&|]\s*|\$\()\s*(systemctl\s+)?(reboot|shutdown|kexec|poweroff)\b", "the owner reboots")

    def test_remover_protects_the_network_stack(self) -> None:
        text = read("remove-unneeded-surfaces.sh")
        match = re.search(r"^protected='(.+)'$", text, re.M)
        assert match
        protected = re.compile(match.group(1))
        for pkg in ("network-manager", "wpasupplicant", "openssh-server", "cloudflared", "containerd", "linux-image-raspi", "unattended-upgrades", "libnss-systemd"):
            self.assertRegex(pkg, protected)
        for pkg in ("tor", "gnome-remote-desktop", "sparrowwallet", "libnss-sss", "pulseaudio"):
            self.assertNotRegex(pkg, protected)
        self.assertIn("unattended-upgrades systemd-oomd", text, "pin the patch machinery manual before autoremove")
        self.assertIn("gnome-remote-desktop", text)
        self.assertIn("apt-mark manual", text)
        self.assertLess(text.index("apt-mark manual"), text.index("autoremove --purge\n"), "pin before autoremove")

    def test_remover_never_touches_the_legacy_archive(self) -> None:
        text = read("remove-unneeded-surfaces.sh")
        self.assertNotRegex(text, r"\.bitcoin|\.electrs|/usr/local/bin/bitcoin", "ADR 0013: inert, owner-only")

    def test_manifest_redacts_addresses(self) -> None:
        sample = "host 192.0.2.7 via 2001:db8::1 mac aa:bb:cc:dd:ee:ff mail someone@example.invalid\n"
        script = "source <(sed -n '/^redact() {/,/^}/p' \"$1\"); redact"
        out = subprocess.run(
            ["bash", "-c", script, "_", str(HARDENING / "host-manifest.sh")],
            input=sample, capture_output=True, text=True, check=True,
        ).stdout
        self.assertEqual(out, "host <ip4> via <ip6> mac <mac> mail <email>\n")

    def test_manifest_never_copies_key_material(self) -> None:
        text = read("host-manifest.sh")
        self.assertNotRegex(text, r"cat [^\n]*authorized_keys", "keys are counted, never copied")
        self.assertNotRegex(text, r"cat [^\n]*ssh_host_[a-z0-9]+_key\b(?!\.pub)")

    def test_env_example_carries_no_inventory(self) -> None:
        for line in read("hardening.env.example").splitlines():
            if line and not line.startswith("#"):
                key, _, value = line.partition("=")
                if key not in ("UPLINK_INTERFACE", "LOGIN_UID_MIN", "LOGIN_UID_MAX"):
                    self.assertEqual(value.strip('"'), "", f"{key} must ship empty")


if __name__ == "__main__":
    unittest.main()
