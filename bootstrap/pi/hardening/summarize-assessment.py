#!/usr/bin/env python3
"""Reduce one assessment phase directory to the numbers a pull request cites.

Dependency-free. Reads the raw outputs baseline-run.sh wrote and prints one
line per assessor; a missing file prints ``absent`` rather than failing, so a
partial run still summarizes. Nothing here is a judgement: the tools are.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path


def oscap(d: Path) -> str:
    f = d / "oscap-results.xml"
    if not f.exists():
        return "absent"
    text = f.read_text(encoding="utf-8", errors="replace")
    results = Counter(re.findall(r'<definition [^>]*result="([a-z ]+)"', text))
    true_ids = re.findall(r'<definition [^>]*definition_id="([^"]+)"[^>]*result="true"', text)
    return f"true={results.get('true', 0)} false={results.get('false', 0)} other={sum(v for k, v in results.items() if k not in ('true', 'false'))} unpatched_ids={','.join(sorted(true_ids)) or 'none'}"


def lynis(d: Path) -> str:
    f = d / "lynis-report.dat"
    if not f.exists():
        return "absent"
    text = f.read_text(encoding="utf-8", errors="replace")
    idx = re.search(r"^hardening_index=(\d+)", text, re.M)
    warn = len(re.findall(r"^warning\[\]=", text, re.M))
    sugg = len(re.findall(r"^suggestion\[\]=", text, re.M))
    return f"hardening_index={idx.group(1) if idx else '?'} warnings={warn} suggestions={sugg}"


def ssh_audit(d: Path) -> str:
    f = d / "ssh-audit.txt"
    if not f.exists():
        return "absent"
    text = f.read_text(encoding="utf-8", errors="replace")
    return f"fail={text.count('(fail)')} warn={text.count('(warn)')}"


def khc(d: Path) -> str:
    f = d / "kernel-hardening-checker.txt"
    if not f.exists():
        return "absent"
    text = f.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"'OK' - (\d+) / 'FAIL' - (\d+)", text)
    return f"ok={m.group(1)} fail={m.group(2)}" if m else "unparsed"


def systemd_security(d: Path) -> str:
    out = []
    for f in sorted(d.glob("systemd-security-*.service.txt")):
        unit = f.name[len("systemd-security-") : -len(".txt")]
        m = re.search(r"Overall exposure level for [^:]+: ([0-9.]+)", f.read_text(encoding="utf-8", errors="replace"))
        out.append(f"{unit}={m.group(1) if m else '?'}")
    table = d / "systemd-security.txt"
    if table.exists():
        scores = [float(x) for x in re.findall(r"^\S+\s+([0-9.]+)\s", table.read_text(encoding="utf-8", errors="replace"), re.M)]
        if scores:
            out.append(f"units={len(scores)} unsafe(>=8)={sum(s >= 8 for s in scores)}")
    return " ".join(out) or "absent"


def kube_bench(d: Path) -> str:
    f = d / "kube-bench.json"
    if not f.exists():
        return "absent"
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return "unparsed"
    totals = data.get("Totals") or {}
    return " ".join(f"{k.replace('total_', '')}={v}" for k, v in totals.items()) or "no-totals"


def kubescape(d: Path) -> str:
    f = d / "kubescape.json"
    if not f.exists():
        return "absent"
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return "unparsed"
    sd = data.get("summaryDetails") or {}
    score = sd.get("complianceScore") or sd.get("score")
    frameworks = {fw.get("name"): round(fw.get("complianceScore", 0), 1) for fw in sd.get("frameworks", [])}
    return f"score={score} frameworks={frameworks}"


def trivy_counts(path: Path) -> Counter:
    c: Counter = Counter()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return c
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            c[v.get("Severity", "?")] += 1
            if v.get("FixedVersion"):
                c["fixable:" + v.get("Severity", "?")] += 1
    return c


def trivy_rootfs(d: Path) -> str:
    f = d / "trivy-rootfs.json"
    if not f.exists():
        return "absent"
    c = trivy_counts(f)
    return f"critical={c['CRITICAL']} high={c['HIGH']} medium={c['MEDIUM']} fixable_critical={c['fixable:CRITICAL']} fixable_high={c['fixable:HIGH']}"


def trivy_images(d: Path) -> str:
    files = sorted((d / "trivy-images").glob("*.json")) if (d / "trivy-images").exists() else []
    if not files:
        return "absent"
    total: Counter = Counter()
    worst = []
    for f in files:
        c = trivy_counts(f)
        total.update(c)
        if c["CRITICAL"] or c["HIGH"]:
            worst.append(f"{f.stem[:60]}:C{c['CRITICAL']}/H{c['HIGH']}/fixC{c['fixable:CRITICAL']}/fixH{c['fixable:HIGH']}")
    return f"images={len(files)} critical={total['CRITICAL']} high={total['HIGH']} fixable_critical={total['fixable:CRITICAL']} fixable_high={total['fixable:HIGH']} nonclean={len(worst)} " + " ".join(worst[:12])


def grype(d: Path) -> str:
    f = d / "grype-rootfs.json"
    if not f.exists():
        return "absent"
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return "unparsed"
    c: Counter = Counter()
    for m in data.get("matches") or []:
        sev = (m.get("vulnerability") or {}).get("severity", "?")
        c[sev] += 1
        if (m.get("vulnerability") or {}).get("fix", {}).get("state") == "fixed":
            c["fixed:" + sev] += 1
    return f"critical={c['Critical']} high={c['High']} medium={c['Medium']} fixable_critical={c['fixed:Critical']} fixable_high={c['fixed:High']}"


def manifest(d: Path) -> str:
    m = d / "manifest"
    if not m.exists():
        return "absent"
    def count(name: str) -> int:
        f = m / name
        return sum(1 for ln in f.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.startswith(("==", "[exit"))) if f.exists() else -1
    return f"packages={count('10-packages.txt')} manual={count('11-manual.txt')} enabled_units={count('30-units-enabled.txt')} listeners={count('23-sockets.txt')} suid={count('41-suid.txt')} files={len(list(m.glob('*.txt')))}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: summarize-assessment.py <phase-dir>", file=sys.stderr)
        return 2
    d = Path(argv[1])
    for name, fn in (
        ("manifest", manifest), ("oscap", oscap), ("lynis", lynis), ("ssh-audit", ssh_audit), ("kernel-hardening-checker", khc),
        ("systemd-security", systemd_security), ("kube-bench", kube_bench), ("kubescape", kubescape),
        ("trivy-rootfs", trivy_rootfs), ("trivy-images", trivy_images), ("grype-rootfs", grype),
    ):
        print(f"{name}: {fn(d)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
