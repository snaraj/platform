# Boot-time clock and control-plane recovery

Use this procedure when an existing kubeadm host fails to recover after a
power interruption. It does not rebuild the cluster or restore application
composition. Follow [disaster recovery](disaster-recovery.md) only when the
evidence actually requires restoration; keep protected services and archives
outside ordinary repair.

## Diagnose before changing state

Retain tested recovery access and serialize host maintenance with application
operators. Record the current boot, UTC offset against a trusted independent
reference, NTP selection, runtime error classes, and workload readiness in
private evidence. Classify causes before restarting anything:

- A clock older than server certificates can prevent NTS key establishment.
  A reachable authenticated candidate still cannot discipline time when the
  configured source quorum is unsatisfied. Inspect both quorum and effective
  daemon options; do not assume the large-step option is missing.
- A running runtime container can retain a name that kubelet wants to reserve.
  A name-reservation error does not establish that the holder is safe to delete.
- Instantaneous normal power flags do not exclude recent voltage drops. Inspect
  fresh kernel events with case-insensitive matching and current firmware flags,
  distinguishing current flags from history since boot. Do not stress the host
  to reproduce a power fault.

Preserve NTS authentication, certificate validation, and the reviewed
independent-source quorum. Do not introduce unauthenticated fallback, `noval`,
or a one-source exception. NTPsec's `-g` permits one initial correction beyond
the panic threshold; it does not bypass certificate validation or source
selection. See the [NTPsec clock options](https://docs.ntpsec.org/latest/clock.html)
and [source-selection options](https://docs.ntpsec.org/latest/miscopt.html).

If the epoch is wrong, a separately authorized one-time correction from a
fresh trusted reference can unblock NTS. Record before/after offset and verify
authenticated selection afterward. Absolute-time administrative grants may
expire immediately when the clock advances; retain a recovery path that does
not depend on that grant. Do not silently extend or weaken its expiry.

## Preserve a clock floor across power loss

A battery-backed RTC preserves elapsed time while power is disconnected.
A saved timestamp only supplies an approximate lower bound: its error includes
both time since the last successful save and the entire powered-off interval.
It can still be too old for newly issued certificates after a long outage.
Neither mechanism replaces NTS or proves that the current time is authentic.
The Pi 5 has an RTC; verify its backup power rather than assuming the hardware
is absent. See the [manufacturer's RTC documentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#real-time-clock-rtc).

For a distribution providing `fake-hwclock`, prefer its maintained boot,
shutdown, and periodic units over a custom clock-setting daemon.
Ubuntu 24.04's package separates `fake-hwclock-load.service`,
`fake-hwclock-save.service`, and `fake-hwclock-save.timer`.
The load operation is forward-only unless explicitly forced; the timer saves
hourly and the shutdown unit saves at shutdown.
See the [distribution manual](https://manpages.ubuntu.com/manpages/noble/man8/fake-hwclock.8.html).
Do not assume another distribution ships the same unit layout.

### Preconditions and exact prestate

Apply only in the owner-authorized host transaction, after continuous power
evidence is acceptable and a current cluster-health baseline is recorded.
The source PR publishes this procedure; it does not prove live installation.
Use the [upgrade transaction](upgrades.md) for package acquisition, exact
version/origin/dependency review, maintainer hooks, and rollback feasibility.

Before installation or enabling any unit:

1. Check whether an earlier time-security decision deliberately disabled the
   package. Resolve that decision explicitly; do not automatically unmask it.
2. Capture package/version state and the enabled, active, masked, fragment, and
   drop-in state of exactly the three named units. Preserve any existing
   `/etc/default/fake-hwclock`, `/etc/fake-hwclock.data`, and applicable
   unit overrides with ownership, modes, hashes, and exact rollback copies
   outside Git in root-only custody. Do not sweep unrelated configuration.
3. Inspect the reviewed package's maintainer scripts and effective units
   before installing: package hooks may start the load unit immediately.
   Require forward-only load, no `force` argument, no `FORCE` expansion to
   force, and no `FILE` override redirecting the saved timestamp. Inspect
   both the unit environment and its environment files privately. Unknown
   overrides require a new exact plan, not automatic removal.
4. Require the effective load unit to complete before NTPsec starts. In the
   stated distribution layout it is ordered before `sysinit.target`;
   verify the actual NTPsec dependency graph and every drop-in rather than
   assuming a file name establishes ordering.
5. Require every existing managed path to have safe root custody, with no
   symlink traversal or untrusted writer. Parse an existing timestamp as UTC
   and compare it with the trusted reference. A corrupt or future timestamp
   is a stop condition before any package hook or load action can run.
6. Prove exactly one network-time daemon owns the clock and that it currently
   selects an authenticated source with the reviewed quorum and acceptable
   offset. A lone `NTPSynchronized=yes` flag is insufficient.
   Capture NTP peer authentication, reachability and selection separately.

### Apply the reviewed package and units

Revalidate the exact package transaction immediately before installation.
Set the variable below from that reviewed manifest; it is deliberately not a
moving `latest` selector. The approved dependency closure must still match
the package-manager simulation. Stop on any changed candidate or added package.

```sh
: "${reviewed_fake_hwclock_version:?set the exact reviewed package version}"
sudo apt-get --no-remove --no-install-recommends install \
  "fake-hwclock=${reviewed_fake_hwclock_version}"
```

Reinspect the installed effective units, package version and hashes, file
custody, absence of force/path overrides, and boot ordering before proceeding.
Run systemd's unit verification for the actual installed fragments and inspect
errors; do not start a load unit to test it on a running cluster.

While NTS is selected and the trusted-reference comparison remains acceptable,
seed the timestamp and enable only the reviewed package units:

```sh
sudo env -u FILE /usr/sbin/fake-hwclock save
sudo systemctl enable fake-hwclock-load.service fake-hwclock-save.service
sudo systemctl enable --now fake-hwclock-save.timer
```

Independently parse and verify the saved UTC timestamp; the utility's exit
status alone is not sufficient evidence. Check file ownership/mode and that
the load and shutdown units are enabled, the timer is active, and a next
trigger is scheduled. Observe a later successful timed save and verify the
timestamp advances. Keep the original package schedule unless a separately
reviewed change justifies a different write frequency.

These units save local system time; they do not authenticate the saved value.
A forward-only load also cannot repair an RTC or saved file that is ahead.
A future-clock incident needs a separately diagnosed correction, not a
permanent forced-backward boot setting.

### Rollback and acceptance

On failure, stop further mutation and preserve the transaction evidence.
Restore only the exact task-owned changes and prior enabled/masked/active
states. Stop a newly enabled save timer before restoring a previous data file.
Do not use `systemctl revert` to erase unrelated drop-ins, purge a package
that existed beforehand, or restart the load unit as a rollback step.
Restoring files cannot undo a clock step; never backdate a running control
plane merely to reproduce its prestate.

A controlled reboot requires current healthy services, stable power, tested
physical/LAN recovery, retained access, exact boot rollback, an owner-approved
window, and coordination with application operators. Verify afterward:

- clock within the agreed trusted-reference bound within two minutes;
- effective load completed before NTPsec, authenticated time selected,
  each configured provider's authentication and reachability reported;
- node and control-plane pods ready, no future timestamps or persistent
  container-creation errors, DNS and active Flux objects ready;
- public routes healthy and protected application readiness reported by its
  responsible operator; unexpected suspension is not counted as convergence;
- zero unexplained failed system units, the save timer active, and a fresh
  successful save.

A warm reboot is not proof of RTC battery retention or abrupt-power-loss
recovery. Perform a cold-boot test only in its own approved recovery window.
Never unplug a live control plane to manufacture acceptance evidence.

## Bound recovery automation

Use systemd restart/backoff for a failed daemon and kubelet's normal
reconciliation first. Wait for corrected time to propagate before one bounded,
authorized kubelet restart. If name-reservation errors persist, independently
bind each candidate to its namespace, pod identity, container identity,
attempt, age, runtime state and current process; prove the exact holder is
not referenced by current Kubernetes container status.

Any deletion procedure needs a closed namespace allowlist, protected-workload
exclusions, a single executor, a finite frozen candidate set, repeated
validation immediately before mutation, and a root-only recovery journal.
Pause the competing reconciler only for the bounded transaction and restore
its previous state even after failure. A changed or ambiguous holder stops
that candidate. Do not replace this with periodic `crictl rm`, broad pod
deletion, or a container-runtime restart loop. Automated read-only detection
can alert while ambiguous repair remains an operator action.

## Power, firmware and software currency

Use the manufacturer's [power requirements](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply)
and [boot power metadata](https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/configuration/reference.adoc)
to distinguish an advertised supply-current profile from voltage actually
delivered at the board. A profile alone does not identify a faulty supply,
cable, connector or outlet. Do not force a higher current declaration or
suppress voltage warnings as a repair.

Fresh recurring undervoltage holds package installation, firmware writes and
reboot testing. Software cannot repair an inadequate physical power path.
A battery-backed clock improves time retention; it does not power the host
through an outage. A UPS is a separate hardware decision.

Review the stable/default bootloader release channel against the
[upstream release notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md).
A package-local `rpi-eeprom-update` report can be current only relative to its
installed image catalogue. Newer firmware can provide bounded fatal-error
recovery, but a specific release-note fix must match the observed failure.
Bootloader watchdogs and OS watchdogs cover different stages; enable neither
without tested timing, recovery and failure-loop limits.

The daily software-currency workflow detects supported upstream drift and
Dependabot proposes governed changes. Neither installs host components.
Track distro packages, boot firmware, runtime/node binaries, and controller
bundles separately; use the upgrade runbook's compatible versions and exact
transactions. Runtime, control-plane, kernel and storage changes require the
separate encrypted off-device recovery and restore proof described in
[disaster recovery](disaster-recovery.md).
