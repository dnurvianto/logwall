# Contributing

Thank you for looking. Before you spend time on a change, please read this — it is short, and
it explains what this project will and will not accept, so that neither of us wastes effort.

## The scope is fixed, and it is written down

logwall is an HTTP abuse blocker that runs as a **layer** on top of an existing firewall. It is
not a firewall, and it is not trying to become one.

Three documents define the boundary. They are authoritative, and a change that crosses one of
them will be declined regardless of how well it is written:

- [`README.md`](README.md) → **Scope**, **Not supported**, **What this is NOT**
- [`docs/DESIGN.md`](docs/DESIGN.md) → **§2 Scope Boundary**, and the T1/T2/T3 support tiers

If you believe the boundary itself is wrong, open an issue arguing that first. Do not open a
pull request that assumes the argument is already won.

## Evidence, not assumption

This is the one rule that matters most here, and it is not a formality.

Almost every defect in this project's history passed a clean run on a developer workstation and
failed on a real host: seven fixture leaks, a persistence path nothing read, a watchdog whose
stated justification did not survive measurement, an entire code branch that could never
execute. The pattern is always the same — something looked right and was never measured.

So: **a change in behaviour must come with evidence from a real host.**

Include, in the pull request body:

- the command you ran,
- its output **before** the change,
- its output **after**,
- the distribution, the firewall backend, and whether a panel is present.

"It should work" and "this is cleaner" are not evidence. A patch with a measurement is more
welcome than a larger patch without one.

Changes that touch no behaviour — typos, documentation wording, comments — do not need this.

## Before you open a pull request

```bash
bash    tests/lineending_test.sh   # CRLF breaks every script on Linux
python3 tests/smoke_test.py        # parsers, window, subnets, profiling, guards, escalation
bash    tests/gate_test.sh         # the gate refuses what it must
```

All three must pass. CI runs them too, but running them locally is faster than a round trip.

If you change behaviour that a test covers, update the test in the same pull request. If you
change behaviour no test covers, adding one is the most valuable thing you can contribute.

**Do not "fix" a failing test by loosening its assertion** unless the assertion itself is wrong —
and if it is, say so explicitly and explain why. One assertion in this repository was pinning a
claim that measurement later disproved; correcting it was right, but only because the underlying
claim was shown to be false first.

## Style

Match the surrounding code rather than any external guide.

- **Bash**: `logwall` and `uninstall.sh` run under `set -euo pipefail`. Two consequences bite
  regularly: a `$(...)` containing `grep`, `diff` or `cmp` must end in `|| true`, because those
  commands report "nothing matched" through their exit status; and `cond && cmd` is safe
  mid-function but fatal as a function's **last** command, where it becomes the return value.
- **Python**: standard library only. No `pip`, no vendored dependencies. The floor is 3.6,
  because AlmaLinux 8 ships 3.6 and dropping it would drop every RHEL 8 host.
- **Comments explain why, not what.** A comment that restates the code is noise; a comment
  recording what was measured, or which assumption turned out to be wrong, is the reason
  anyone can safely change this code later.
- **English**, in code, comments and documentation.
- LF line endings, always.

## Safety rules that are not negotiable

This tool runs as root, from cron, and its failure mode is locking an administrator out of
their own server. These are not preferences:

- Never a global `iptables -F`. logwall touches only its own `LOGWALL_*` chains.
- Never modify or delete a rule belonging to another tool. Report the conflict instead.
- Never remove a safety net (deadman switch, circuit breaker, CDN hard guard, whitelist
  priority) to make a feature simpler.
- Never send data to an external service. Everything stays on the host.
- No `shell=True`, ever. Log content is entirely attacker-controlled.

## Reporting a bug

Include the output of `logwall version` and `logwall doctor`. Between them they identify the
distribution, init system, backend, panel, IPv6 status and support tier — which is the first
thing anyone needs in order to reproduce anything.

If it involves blocking behaviour, include the relevant log lines with the addresses redacted.

## Licence

MIT. By contributing you agree your contribution is released under it.

If the direction of this project does not suit you, forking is a legitimate and expected
outcome — the licence exists precisely so that a disagreement does not have to become an
argument.
