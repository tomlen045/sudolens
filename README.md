# sudolens — sudo privilege-path X-ray

**One file. Zero dependencies. Read-only.** `sudolens` parses your sudoers (plus every file in
`sudoers.d`) and answers the question nobody can answer after a teammate leaves:
*who can become root on this box, through which command, and how bad is it?*

It never modifies a sudoers file. It only reads, parses, expands aliases, and tiers every
privilege path by risk — so you can finally see the whole escalation surface, not guess at it.

```
     ┌──────────────┐        ┌──────────────────────────────┐
     │ /etc/sudoers │──read──▶  user/group → host → command │──▶ CRIT x3 WARN x3 INFO x13
     │ sudoers.d/*  │        │  (aliases expanded)          │         ↑ tiered, explained
     └──────────────┘        └──────────────────────────────┘
```

## Why

Three moments when you need this tool:

1. **You inherit a server.** The sudoers file is sacred and scary — you don't dare touch it,
   and nobody remembers why `deploy2` has a line in `sudoers.d`. Is that line still needed?
2. **An audit asks "list every privilege-escalation path".** Today your answer is a shrug and
   `grep NOPASSWD /etc/sudoers` — which misses aliases, host scoping, and the whole `.d` dir.
3. **NOPASSWD crept in.** `NOPASSWD: /usr/bin/vim /etc/motd` looks harmless. It is a full
   root escape hatch (`:!sh`). Nobody reviews semantics, everyone reviews syntax.

sudolens reads the file the way sudo does (line continuations, `#includedir`, comment rules,
alias expansion) and tells you which paths are *actually* dangerous — not just which lines
contain a keyword.

## Quick start

```bash
# No install. One file, Python 3.8+ stdlib only.
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen/sudolens@main/sudolens.py -o sudolens.py

# 30-second demo on built-in synthetic data (24 rules, only 3 are dangerous)
python3 sudolens.py --demo

# Your machine (default: redacted summary — counts only, no rule content printed)
sudo python3 sudolens.py scan

# Human explanation for one user
sudo python3 sudolens.py explain alice

# Machine-readable baseline for cron
sudo python3 sudolens.py scan --json --full > sudoers-baseline.json
python3 sudolens.py diff sudoers-baseline.json        # exit 0 = unchanged, 1 = changed, 2 = error
```

## Example output (`--demo`, synthetic data)

```
$ python3 sudolens.py --demo
sudolens v1.0.0 — sudo 提权路径透视镜（--demo 合成数据）
解析 1 个文件（demo）· 24 条规则 · 19 条提权路径
------------------------------------------------------------------------
CRIT x3   WARN x3   INFO x13   （按风险排序）
[CRIT] demo @ ALL → (root) NOPASSWD: 任意命令 [SL-01] (demo:25)
[CRIT] backup_svc @ ALL → (root) NOPASSWD: /usr/bin/vi /etc/motd [SL-02] (demo:26)
[CRIT] jenkins_demo @ ALL → (ALL) NOPASSWD: /usr/bin/su - demo [SL-02] (demo:27)
[WARN] audit1 @ ALL → (root) NOPASSWD+NOEXEC: /usr/bin/tee /etc/*.conf [SL-04] (demo:28)
[WARN] operator2 @ ALL → (root) NOPASSWD+NOEXEC: /usr/bin/tee /etc/*.conf [SL-04] (demo:28)
[WARN] audit1 @ ALL → (root) 需密码: /usr/bin/app_runner [SL-05] (demo:29)
[INFO] operator2 @ ALL → (root) 需密码: /usr/bin/less /var/log/auth.log ... [SL-09] (demo:16)
…另有 9 条无信号常规授权（--json / explain 可看全量）
------------------------------------------------------------------------
信号统计: SL-01×1  SL-02×2  SL-04×2  SL-05×1  SL-06×1  SL-07×1  SL-08×1  SL-09×1
结论: 3 条 critical —— 这些账号等于（免密）持有整台机器
```

`explain` speaks human:

```
$ python3 sudolens.py explain demo --demo
sudolens v1.0.0 — 用户 demo 的提权路径（--demo 合成数据）
共 4 条路径，1 条命中风险信号
------------------------------------------------------------------------
[CRIT] demo @ ALL → 任意命令 (demo:25)
  demo 在任意主机上可以免密码运行 任意命令（runas root）。 为什么危险：sudo -i 一条命令就是完整
  root，且没有任何密码验证留痕，出事后无法审计是谁干的。
...
小结: demo 最高风险等级 CRITICAL（免密 root 级）—— 建议收窄命令、加参数限制或改回需密码。
```

## Risk tiers (9 signals)

| ID | Severity | Trigger | Why it matters |
|----|----------|---------|----------------|
| SL-01 | **critical** | NOPASSWD + `ALL` or wildcard (`/usr/bin/*`) | Passwordless full root, no audit trail |
| SL-02 | **critical** | NOPASSWD + escape-capable command (su, vim, find, less, awk, python*, docker, tee…) | The command itself escapes to a shell → root |
| SL-03 | warn | NOPASSWD with narrowed command | No verification, no accountability for side effects |
| SL-04 | warn | NOPASSWD + wildcard/escape but `NOEXEC` set | Mitigation, not a cure — file saves & redirects still write |
| SL-05 | warn | `SETENV` tag | LD_PRELOAD / PATH injection turns safe commands into backdoors |
| SL-06 | info | Negation (`ALL, !SU`) | sudoers negation cannot truly revoke — never treat it as a defense |
| SL-07 | info | Full root path (password required) | Risk = password hygiene |
| SL-08 | info | Wildcard widens argument surface (password required) | Impact grows if the password leaks |
| SL-09 | info | Escape-capable command (password required) | Password in a log/history = root |

Escape command list (SL-02/SL-09): `su sudo passwd chsh bash sh dash zsh ksh csh tcsh ash fish
busybox env find less more most vi vim view ex awk gawk mawk sed xargs tee perl ruby php lua
node python* docker podman chroot nsenter unshare mount tmux screen gdb strace ltrace nc netcat
ncat socat`.

## Redaction policy (the tool protects you from yourself)

sudoers content is sensitive. So by default, `scan` against the **real** file prints only
summary counts and tier statistics — zero rule content. Full details require `--full`
explicitly, or `--json --full` for machines. `--demo` always shows everything because it is
synthetic. Never paste real scan output into tickets or articles.

## Exit codes

| command | 0 | 1 | 2 |
|---------|---|---|---|
| `scan` | clean | findings exist | parse/read error |
| `diff` | no change | paths added/removed | parse error |
| `selftest` | all green | invariants failed | — |

Cron recipe:

```
0 6 * * 1  sudo python3 /usr/local/bin/sudolens.py scan --json --full > /tmp/base.now \
        && python3 /usr/local/bin/sudolens.py diff /var/lib/sudolens/baseline.json \
        || mail -s 'sudoers drift' ops@example.internal
```

## Self-test

18 invariants, all green, no root needed — every fixture lives in a temp dir:

```bash
$ python3 sudolens.py selftest
sudolens selftest — 18 条不变量
  ok   INV01 NOPASSWD+ALL→critical
  ok   INV02 NOPASSWD+wildcard→critical
  ...
PASS 18 / FAIL 0
ALL GREEN
```

Invariants include: NOPASSWD+ALL must be critical; commented-out rules produce zero paths;
`#includedir` pulls in every file (skipping dotted names like sudo does); line continuations
merge; alias expansion still hits dangerous commands; idempotent output; demo hand-counts match.

## Known limitations (honesty section)

- **Static parse ≠ runtime audit.** sudolens sees what the file *grants*, not what happens at runtime.
- `Defaults` directives are counted but not expanded (e.g. a default runas is approximated as root).
- Wildcard semantics follow the sudoers manual approximately; exotic netgroup syntax is not fully modeled.
- Nested alias expansion is supported; circular aliases are treated as non-expanding.
- Parse errors are reported as warnings with line numbers — sudoers is syntax-checked by `visudo`;
  sudolens is a read-only lens, not a linter-enforcer.

## License

MIT
