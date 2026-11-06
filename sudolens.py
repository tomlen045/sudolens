#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sudolens — sudo 提权路径透视镜：只读解析 sudoers，枚举「用户/组 → 主机 → 命令」提权路径并分级。
零依赖，Python 3.8+ 标准库。绝不修改任何 sudoers 文件（只读铁律）。

用法:
  sudolens.py scan [--path /etc/sudoers] [--json] [--full] [--demo]
  sudolens.py explain <user> [--json] [--demo]
  sudolens.py diff BASELINE.json [--path /etc/sudoers] [--demo] [--json]
  sudolens.py selftest
  sudolens.py --demo            # 等价于 scan --demo，内置合成数据完整演示

风险信号（9 类）:
  SL-01 critical  NOPASSWD + 任意命令/通配符（ALL、/usr/bin/* 等）→ 等于免密 root
  SL-02 critical  NOPASSWD + 可逃逸命令（su/sudo/bash/sh/vi/vim/env/find/less/more/
                  awk/sed/python*/xargs/tee/passwd/chsh/perl/ruby/node 等）→ 借道逃逸成 root
  SL-03 warn      NOPASSWD 免密授权（命令已收窄）→ 无验证留痕，副作用无法追责
  SL-04 warn      NOPASSWD + 通配/逃逸，但带 NOEXEC → 缓解因子降级（不是解药，如实说明）
  SL-05 warn      SETENV 标签 → 可改环境变量（LD_PRELOAD 类注入可武器化普通命令）
  SL-06 info      规则含取反 (!) → sudoers 取反语义陷阱提示（! 不能真正收回权限）
  SL-07 info      完整 root 提权路径（需密码）→ 风险取决于密码强度与泄露面
  SL-08 info      通配符放宽参数面（需密码）→ 密码泄露后影响面被放大
  SL-09 info      可逃逸命令（需密码）→ 密码一旦进日志/历史即等同 root

退出码纪律:
  scan:  0=无 critical/warn  1=有发现  2=解析/读取错误
  diff:  0=无变化  1=有变化  2=解析错误
  selftest: 0=全绿  1=有失败

脱敏纪律（本工具自身的默认行为）:
  对真实 /etc/sudoers 默认只输出汇总计数与分级统计，不展示任何规则内容；
  --demo 用内置合成数据演示全量输出；--full 显式要求才输出明细。

已知局限（如实披露）:
  静态解析 ≠ 运行时审计。Defaults 指令不展开（如 runas 默认值按 root 估算）；
  嵌套别名展开支持但循环引用按不展开处理；通配符语义按 sudoers 手册近似。

不变量（selftest 内置断言，共 18 条）:
  INV01 NOPASSWD+ALL 必判 critical (SL-01)
  INV02 NOPASSWD+通配路径 (/usr/bin/*) 必判 critical (SL-01)
  INV03 NOPASSWD+su 必判 critical (SL-02)
  INV04 NOPASSWD+vim（即使限定参数）必判 critical (SL-02)
  INV05 NOPASSWD+收窄命令 只判 warn (SL-03)，不得误判 critical
  INV06 NOPASSWD+ALL+NOEXEC 降级为 warn (SL-04)，不得静默放过
  INV07 纯注释行不产生任何路径（注释里写 NOPASSWD: ALL 也不行）
  INV08 #includedir 目录内文件全部纳入解析
  INV09 行尾反斜杠续接合并为单条规则
  INV10 Cmnd_Alias 引用展开后危险命令照样命中
  INV11 %组 规则以 %组名 枚举路径
  INV12 SETENV 标签判 warn (SL-05)
  INV13 取反规则触发 SL-06 提示
  INV14 退出码: 干净=0 / 有发现=1 / 文件缺失=2
  INV15 --demo 手工预期逐条对应: 24 规则/19 路径/3 critical/3 warn
  INV16 幂等: 同一输入连续两次解析输出逐字节一致
  INV17 explain: 只讲该用户的路径，每条命中都带「为什么危险」
  INV18 Host_Alias 展开到具体主机成员
"""

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

__version__ = "1.0.0"

SEV_RANK = {"critical": 0, "warn": 1, "info": 2}
SEV_TAG = {"critical": "CRIT", "warn": "WARN", "info": "INFO"}

# 9 类风险信号: id -> (severity, 一句话)
FINDINGS = {
    "SL-01": ("critical", "NOPASSWD + 任意命令/通配符"),
    "SL-02": ("critical", "NOPASSWD + 可逃逸命令"),
    "SL-03": ("warn", "NOPASSWD 免密授权（命令收窄）"),
    "SL-04": ("warn", "NOPASSWD + 通配/逃逸，NOEXEC 缓解"),
    "SL-05": ("warn", "SETENV 允许改环境变量"),
    "SL-06": ("info", "取反规则 (!) 语义陷阱提示"),
    "SL-07": ("info", "完整 root 提权路径（需密码）"),
    "SL-08": ("info", "通配符放宽参数面（需密码）"),
    "SL-09": ("info", "可逃逸命令（需密码）"),
}

# shell 逃逸类命令清单（basename 精确匹配）+ 前缀规则（python* 家族）
ESCAPE_EXACT = {
    "su", "sudo", "passwd", "chsh",
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "fish", "busybox",
    "env", "find", "less", "more", "most", "vi", "vim", "view", "ex",
    "awk", "gawk", "mawk", "sed", "xargs", "tee",
    "perl", "ruby", "php", "lua", "node",
    "docker", "podman", "chroot", "nsenter", "unshare", "mount",
    "tmux", "screen", "gdb", "strace", "ltrace",
    "nc", "netcat", "ncat", "socat",
}
ESCAPE_PREFIX = ("python",)

TAG_NAMES = {
    "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV",
    "MAIL", "NOMAIL", "FOLLOW", "NOFOLLOW",
    "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT",
    "INTERCEPT", "NOINTERCEPT",
}

MAX_PATHS = 400
DEFAULT_SUDOERS = "/etc/sudoers"


# ---------------------------------------------------------------- parsing

def logical_lines(text):
    """按行尾反斜杠续接合并；返回 [(起始行号, 合并后的行)]。"""
    out = []
    buf = None
    start = None
    for idx, raw in enumerate(text.split("\n"), 1):
        s = raw.rstrip("\r")
        trailing = 0
        t = s
        while t.endswith("\\"):
            trailing += 1
            t = t[:-1]
        if trailing % 2 == 1:
            if buf is None:
                buf, start = s[:-1] + " ", idx
            else:
                buf += s[:-1] + " "
            continue
        if buf is not None:
            out.append((start, buf + s))
            buf, start = None, None
        else:
            out.append((idx, s))
    if buf is not None:
        out.append((start, buf))
    return out


def strip_comment(line):
    """返回 (去掉注释后的代码, include 指令或 None)。
    sudoers 语义: # 在行首或空白后开始注释，除非是 #include / #includedir 指令。"""
    i = 0
    while True:
        j = line.find("#", i)
        if j == -1:
            return line, None
        if j == 0 or line[j - 1] in " \t":
            rest = line[j + 1:]
            m = re.match(r"(includedir|include)(\s+|$)", rest)
            if m:
                return line[:j].strip(), rest.strip()
            return line[:j].rstrip(), None
        i = j + 1


def split_top(s, sep=","):
    """按分隔符切分，忽略括号内与引号内的分隔符。"""
    parts = []
    depth = 0
    quote = None
    cur = []
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            cur.append(ch)
            continue
        if ch == "(":
            depth += 1
            cur.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
            continue
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def new_ctx():
    return {
        "aliases": {"user": {}, "runas": {}, "host": {}, "cmnd": {}},
        "paths": [],
        "rules": 0,
        "defaults": 0,
        "unparsed": 0,
        "files": [],
        "missing_dirs": 0,
        "notes": [],
        "truncated": False,
    }


def parse_text(text, source, ctx):
    """解析一段 sudoers 文本（含别名、Defaults、用户规格、include 指令）。"""
    for ln, ll in logical_lines(text):
        code, directive = strip_comment(ll)
        if directive is not None:
            handle_directive(directive, source, ctx)
            continue
        s = code.strip()
        if not s:
            continue
        ctx["rules"] += 1
        m = re.match(r"^(User|Runas|Host|Cmnd)_Alias\s+([A-Z][A-Z0-9_]*)\s*=\s*(.+)$", s)
        if m:
            kind = {"User": "user", "Runas": "runas", "Host": "host", "Cmnd": "cmnd"}[m.group(1)]
            ctx["aliases"][kind][m.group(2)] = split_top(m.group(3))
            continue
        if s.startswith("Defaults"):
            ctx["defaults"] += 1
            continue
        if parse_userspec(s, source, ln, ctx):
            continue
        ctx["unparsed"] += 1
        if ctx["unparsed"] <= 3:
            ctx["notes"].append("第 %d 行未能解析（sudoers 里 visudo 也会拒绝）: %s" % (ln, s[:40]))


def handle_directive(directive, source, ctx):
    parts = directive.split(None, 1)
    if len(parts) != 2:
        return
    op, target = parts[0], parts[1].strip()
    if op == "includedir":
        d = os.path.expanduser(target)
        if not os.path.isdir(d):
            ctx["missing_dirs"] += 1
            ctx["notes"].append("#includedir %s 指向的目录不存在（本机没有该目录或有拼写错误）" % target)
            return
        for fn in sorted(os.listdir(d)):
            # sudo 语义: 跳过含 . 的文件、以 ~ 结尾的文件和隐藏文件
            if fn.startswith(".") or "." in fn or fn.endswith("~"):
                continue
            fp = os.path.join(d, fn)
            if not os.path.isfile(fp):
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    sub = fh.read()
            except OSError as e:
                ctx["notes"].append("sudoers.d/%s 读取失败: %s" % (fn, e))
                continue
            ctx["files"].append("sudoers.d/" + fn)
            parse_text(sub, "sudoers.d/" + fn, ctx)
    elif op == "include":
        fp = os.path.expanduser(target)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                sub = fh.read()
        except OSError as e:
            ctx["notes"].append("include %s 失败: %s" % (target, e))
            return
        ctx["files"].append(os.path.basename(fp))
        parse_text(sub, os.path.basename(fp), ctx)


def parse_command(item):
    """命令项 → {path, args, escape, wildcard, bare}"""
    parts = item.split(None, 1)
    path = parts[0]
    args = parts[1].strip() if len(parts) > 1 else ""
    base = path.rstrip("/").rsplit("/", 1)[-1].lower()
    escape = base in ESCAPE_EXACT or any(base.startswith(p) for p in ESCAPE_PREFIX)
    wildcard = path == "ALL" or "*" in path or "*" in args
    bare = args == ""
    return {"path": path, "args": args, "escape": escape, "wildcard": wildcard, "bare": bare}


def parse_cmndspec(spec):
    """单条 cmndspec → (runas_raw, [tags], cmd_text, negated)；失败返回 None。"""
    spec = spec.strip()
    if not spec:
        return None
    runas = None
    m = re.match(r"^\(([^)]*)\)\s*", spec)
    if m:
        runas = m.group(1).strip()
        spec = spec[m.end():].strip()
    tags = []
    while True:
        m = re.match(r"^([A-Z][A-Z_]*)\s*:\s*", spec)
        if m and m.group(1) in TAG_NAMES:
            tags.append(m.group(1))
            spec = spec[m.end():]
        else:
            break
    neg = False
    if spec.startswith("!"):
        neg = True
        spec = spec[1:].strip()
    if not spec:
        return None
    return runas, tags, spec, neg


def expand_cmnd(text, neg, ctx, seen=None):
    """展开 Cmnd_Alias 引用 → [{path,args,...,neg}]；循环引用按不展开处理。"""
    if seen is None:
        seen = set()
    if text in ctx["aliases"]["cmnd"]:
        if text in seen:
            return []
        seen = seen | {text}
        out = []
        for item in ctx["aliases"]["cmnd"][text]:
            i_neg = item.startswith("!")
            t = item[1:].strip() if i_neg else item
            out.extend(expand_cmnd(t, neg or i_neg, ctx, seen))
        return out
    c = parse_command(text)
    c["neg"] = neg
    return [c]


def expand_user(item, ctx, seen=None):
    """展开用户项 → [(名字, 经过的别名或 None)]。%组/+netgroup 原样保留。"""
    if seen is None:
        seen = set()
    item = item.strip()
    if item.startswith(("%", "+")) or item == "ALL":
        return [(item, None)]
    if item in ctx["aliases"]["user"]:
        if item in seen:
            return []
        seen = seen | {item}
        out = []
        for m2 in ctx["aliases"]["user"][item]:
            for u, _ in expand_user(m2, ctx, seen):
                out.append((u, item))
        return out
    return [(item, None)]


def expand_host(item, ctx, seen=None):
    if seen is None:
        seen = set()
    item = item.strip()
    if item in ctx["aliases"]["host"]:
        if item in seen:
            return []
        seen = seen | {item}
        out = []
        for m2 in ctx["aliases"]["host"][item]:
            out.extend(expand_host(m2, ctx, seen))
        return out
    return [item]


def runas_root_or_all(runas_raw):
    """未写 runas 时 sudoers 默认以 root 运行；写了则看用户段是否含 root/ALL。"""
    if not runas_raw:
        return True
    users_part = runas_raw.split(":")[0]
    items = [x.strip() for x in users_part.split(",") if x.strip()]
    return any(x in ("root", "ALL") for x in items)


def parse_userspec(s, source, ln, ctx):
    """用户规格: userlist hostlist = cmndspeclist → 展开成路径。"""
    eq = s.find("=")
    if eq <= 0:
        return False
    lhs, rhs = s[:eq].strip(), s[eq + 1:].strip()
    lhs_norm = re.sub(r",\s*", " , ", lhs)
    toks = [t for t in lhs_norm.split() if t != ","]
    if len(toks) < 2:
        return False
    host_tok, user_toks = toks[-1], toks[:-1]
    specs = split_top(rhs)
    hosts = expand_host(host_tok, ctx)
    for u_tok in user_toks:
        for u, via in expand_user(u_tok, ctx):
            for h in hosts:
                for spec in specs:
                    parsed = parse_cmndspec(spec)
                    if parsed is None:
                        continue
                    runas_raw, tags, cmd_text, neg = parsed
                    cmds = expand_cmnd(cmd_text, neg, ctx)
                    if not cmds:
                        continue
                    p = {
                        "user": u,
                        "via": via,
                        "host": h,
                        "runas": runas_raw or "root",
                        "tags": tags,
                        "commands": cmds,
                        "source": source,
                        "line": ln,
                        "findings": [],
                        "risk": "info",
                    }
                    analyze_path(p)
                    ctx["paths"].append(p)
                    if len(ctx["paths"]) >= MAX_PATHS:
                        ctx["truncated"] = True
                        return True
    return True


# ---------------------------------------------------------------- analysis

def mk_finding(fid, detail=""):
    sev, msg = FINDINGS[fid]
    f = {"id": fid, "severity": sev, "message": msg}
    if detail:
        f["detail"] = detail
    return f


def analyze_path(p):
    """给一条提权路径打风险信号（9 类）。"""
    tags = p["tags"]
    nop = "NOPASSWD" in tags
    noexec = "NOEXEC" in tags
    setenv = "SETENV" in tags
    active = [c for c in p["commands"] if not c.get("neg")]
    esc = any(c["escape"] for c in active)
    wild = any(c["wildcard"] for c in active)
    has_all = any(c["path"] == "ALL" for c in active)
    full_root = has_all and runas_root_or_all(p["runas"])

    if any(c.get("neg") for c in p["commands"]):
        p["findings"].append(mk_finding(
            "SL-06", "取反 (!) 在 sudoers 里不能真正收回权限（ALL, !SU 依然可 su），只当提示看"))
    if nop and (esc or wild):
        if noexec:
            p["findings"].append(mk_finding(
                "SL-04", "NOEXEC 挡住『再执行别的程序』，是缓解不是解药：编辑器保存、重定向写文件仍可行"))
        elif esc:
            names = sorted({c["path"].rsplit("/", 1)[-1] for c in active if c["escape"]})
            p["findings"].append(mk_finding(
                "SL-02", "可逃逸命令: " + ", ".join(names)))
        else:
            p["findings"].append(mk_finding(
                "SL-01", "NOPASSWD + " + ("任意命令" if has_all else "通配符")))
    elif nop:
        detail = "未限制参数" if any(c["bare"] for c in active) else "已限制参数"
        p["findings"].append(mk_finding("SL-03", detail))
    if setenv:
        p["findings"].append(mk_finding(
            "SL-05", "SETENV 允许自定义环境变量（LD_PRELOAD 等可把看似安全的命令变成后门）"))
    if not nop and esc:
        names = sorted({c["path"].rsplit("/", 1)[-1] for c in active if c["escape"]})
        p["findings"].append(mk_finding(
            "SL-09", "可逃逸命令（需密码）: " + ", ".join(names)))
    elif not nop and full_root:
        p["findings"].append(mk_finding(
            "SL-07", "完整 root 提权路径，仅靠密码把关"))
    elif not nop and wild:
        p["findings"].append(mk_finding(
            "SL-08", "通配符放宽了参数面"))

    if p["findings"]:
        p["risk"] = min((f["severity"] for f in p["findings"]), key=lambda s: SEV_RANK[s])


def scan_paths(path=DEFAULT_SUDOERS, demo=False):
    """读文件 → 解析 → 返回 (model, err)。err 非 None 时 model 不可用。"""
    if demo:
        ctx = new_ctx()
        ctx["files"].append("demo")
        parse_text(DEMO_SUDOERS, "demo", ctx)
        return finish_model(ctx), None
    if os.path.isdir(path):
        return None, "%s 是目录，请给文件路径（默认 %s）" % (path, DEFAULT_SUDOERS)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except PermissionError:
        return None, ("%s 无读取权限（sudoers 通常只给 root 读）。"
                      "用 sudo 运行本命令，或 --path 指向一份可读副本；先看演示可用 --demo" % path)
    except OSError as e:
        return None, "读取 %s 失败: %s" % (path, e)
    ctx = new_ctx()
    ctx["files"].append(os.path.basename(path) or path)
    parse_text(text, os.path.basename(path) or path, ctx)
    return finish_model(ctx), None


def finish_model(ctx):
    paths = sorted(ctx["paths"], key=lambda p: (SEV_RANK[p["risk"]], p["source"], p["line"], p["user"]))
    counts = {"critical": 0, "warn": 0, "info": 0}
    for p in paths:
        counts[p["risk"]] += 1
    sig_counts = {}
    for p in paths:
        for f in p["findings"]:
            sig_counts[f["id"]] = sig_counts.get(f["id"], 0) + 1
    return {
        "files": ctx["files"],
        "rules": ctx["rules"],
        "defaults": ctx["defaults"],
        "unparsed": ctx["unparsed"],
        "paths_count": len(ctx["paths"]),
        "paths": paths,
        "truncated": ctx["truncated"],
        "missing_dirs": ctx["missing_dirs"],
        "notes": ctx["notes"],
        "critical": counts["critical"],
        "warn": counts["warn"],
        "info": counts["info"],
        "signal_counts": sig_counts,
        "user_aliases": {k: v for k, v in ctx["aliases"]["user"].items()},
    }


# ---------------------------------------------------------------- rendering

def cmd_display(p, cap=2):
    active = [c for c in p["commands"] if not c.get("neg")]
    if any(c["path"] == "ALL" for c in active):
        return "任意命令"
    outs = []
    for c in active[:cap]:
        s = c["path"] + (" " + c["args"] if c["args"] else "")
        outs.append(s)
    if len(active) > cap:
        outs.append("…共 %d 条命令" % len(active))
    return ", ".join(outs) if outs else "(空)"


def tags_display(p):
    t = list(p["tags"])
    if "NOPASSWD" in t:
        return "NOPASSWD" + ("+NOEXEC" if "NOEXEC" in t else "")
    return "需密码"


def render_human(model, demo=False, full=True):
    out = []
    mode = "（--demo 合成数据）" if demo else ""
    out.append("sudolens v%s — sudo 提权路径透视镜%s" % (__version__, mode))
    files_disp = ", ".join(model["files"]) if model["files"] else "(无)"
    out.append("解析 %d 个文件（%s）· %d 条规则 · %d 条提权路径%s" % (
        len(model["files"]), files_disp, model["rules"], model["paths_count"],
        "（超过 %d 条已截断）" % MAX_PATHS if model["truncated"] else ""))
    if model["unparsed"]:
        out.append("⚠ %d 行未解析" % model["unparsed"])
    out.append("-" * 72)
    out.append("CRIT x%d   WARN x%d   INFO x%d%s" % (
        model["critical"], model["warn"], model["info"],
        "   （本机内容已脱敏，仅输出统计；--full 看明细）" if not full else "   （按风险排序）"))

    if full:
        shown = 0
        for p in model["paths"]:
            if p["risk"] == "info" and not p["findings"]:
                continue
            fids = ",".join(f["id"] for f in p["findings"]) or "—"
            out.append("[%s] %s @ %s → (%s) %s: %s [%s] (%s:%d)" % (
                SEV_TAG[p["risk"]], p["user"], p["host"], p["runas"],
                tags_display(p), cmd_display(p), fids, p["source"], p["line"]))
            shown += 1
        clean = sum(1 for p in model["paths"] if not p["findings"])
        if clean:
            out.append("…另有 %d 条无信号常规授权（--json / explain 可看全量）" % clean)
    out.append("-" * 72)
    if model["signal_counts"]:
        sig = "  ".join("%s×%d" % (k, v) for k, v in sorted(model["signal_counts"].items()))
        out.append("信号统计: " + sig)
    else:
        out.append("信号统计: 无命中")
    if model["critical"]:
        out.append("结论: %d 条 critical —— 这些账号等于（免密）持有整台机器" % model["critical"])
    elif model["warn"]:
        out.append("结论: 无 critical，%d 条 warn 值得看一眼" % model["warn"])
    else:
        out.append("结论: 未发现 critical/warn")
    for n in model["notes"]:
        out.append("note: " + n)
    return "\n".join(out)


EXPLAIN_WHY = {
    "SL-01": "为什么危险：sudo -i 一条命令就是完整 root，且没有任何密码验证留痕，出事后无法审计是谁干的。",
    "SL-02": "为什么危险：这类命令本身能逃逸成 root（比如 vim 里输入 :!sh、find 的 -exec、less 的 !命令），给它免密就等于交出整个 root。",
    "SL-03": "为什么危险：范围虽然收窄，但执行不再有任何验证。命令一旦有副作用（重启服务、改文件），出了事无法追责到人。",
    "SL-04": "为什么只是 warn：NOEXEC 挡住了『命令再拉起别的程序』，是缓解不是解药——编辑器保存、输出重定向仍能改文件，别把它当安全边界。",
    "SL-05": "为什么危险：SETENV 允许改环境变量。LD_PRELOAD、PATH 注入可以把一条看似无害的命令变成后门。",
    "SL-06": "为什么只是提示：sudoers 的取反 (!) 不能真正收回权限——ALL, !SU 的写法依然可以 su。它只是提醒你别把取反当防线。",
    "SL-07": "为什么是 info：完整 root 路径但每次要输密码。风险取决于密码强度、是否进过聊天记录和Shell历史。",
    "SL-08": "为什么是 info：通配符放宽了参数面，密码泄露后影响面随之放大。",
    "SL-09": "为什么是 info：这条命令具备 shell 逃逸能力，密码一旦被记录（日志/历史/键盘记录），等同交出 root。",
}


def path_sentence(p):
    who = p["user"] + ("（经别名 %s）" % p["via"] if p.get("via") else "")
    where = "任意主机" if p["host"] == "ALL" else "主机 " + p["host"]
    pwd = "免密码" if "NOPASSWD" in p["tags"] else "需要密码"
    base = "%s 在%s上可以%s运行 %s（runas %s）。" % (
        who, where, pwd, cmd_display(p, cap=3), p["runas"])
    if not p["findings"]:
        return base + " 说明：命令收窄且需要密码，未命中风险信号，属受控常规授权。"
    parts = [base]
    for f in p["findings"]:
        parts.append(EXPLAIN_WHY.get(f["id"], ""))
    return " ".join(x for x in parts if x)


def render_explain(model, user, demo=False):
    hits = [p for p in model["paths"] if p["user"] == user]
    alias_disp = ""
    if not hits and user.upper() in model.get("user_aliases", {}):
        hits = [p for p in model["paths"] if p.get("via") == user.upper()]
        alias_disp = "（别名成员展开）"
    out = []
    out.append("sudolens v%s — 用户 %s 的提权路径%s%s" % (
        __version__, user, alias_disp, "（--demo 合成数据）" if demo else ""))
    out.append("共 %d 条路径，%d 条命中风险信号" % (len(hits), sum(1 for p in hits if p["findings"])))
    if not hits:
        out.append("该用户没有任何提权路径（不在 sudoers 授权里）。")
        return "\n".join(out)
    out.append("-" * 72)
    for p in hits:
        out.append("[%s] %s @ %s → %s (%s:%d)" % (
            SEV_TAG[p["risk"]], p["user"], p["host"], cmd_display(p, cap=3), p["source"], p["line"]))
        out.append("  " + path_sentence(p))
        out.append("")
    out.append("-" * 72)
    worst = min((p["risk"] for p in hits), key=lambda s: SEV_RANK[s])
    out.append("小结: %s 最高风险等级 %s%s" % (
        user, {"critical": "CRITICAL（免密 root 级）", "warn": "WARN（免密受限）", "info": "INFO（受控）"}[worst],
        "—— 建议收窄命令、加参数限制或改回需密码。" if worst != "info" else "。"))
    return "\n".join(out)


# ---------------------------------------------------------------- diff

def path_sig(p):
    cmds = ";".join("%s %s" % (c["path"], c["args"]) if c["args"] else c["path"] for c in p["commands"])
    return "|".join([
        p["user"], p.get("via") or "-", p["host"], p["runas"],
        ",".join(sorted(p["tags"])), cmds, p["source"],
    ])


def cmd_diff(model, baseline_file):
    try:
        with open(baseline_file, "r", encoding="utf-8") as fh:
            base = json.load(fh)
    except OSError as e:
        return None, "读取基线失败: %s" % e
    except ValueError as e:
        return None, "基线 JSON 解析失败: %s" % e
    base_paths = base.get("paths") if isinstance(base, dict) else base
    if not isinstance(base_paths, list):
        return None, "基线里没有 paths 列表（用 scan --json --full 生成）"
    base_sigs = {path_sig(p): p for p in base_paths}
    now_sigs = {path_sig(p): p for p in model["paths"]}
    added = [now_sigs[s] for s in now_sigs if s not in base_sigs]
    removed = [base_sigs[s] for s in base_sigs if s not in now_sigs]
    return {"added": added, "removed": removed}, None


def render_diff(res):
    out = []
    out.append("sudolens diff — 与基线对比")
    out.append("新增 %d 条提权路径，消失 %d 条" % (len(res["added"]), len(res["removed"])))
    for p in res["added"]:
        out.append("[新增][%s] %s @ %s → %s (%s:%d)" % (
            SEV_TAG[p["risk"]].strip(), p["user"], p["host"], cmd_display(p), p["source"], p["line"]))
    for p in res["removed"]:
        out.append("[消失] %s @ %s → %s (%s)" % (
            p["user"], p["host"], cmd_display(p), p["source"]))
    if not res["added"] and not res["removed"]:
        out.append("无变化。")
    return "\n".join(out)


# ---------------------------------------------------------------- demo data

DEMO_SUDOERS = """\
# sudolens --demo 合成 sudoers：全部为虚构账号，与任何真实主机无关
# 设计偏态：25 条规则里只有 3 条 critical——验证「多数安全、少数危险」不漏报
Defaults env_reset
Defaults mail_badpass
User_Alias DEVTEAM = demo, coder2
User_Alias OPS = operator2, audit1
Cmnd_Alias WEBCTL = /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
Cmnd_Alias PKGTOOLS = /usr/bin/apt update, /usr/bin/apt upgrade
Cmnd_Alias LOGVIEW = /usr/bin/less /var/log/auth.log, /usr/bin/tail -f /var/log/syslog
Cmnd_Alias SHELLS = /bin/su, /bin/bash, /bin/sh

# ---- 常规授权：需密码、命令收窄（应为 INFO/无信号）----
demo       ALL = WEBCTL
coder2     ALL = (root) PKGTOOLS
%deploy    ALL = /usr/bin/rsync -a /var/www/ /backup/www/
operator2  ALL = LOGVIEW
audit1     ALL = /usr/bin/journalctl -u nginx
%opers     ALL = /sbin/reboot, /sbin/shutdown -h now
demo       db1 = /usr/bin/psql demo_db
demo       ALL = /bin/kill
backup_svc ALL = /usr/bin/rsync -a /var/ /backup/var/
coder2     ALL = /usr/bin/systemctl status '*'

# ---- 危险规则（演示检出）----
demo        ALL = NOPASSWD: ALL
backup_svc  ALL = (root) NOPASSWD: /usr/bin/vi /etc/motd
jenkins_demo ALL = (ALL) NOPASSWD: /usr/bin/su - demo
OPS         ALL = (root) NOPASSWD: NOEXEC: /usr/bin/tee /etc/*.conf
audit1      ALL = (root) SETENV: /usr/bin/app_runner
coder2      ALL = ALL, !SHELLS
"""


# ---------------------------------------------------------------- selftest

def run_selftest():
    results = []

    def ok(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    def parse(text, source="t"):
        ctx = new_ctx()
        ctx["files"].append(source)
        parse_text(text, source, ctx)
        return finish_model(ctx)

    def ids(model):
        s = {}
        for p in model["paths"]:
            for f in p["findings"]:
                s[f["id"]] = s.get(f["id"], 0) + 1
        return s

    # INV01 NOPASSWD+ALL → SL-01 critical
    m = parse("demo ALL = NOPASSWD: ALL\n")
    s = ids(m)
    ok("INV01 NOPASSWD+ALL→critical", s.get("SL-01") == 1 and m["critical"] == 1, str(s))

    # INV02 NOPASSWD+通配路径 → SL-01 critical
    m = parse("svc ALL = NOPASSWD: /usr/bin/*\n")
    s = ids(m)
    ok("INV02 NOPASSWD+wildcard→critical", s.get("SL-01") == 1, str(s))

    # INV03 NOPASSWD+su → SL-02 critical
    m = parse("ops ALL = (root) NOPASSWD: /bin/su - dev\n")
    s = ids(m)
    ok("INV03 NOPASSWD+su→critical", s.get("SL-02") == 1, str(s))

    # INV04 NOPASSWD+vim（限定参数也算）→ SL-02 critical
    m = parse("ops ALL = NOPASSWD: /usr/bin/vim /etc/hosts\n")
    s = ids(m)
    ok("INV04 NOPASSWD+vim→critical", s.get("SL-02") == 1, str(s))

    # INV05 NOPASSWD+收窄命令 → 只 warn (SL-03)，不误判 critical
    m = parse("ops ALL = NOPASSWD: /usr/bin/systemctl restart nginx\n")
    s = ids(m)
    ok("INV05 NOPASSWD收窄→warn(SL-03)", s.get("SL-03") == 1 and m["critical"] == 0, str(s))

    # INV06 NOPASSWD+ALL+NOEXEC → 降级 warn (SL-04)，不得静默放过
    m = parse("ops ALL = (root) NOPASSWD: NOEXEC: ALL\n")
    s = ids(m)
    ok("INV06 NOEXEC降级→warn(SL-04)",
       s.get("SL-04") == 1 and s.get("SL-01") is None and m["critical"] == 0 and m["warn"] == 1, str(s))

    # INV07 纯注释行不产生路径
    m = parse("# ops ALL = NOPASSWD: ALL\n# NOPASSWD: ALL anywhere\n\n")
    ok("INV07 注释不产生路径", m["paths_count"] == 0 and m["rules"] == 0,
       "paths=%d rules=%d" % (m["paths_count"], m["rules"]))

    # INV08 #includedir 目录内文件全部纳入
    with tempfile.TemporaryDirectory() as td:
        mainf = os.path.join(td, "sudoers")
        incd = os.path.join(td, "sudoers.d")
        os.makedirs(incd)
        with open(mainf, "w") as fh:
            fh.write("demo ALL = /bin/kill\n#includedir %s\n" % incd)
        with open(os.path.join(incd, "extra"), "w") as fh:
            fh.write("svc ALL = NOPASSWD: /usr/bin/id\n")
        with open(os.path.join(incd, "skip.me"), "w") as fh:
            fh.write("ghost ALL = NOPASSWD: ALL\n")  # 含 . 的文件 sudo 会跳过
        m, err = scan_paths(mainf)
        ok("INV08 includedir 全纳入", err is None and m["paths_count"] == 2
           and any(p["source"] == "sudoers.d/extra" for p in m["paths"])
           and not any(p["user"] == "ghost" for p in m["paths"]),
           "paths=%d files=%s" % (m["paths_count"] if m else -1, m["files"] if m else err))

    # INV09 行续接合并
    m = parse("demo ALL = NOPASSWD: \\\n    /usr/bin/systemctl restart nginx\n")
    ok("INV09 续接合并", m["paths_count"] == 1 and m["unparsed"] == 0
       and m["paths"][0]["tags"] == ["NOPASSWD"],
       "paths=%d" % m["paths_count"])

    # INV10 Cmnd_Alias 展开后危险命令命中
    m = parse("Cmnd_Alias SHELLS = /bin/su, /bin/bash\nops ALL = NOPASSWD: SHELLS\n")
    s = ids(m)
    ok("INV10 别名展开命中", s.get("SL-02") == 1, str(s))

    # INV11 %组 枚举
    m = parse("%ops ALL = /sbin/reboot\n")
    ok("INV11 %组枚举", m["paths_count"] == 1 and m["paths"][0]["user"] == "%ops",
       str([p["user"] for p in m["paths"]]))

    # INV12 SETENV → SL-05
    m = parse("ops ALL = (root) SETENV: /usr/bin/app\n")
    s = ids(m)
    ok("INV12 SETENV→SL-05", s.get("SL-05") == 1, str(s))

    # INV13 取反规则 → SL-06 提示
    m = parse("ops ALL = (ALL) ALL, !/bin/su\n")
    s = ids(m)
    ok("INV13 取反→SL-06", s.get("SL-06") == 1, str(s))

    # INV14 退出码
    m_clean = parse("demo ALL = /bin/kill\n")
    m_dirty = parse("demo ALL = NOPASSWD: ALL\n")
    _, err2 = scan_paths("/nonexistent/sudoers/definitely/missing")
    exit_clean = 1 if (m_clean["critical"] or m_clean["warn"]) else 0
    exit_dirty = 1 if (m_dirty["critical"] or m_dirty["warn"]) else 0
    ok("INV14 退出码 0/1/2", exit_clean == 0 and exit_dirty == 1 and err2 is not None,
       "clean=%d dirty=%d missing=%s" % (exit_clean, exit_dirty, "2" if err2 else "?"))

    # INV15 --demo 手工预期逐条对应
    m = finish_model(_demo_ctx())
    s = ids(m)
    ok("INV15 demo手工预期",
       m["rules"] == 24 and m["paths_count"] == 19
       and s.get("SL-01") == 1 and s.get("SL-02") == 2 and m["critical"] == 3
       and s.get("SL-04") == 2 and s.get("SL-05") == 1 and m["warn"] == 3,
       "rules=%d paths=%d %s crit=%d warn=%d" % (
           m["rules"], m["paths_count"], s, m["critical"], m["warn"]))

    # INV16 幂等
    a = json.dumps(_demo_ctx_model(), sort_keys=True, ensure_ascii=False)
    b = json.dumps(_demo_ctx_model(), sort_keys=True, ensure_ascii=False)
    ok("INV16 幂等一致", a == b, "len=%d" % len(a))

    # INV17 explain 只讲该用户且带「为什么」
    m = finish_model(_demo_ctx())
    txt = render_explain(m, "demo", demo=True)
    demo_paths = [p for p in m["paths"] if p["user"] == "demo"]
    ok("INV17 explain 边界",
       len(demo_paths) == 4 and "为什么危险" in txt and "operator2" not in txt.replace("OPS", "")
       and "jenkins_demo" not in txt,
       "demo路径=%d" % len(demo_paths))

    # INV18 Host_Alias 展开到成员
    m = parse("Host_Alias WEB = nginx1, nginx2\ndemo WEB = /bin/kill\n")
    hosts = sorted(p["host"] for p in m["paths"])
    ok("INV18 Host_Alias 展开", hosts == ["nginx1", "nginx2"], str(hosts))

    print("sudolens selftest — %d 条不变量" % len(results))
    failed = 0
    for name, cond, detail in results:
        if cond:
            print("  ok   %s" % name)
        else:
            failed += 1
            print("  FAIL %s  [%s]" % (name, detail))
    print("-" * 60)
    print("PASS %d / FAIL %d" % (len(results) - failed, failed))
    if failed == 0:
        print("ALL GREEN")
        return 0
    print("SELFTEST FAILED")
    return 1


def _demo_ctx():
    ctx = new_ctx()
    ctx["files"].append("demo")
    parse_text(DEMO_SUDOERS, "demo", ctx)
    return ctx


def _demo_ctx_model():
    return finish_model(_demo_ctx())


# ---------------------------------------------------------------- JSON / CLI

def model_json(model, demo, full):
    payload = {
        "tool": "sudolens",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "demo": demo,
        "redacted": not full,
        "files": model["files"],
        "rules": model["rules"],
        "defaults": model["defaults"],
        "unparsed": model["unparsed"],
        "stats": {"critical": model["critical"], "warn": model["warn"], "info": model["info"],
                  "paths": model["paths_count"]},
        "signal_counts": model["signal_counts"],
        "paths": model["paths"] if full else [],
        "notes": model["notes"],
    }
    return payload


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sudolens",
        description="sudo 提权路径透视镜：只读解析 sudoers，枚举「用户/组 → 主机 → 命令」路径并分级。零依赖单文件。",
        epilog="示例:\n"
               "  python3 sudolens.py --demo                 # 内置合成数据完整演示\n"
               "  python3 sudolens.py scan --json --full > baseline.json\n"
               "  python3 sudolens.py diff baseline.json     # cron 友好: 0无变化/1有变化/2错误\n"
               "  python3 sudolens.py explain demo --demo\n"
               "  python3 sudolens.py selftest               # 18 条不变量自测\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="sudolens " + __version__)
    ap.add_argument("--demo", action="store_true", help="用内置合成 sudoers 跑一次完整演示（等价 scan --demo）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="解析 sudoers 并枚举提权路径")
    p.add_argument("--path", default=DEFAULT_SUDOERS, help="sudoers 文件路径（默认 /etc/sudoers）")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--full", action="store_true", help="输出完整路径明细（默认本机只出统计，防内容外泄）")
    p.add_argument("--demo", action="store_true", help="用内置合成数据演示")

    p = sub.add_parser("explain", help="单用户提权路径人话解释")
    p.add_argument("user", help="用户名（或大写别名）")
    p.add_argument("--path", default=DEFAULT_SUDOERS)
    p.add_argument("--json", action="store_true")
    p.add_argument("--demo", action="store_true")

    p = sub.add_parser("diff", help="与基线 JSON 对比提权路径变化")
    p.add_argument("baseline", help="基线文件（scan --json --full 生成）")
    p.add_argument("--path", default=DEFAULT_SUDOERS)
    p.add_argument("--json", action="store_true")
    p.add_argument("--demo", action="store_true")

    sub.add_parser("selftest", help="内置不变量断言全绿")

    args = ap.parse_args(argv)

    if args.demo and not args.cmd:
        args.cmd = "scan"
        args.path = DEFAULT_SUDOERS
        args.json = False
        args.full = True
    if not args.cmd:
        ap.print_help()
        return 0

    if args.cmd == "selftest":
        return run_selftest()

    if args.cmd == "scan":
        model, err = scan_paths(args.path, demo=args.demo)
        if err:
            print("sudolens: 错误 — " + err, file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(model_json(model, args.demo, args.full or args.demo),
                             ensure_ascii=False, indent=2))
        else:
            print(render_human(model, demo=args.demo, full=args.full or args.demo))
        return 1 if (model["critical"] or model["warn"]) else 0

    if args.cmd == "explain":
        model, err = scan_paths(args.path, demo=args.demo)
        if err:
            print("sudolens: 错误 — " + err, file=sys.stderr)
            return 2
        if args.json:
            hits = [p for p in model["paths"] if p["user"] == args.user]
            print(json.dumps({"tool": "sudolens", "version": __version__, "user": args.user,
                              "paths": hits}, ensure_ascii=False, indent=2))
            return 0
        print(render_explain(model, args.user, demo=args.demo))
        return 0

    if args.cmd == "diff":
        model, err = scan_paths(args.path, demo=args.demo)
        if err:
            print("sudolens: 错误 — " + err, file=sys.stderr)
            return 2
        res, derr = cmd_diff(model, args.baseline)
        if derr:
            print("sudolens: 错误 — " + derr, file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"tool": "sudolens", "version": __version__,
                              "added": res["added"], "removed": res["removed"]},
                             ensure_ascii=False, indent=2))
        else:
            print(render_diff(res))
        return 1 if (res["added"] or res["removed"]) else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
