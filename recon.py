#!/usr/bin/env python3
"""
recon_orchestrator.py

Orchestrates recon tools (subfinder, shuffledns, dnsx, httpx, katana, nuclei, naabu, alterx, urlfinder)
in a safe, auditable way.

Safety features:
 - Requires target to be listed in scope file (scope.txt)
 - Runs in dry-run by default. Use --confirm to execute commands.
 - Active scanning (naabu/nmap) disabled unless --enable-active provided.
 - Rate-limited with configurable delay between tool runs.
 - Logs commands and outputs to ./logs/<target>-<timestamp>/

Dependencies:
 - Python 3.8+
 - Tools installed and available in PATH (subfinder, shuffledns, dnsx, httpx, katana, nuclei, naabu, urlfinder)
   Adjust the command templates below if your tool binary names/flags differ.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------
# Configuration & templates
# ---------------------------

# Commands templates. Keep placeholders: {target}, {infile}, {outfile}, {wordlist}, {resolvers}
TEMPLATES = {
    "subfinder": "subfinder -d {target} -all -o {outdir}/subfinder_{target}.txt",
    # shuffledns can accept -w (wordlist) and -r (resolvers) depending on version
    "shuffledns": "shuffledns -d {target} -w {wordlist} -r {resolvers} -o {outdir}/shuffledns_{target}.txt",
    # alterx/permutation placeholder - adjust if your tool name differs
    "alterx": "alterx -l {outdir}/combined_domains_{target}.txt -w {wordlist} -o {outdir}/permutations_{target}.txt",
    # dnsx resolves hostnames to IPs and outputs responses
    "dnsx": "dnsx -l {infile} -a -resp -o {outdir}/dnsx_{target}.txt",
    # naabu / host discovery (active) - disabled unless enabled
    "naabu": "naabu -l {infile} -p top-100 -e 22 -o {outdir}/naabu_{target}.txt",
    # httpx probe
    "httpx": "httpx -l {infile} -status-code -title -content-type -content-length -o {outdir}/httpx_{target}.txt",
    # katana crawling (JS parsing variants)
    "katana_basic": "katana -u {url} -o {outdir}/katana_basic_{target}.txt",
    "katana_jsl": "katana -u {url} -jsl -o {outdir}/katana_jsl_{target}.txt",
    "katana_auth": "katana -u {url} -H \"Cookie: {cookie}\" -xhr -jc -jsl -aff -o {outdir}/katana_auth_{target}.txt",
    # nuclei scan (simple)
    "nuclei": "nuclei -l {infile} -t cves/ -o {outdir}/nuclei_{target}.txt",
    # urlfinder (passive sources)
    "urlfinder": "urlfinder -d {target} --silent | tee {outdir}/urlfinder_{target}.txt"
}

# default wordlist & resolvers (you can override)
DEFAULT_WORDLIST = "wordlist.txt"
DEFAULT_RESOLVERS = "resolvers.txt"

# ---------------------------
# Helpers
# ---------------------------

def ensure_tools_exist(tools):
    missing = []
    for t in tools:
        if shutil.which(t) is None:
            missing.append(t)
    return missing


def log(msg, logfile):
    ts = datetime.utcnow().isoformat()
    line = f"[{ts}] {msg}"
    print(line)
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_cmd(cmd, dry_run, logfile, cwd=None, timeout=3600):
    """
    Run a shell command (string) with optional dry-run.
    Logs the command and returns subprocess.CompletedProcess or None (for dry-run).
    """
    log(f"CMD: {cmd}", logfile)
    if dry_run:
        log("(dry-run) skipping execution", logfile)
        return None
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
        stdout = proc.stdout.decode(errors="replace")
        stderr = proc.stderr.decode(errors="replace")
        with open(logfile.replace(".log", ".out"), "a", encoding="utf-8") as f:
            f.write(f"\n\n# COMMAND: {cmd}\n")
            f.write("--- STDOUT ---\n")
            f.write(stdout)
            f.write("\n--- STDERR ---\n")
            f.write(stderr)
        log(f"Exit {proc.returncode} (stdout/stderr written to out file)", logfile)
        return proc
    except subprocess.TimeoutExpired:
        log(f"Timeout expired for command: {cmd}", logfile)
        return None


def prepare_outdir(base, target):
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outdir = Path(base) / f"{target}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)
    return str(outdir)


def load_scope(scope_file):
    if not os.path.exists(scope_file):
        return set()
    with open(scope_file, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


# ---------------------------
# Orchestration steps
# ---------------------------

def step_subfinder(target, outdir, dry_run, logfile):
    cmd = TEMPLATES["subfinder"].format(target=target, outdir=outdir)
    return run_cmd(cmd, dry_run, logfile)


def step_shuffledns(target, outdir, dry_run, logfile, wordlist, resolvers):
    infile = f"{outdir}/subfinder_{target}.txt"
    # If no subfinder output exists, shuffledns can still run against domain
    cmd = TEMPLATES["shuffledns"].format(target=target, outdir=outdir, wordlist=wordlist, resolvers=resolvers)
    return run_cmd(cmd, dry_run, logfile)


def step_alterx_combine(target, outdir, dry_run, logfile, wordlist):
    # create combined domains file (dedupe subfinder + shuffledns outputs)
    combined = f"{outdir}/combined_domains_{target}.txt"
    log(f"Combining outputs into {combined}", logfile)
    if not dry_run:
        parts = []
        for p in [f"{outdir}/subfinder_{target}.txt", f"{outdir}/shuffledns_{target}.txt"]:
            if os.path.exists(p):
                parts.append(p)
        # cat them into combined and dedupe
        if parts:
            with open(combined, "w", encoding="utf-8") as out:
                seen = set()
                for p in parts:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for l in f:
                            s = l.strip()
                            if s and s not in seen:
                                seen.add(s)
                                out.write(s + "\n")
    cmd = TEMPLATES["alterx"].format(target=target, outdir=outdir, wordlist=wordlist)
    return run_cmd(cmd, dry_run, logfile)


def step_dnsx(target, outdir, dry_run, logfile):
    infile = f"{outdir}/permutations_{target}.txt"
    if not os.path.exists(infile):
        # fallback to combined_domains
        infile = f"{outdir}/combined_domains_{target}.txt"
    cmd = TEMPLATES["dnsx"].format(infile=infile, outdir=outdir, target=target)
    return run_cmd(cmd, dry_run, logfile)


def step_naabu(target, outdir, dry_run, logfile, enable_active):
    if not enable_active:
        log("naabu (host discovery) is disabled (requires --enable-active)", logfile)
        return None
    infile = f"{outdir}/dnsx_{target}.txt"
    cmd = TEMPLATES["naabu"].format(infile=infile, outdir=outdir, target=target)
    return run_cmd(cmd, dry_run, logfile)


def step_httpx(target, outdir, dry_run, logfile):
    infile = f"{outdir}/naabu_{target}.txt"
    if not os.path.exists(infile):
        # try dnsx results as fallback (hostnames)
        infile = f"{outdir}/dnsx_{target}.txt"
    cmd = TEMPLATES["httpx"].format(infile=infile, outdir=outdir, target=target)
    return run_cmd(cmd, dry_run, logfile)


def step_katana(target, outdir, dry_run, logfile, cookie=None):
    # katana against each resolved URL in httpx results
    httpx_file = f"{outdir}/httpx_{target}.txt"
    katana_out = f"{outdir}/katana_from_httpx_{target}.txt"
    if not os.path.exists(httpx_file):
        log("httpx output not found; skipping katana stage", logfile)
        return None
    # create a simple loop that crawls each URL (we'll read urls from httpx output)
    with open(katana_out, "a", encoding="utf-8") as kat_out:  # create file even in dry-run
        pass
    with open(httpx_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # httpx default output may be: <url> <status> <title> ... easier to get first token
            url = line.split()[0]
            # basic katana
            cmd_basic = TEMPLATES["katana_basic"].format(url=url, outdir=outdir, target=target)
            run_cmd(cmd_basic, dry_run, logfile)
            # jsl deeper parse - optional
            cmd_jsl = TEMPLATES["katana_jsl"].format(url=url, outdir=outdir, target=target)
            run_cmd(cmd_jsl, dry_run, logfile)
            # if cookie provided, run authenticated crawl
            if cookie:
                cmd_auth = TEMPLATES["katana_auth"].format(url=url, outdir=outdir, target=target, cookie=cookie)
                run_cmd(cmd_auth, dry_run, logfile)
            # small delay between per-URL crawls
            time.sleep(0.5)
    return True


def step_nuclei(target, outdir, dry_run, logfile):
    infile = f"{outdir}/httpx_{target}.txt"
    if not os.path.exists(infile):
        log("httpx output not found; skipping nuclei", logfile)
        return None
    cmd = TEMPLATES["nuclei"].format(infile=infile, outdir=outdir, target=target)
    return run_cmd(cmd, dry_run, logfile)


def step_urlfinder(target, outdir, dry_run, logfile):
    cmd = TEMPLATES["urlfinder"].format(target=target, outdir=outdir)
    return run_cmd(cmd, dry_run, logfile)


# ---------------------------
# Main orchestration
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Recon Orchestrator (safe defaults: dry-run, scope-check, active disabled)")
    parser.add_argument("-t", "--target", required=True, help="Target domain (example.com) or IP")
    parser.add_argument("--scope-file", default="scope.txt", help="Path to scope file. Target must appear here to run.")
    parser.add_argument("--outbase", default="logs", help="Base output directory")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Wordlist path for permutations/bruteforce")
    parser.add_argument("--resolvers", default=DEFAULT_RESOLVERS, help="Resolvers list for shuffledns/dnsx")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Dry-run (print commands only). Default: ON")
    parser.add_argument("--confirm", action="store_true", help="Confirm execution (required to actually run commands).")
    parser.add_argument("--enable-active", action="store_true", help="Enable active scans (naabu/nmap). Requires --confirm.")
    parser.add_argument("--cookie", default=None, help="Optional Cookie header value for authenticated katana crawl.")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay (seconds) between tool executions")
    parser.add_argument("--tools", default="all", help="Comma-separated list of tools to run (subfinder,shuffledns,alterx,dnsx,naabu,httpx,katana,nuclei,urlfinder)")
    args = parser.parse_args()

    # default: dry-run unless user sets --confirm
    if args.confirm:
        args.dry_run = False

    # scope check
    scope = load_scope(args.scope_file)
    if args.target not in scope:
        print(f"ERROR: Target '{args.target}' NOT found in scope file '{args.scope_file}'.")
        print("To proceed, add the target to the scope file and re-run, and include --confirm to execute.")
        sys.exit(1)

    # if active scans enabled, require confirm
    if args.enable_active and not args.confirm:
        print("ERROR: --enable-active requires --confirm. Aborting.")
        sys.exit(1)

    # prepare outdir & logfile
    outdir = prepare_outdir(args.outbase, args.target.replace("/", "_"))
    logfile = os.path.join(outdir, f"recon_{args.target}.log")
    log(f"Starting recon for {args.target}; outdir={outdir}; dry_run={args.dry_run}; enable_active={args.enable_active}", logfile)

    # check tool availability for requested tools (best-effort)
    requested = [t.strip().lower() for t in args.tools.split(",")] if args.tools != "all" else ["subfinder","shuffledns","alterx","dnsx","naabu","httpx","katana","nuclei","urlfinder"]
    tool_map = {
        "subfinder": "subfinder",
        "shuffledns": "shuffledns",
        "alterx": "alterx",
        "dnsx": "dnsx",
        "naabu": "naabu",
        "httpx": "httpx",
        "katana": "katana",
        "nuclei": "nuclei",
        "urlfinder": "urlfinder"
    }
    tools_to_check = [tool_map[t] for t in requested if t in tool_map]
    missing = ensure_tools_exist(tools_to_check)
    if missing:
        log(f"WARNING: The following tools are not found in PATH: {missing}. The script will still print commands, but execution may fail.", logfile)

    # Steps (as seen in the speaker pipeline)
    try:
        if "subfinder" in requested:
            step_subfinder(args.target, outdir, args.dry_run, logfile)
            time.sleep(args.delay)

        if "shuffledns" in requested:
            step_shuffledns(args.target, outdir, args.dry_run, logfile, args.wordlist, args.resolvers)
            time.sleep(args.delay)

        if "alterx" in requested:
            step_alterx_combine(args.target, outdir, args.dry_run, logfile, args.wordlist)
            time.sleep(args.delay)

        if "dnsx" in requested:
            step_dnsx(args.target, outdir, args.dry_run, logfile)
            time.sleep(args.delay)

        if "naabu" in requested:
            step_naabu(args.target, outdir, args.dry_run, logfile, args.enable_active)
            time.sleep(args.delay)

        if "httpx" in requested:
            step_httpx(args.target, outdir, args.dry_run, logfile)
            time.sleep(args.delay)

        if "katana" in requested:
            step_katana(args.target, outdir, args.dry_run, logfile, cookie=args.cookie)
            time.sleep(args.delay)

        if "urlfinder" in requested:
            step_urlfinder(args.target, outdir, args.dry_run, logfile)
            time.sleep(args.delay)

        if "nuclei" in requested:
            step_nuclei(args.target, outdir, args.dry_run, logfile)
            time.sleep(args.delay)

        log("Recon pipeline completed (or dry-run printed all commands). Review outputs in outdir.", logfile)
    except KeyboardInterrupt:
        log("User aborted (KeyboardInterrupt).", logfile)


if __name__ == "__main__":
    main()
