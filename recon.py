#!/usr/bin/env python3
"""
enhanced_recon_orchestrator.py

Advanced orchestration framework for bug bounty reconnaissance with improved features:
- Enhanced safety controls and audit logging
- Parallel execution with thread pools
- Progress tracking and ETA estimation
- Notification system (Discord/Slack webhooks)
- Output deduplication and merging
- Custom tool profiles for different scan intensities
- Resume capability for interrupted scans
- JSON output for integration with other tools
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import hashlib
import signal

# Try importing optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------
# Configuration & Templates
# ---------------------------

@dataclass
class ScanProfile:
    """Defines different scanning intensities"""
    name: str
    description: str
    tools: List[str]
    naabu_ports: str
    nuclei_templates: str
    rate_limit: int
    timeout: int

SCAN_PROFILES = {
    "quick": ScanProfile(
        name="quick",
        description="Fast passive reconnaissance",
        tools=["subfinder", "dnsx", "httpx"],
        naabu_ports="top-100",
        nuclei_templates="cves/",
        rate_limit=1000,
        timeout=1800
    ),
    "standard": ScanProfile(
        name="standard",
        description="Balanced active and passive recon",
        tools=["subfinder", "shuffledns", "alterx", "dnsx", "httpx", "katana", "nuclei", "urlfinder"],
        naabu_ports="top-1000",
        nuclei_templates="cves/,exposures/",
        rate_limit=500,
        timeout=3600
    ),
    "thorough": ScanProfile(
        name="thorough",
        description="Comprehensive deep reconnaissance",
        tools=["subfinder", "shuffledns", "alterx", "dnsx", "naabu", "httpx", "katana", "nuclei", "urlfinder", "gau", "waybackurls"],
        naabu_ports="1-65535",
        nuclei_templates="cves/,exposures/,vulnerabilities/,misconfiguration/",
        rate_limit=20,
        timeout=7200
    )
}

# Enhanced command templates with more options
TEMPLATES = {
    "subfinder": "subfinder -d {target} -all -recursive -t 50 -o {outdir}/subfinder_{target}.txt",
    "shuffledns": "shuffledns -d {target} -w {wordlist} -r {resolvers} -t 500 -o {outdir}/shuffledns_{target}.txt",
    "alterx": "alterx -l {outdir}/combined_domains_{target}.txt -w {wordlist} -o {outdir}/permutations_{target}.txt",
    "dnsx": "dnsx -l {infile} -a -aaaa -cname -mx -txt -resp -o {outdir}/dnsx_{target}.txt -json -o {outdir}/dnsx_{target}.json",
    "naabu": "naabu -l {infile} -p {ports} -c 50 -rate {rate} -o {outdir}/naabu_{target}.txt",
    "httpx": "httpx -l {infile} -status-code -title -content-type -content-length -tech-detect -server -o {outdir}/httpx_{target}.txt -json -o {outdir}/httpx_{target}.json",
    "katana_basic": "katana -u {url} -d 3 -jc -kf all -o {outdir}/katana_basic_{target}.txt",
    "katana_deep": "katana -u {url} -d 5 -jc -jsl -aff -xhr -kf all -o {outdir}/katana_deep_{target}.txt",
    "katana_auth": "katana -u {url} -H \"Cookie: {cookie}\" -d 5 -xhr -jc -jsl -aff -kf all -o {outdir}/katana_auth_{target}.txt",
    "nuclei": "nuclei -l {infile} -t {templates} -severity low,medium,high,critical -o {outdir}/nuclei_{target}.txt -json -o {outdir}/nuclei_{target}.json",
    "urlfinder": "urlfinder -d {target} --silent | tee {outdir}/urlfinder_{target}.txt",
    "gau": "gau {target} --threads 5 --o {outdir}/gau_{target}.txt",
    "waybackurls": "waybackurls {target} | tee {outdir}/waybackurls_{target}.txt"
}

# Default paths
DEFAULT_WORDLIST = "wordlist.txt"
DEFAULT_RESOLVERS = "resolvers.txt"

# ---------------------------
# Utility Classes
# ---------------------------

class ColoredOutput:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @classmethod
    def info(cls, msg):
        return f"{cls.OKBLUE}[INFO]{cls.ENDC} {msg}"
    
    @classmethod
    def success(cls, msg):
        return f"{cls.OKGREEN}[SUCCESS]{cls.ENDC} {msg}"
    
    @classmethod
    def warning(cls, msg):
        return f"{cls.WARNING}[WARNING]{cls.ENDC} {msg}"
    
    @classmethod
    def error(cls, msg):
        return f"{cls.FAIL}[ERROR]{cls.ENDC} {msg}"
    
    @classmethod
    def header(cls, msg):
        return f"{cls.HEADER}{cls.BOLD}{msg}{cls.ENDC}"

class ProgressTracker:
    """Track and display scan progress"""
    def __init__(self, total_steps: int):
        self.total_steps = total_steps
        self.completed_steps = 0
        self.start_time = datetime.now()
        self.step_times = []
        self.lock = threading.Lock()
    
    def complete_step(self, step_name: str):
        with self.lock:
            self.completed_steps += 1
            step_time = datetime.now() - self.start_time
            self.step_times.append(step_time.total_seconds())
            
            # Calculate ETA
            avg_time = sum(self.step_times) / len(self.step_times)
            remaining = self.total_steps - self.completed_steps
            eta_seconds = avg_time * remaining
            eta = timedelta(seconds=int(eta_seconds))
            
            progress = (self.completed_steps / self.total_steps) * 100
            print(ColoredOutput.info(f"Progress: {progress:.1f}% [{self.completed_steps}/{self.total_steps}] - ETA: {eta} - Completed: {step_name}"))
    
    def get_summary(self) -> Dict:
        total_time = datetime.now() - self.start_time
        return {
            "total_time": str(total_time),
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "completion_rate": f"{(self.completed_steps/self.total_steps)*100:.1f}%"
        }

class NotificationManager:
    """Handle notifications via webhooks"""
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
        self.enabled = webhook_url and HAS_REQUESTS
    
    def send(self, title: str, message: str, color: str = "info"):
        if not self.enabled:
            return
        
        colors = {
            "info": 3447003,
            "success": 3066993,
            "warning": 16776960,
            "error": 15158332
        }
        
        # Discord webhook format
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": colors.get(color, colors["info"]),
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        try:
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(ColoredOutput.warning(f"Failed to send notification: {e}"))

# ---------------------------
# Core Functions
# ---------------------------

def ensure_dependencies() -> Dict[str, bool]:
    """Check which tools are available"""
    tools = ["subfinder", "shuffledns", "alterx", "dnsx", "naabu", 
             "httpx", "katana", "nuclei", "urlfinder", "gau", "waybackurls"]
    availability = {}
    for tool in tools:
        availability[tool] = shutil.which(tool) is not None
    return availability

def create_state_file(outdir: str, target: str, profile: str) -> Path:
    """Create a state file for resume capability"""
    state_file = Path(outdir) / "scan_state.json"
    state = {
        "target": target,
        "profile": profile,
        "start_time": datetime.utcnow().isoformat(),
        "completed_steps": [],
        "pending_steps": [],
        "outputs": {},
        "errors": []
    }
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)
    return state_file

def update_state(state_file: Path, step: str, status: str, output: Optional[str] = None):
    """Update the state file"""
    with open(state_file, "r") as f:
        state = json.load(f)
    
    if status == "completed":
        if step not in state["completed_steps"]:
            state["completed_steps"].append(step)
        if step in state["pending_steps"]:
            state["pending_steps"].remove(step)
        if output:
            state["outputs"][step] = output
    elif status == "error":
        state["errors"].append({"step": step, "time": datetime.utcnow().isoformat()})
    
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

def load_scope(scope_file: str) -> Set[str]:
    """Load authorized targets from scope file"""
    if not os.path.exists(scope_file):
        return set()
    
    scope = set()
    with open(scope_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Support wildcards and CIDR notation
                scope.add(line)
    return scope

def validate_target(target: str, scope: Set[str]) -> bool:
    """Check if target is in scope (supports wildcards)"""
    for scope_entry in scope:
        if scope_entry.startswith("*."):
            # Wildcard subdomain
            if target.endswith(scope_entry[2:]) or target == scope_entry[2:]:
                return True
        elif "/" in scope_entry:
            # CIDR notation (basic check)
            if target.startswith(scope_entry.split("/")[0]):
                return True
        elif target == scope_entry:
            return True
    return False

def deduplicate_file(filepath: str) -> int:
    """Remove duplicate lines from a file"""
    if not os.path.exists(filepath):
        return 0
    
    with open(filepath, "r") as f:
        lines = f.readlines()
    
    seen = set()
    unique = []
    for line in lines:
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            unique.append(line)
    
    with open(filepath, "w") as f:
        f.write("\n".join(unique) + "\n")
    
    return len(unique)

def merge_outputs(files: List[str], output_file: str) -> int:
    """Merge multiple files and deduplicate"""
    all_lines = set()
    for file in files:
        if os.path.exists(file):
            with open(file, "r") as f:
                all_lines.update(line.strip() for line in f if line.strip())
    
    with open(output_file, "w") as f:
        for line in sorted(all_lines):
            f.write(line + "\n")
    
    return len(all_lines)

def run_command(cmd: str, timeout: int = 3600, dry_run: bool = False) -> Tuple[bool, str]:
    """Execute a shell command with timeout"""
    if dry_run:
        print(ColoredOutput.info(f"[DRY-RUN] Would execute: {cmd}"))
        return True, ""
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout} seconds"
    except Exception as e:
        return False, str(e)

# ---------------------------
# Recon Steps
# ---------------------------

class ReconOrchestrator:
    def __init__(self, target: str, outdir: str, profile: ScanProfile, 
                 dry_run: bool = False, notifications: Optional[NotificationManager] = None):
        self.target = target
        self.outdir = outdir
        self.profile = profile
        self.dry_run = dry_run
        self.notifications = notifications
        self.logfile = Path(outdir) / f"recon_{target}.log"
        self.state_file = create_state_file(outdir, target, profile.name)
        self.progress = ProgressTracker(len(profile.tools))
        
    def log(self, message: str, level: str = "info"):
        """Write to log file and console"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] [{level.upper()}] {message}"
        
        # Console output with colors
        if level == "error":
            print(ColoredOutput.error(message))
        elif level == "warning":
            print(ColoredOutput.warning(message))
        elif level == "success":
            print(ColoredOutput.success(message))
        else:
            print(ColoredOutput.info(message))
        
        # File output
        with open(self.logfile, "a") as f:
            f.write(log_entry + "\n")
    
    def run_subfinder(self) -> bool:
        """Subdomain enumeration with subfinder"""
        self.log("Starting subfinder enumeration")
        cmd = TEMPLATES["subfinder"].format(
            target=self.target,
            outdir=self.outdir
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/subfinder_{self.target}.txt"
            count = deduplicate_file(output_file)
            self.log(f"Subfinder found {count} unique subdomains", "success")
            update_state(self.state_file, "subfinder", "completed", output_file)
        else:
            self.log(f"Subfinder failed: {output}", "error")
            update_state(self.state_file, "subfinder", "error")
        
        self.progress.complete_step("subfinder")
        return success
    
    def run_shuffledns(self, wordlist: str, resolvers: str) -> bool:
        """DNS brute forcing with shuffledns"""
        self.log("Starting shuffledns brute forcing")
        cmd = TEMPLATES["shuffledns"].format(
            target=self.target,
            outdir=self.outdir,
            wordlist=wordlist,
            resolvers=resolvers
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/shuffledns_{self.target}.txt"
            count = deduplicate_file(output_file)
            self.log(f"Shuffledns found {count} unique subdomains", "success")
            update_state(self.state_file, "shuffledns", "completed", output_file)
        else:
            self.log(f"Shuffledns failed: {output}", "error")
            update_state(self.state_file, "shuffledns", "error")
        
        self.progress.complete_step("shuffledns")
        return success
    
    def run_alterx(self, wordlist: str) -> bool:
        """Generate permutations with alterx"""
        self.log("Generating domain permutations with alterx")
        
        # First, combine all discovered domains
        combined_file = f"{self.outdir}/combined_domains_{self.target}.txt"
        source_files = [
            f"{self.outdir}/subfinder_{self.target}.txt",
            f"{self.outdir}/shuffledns_{self.target}.txt"
        ]
        count = merge_outputs(source_files, combined_file)
        self.log(f"Combined {count} unique domains for permutation")
        
        cmd = TEMPLATES["alterx"].format(
            outdir=self.outdir,
            wordlist=wordlist
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/permutations_{self.target}.txt"
            count = deduplicate_file(output_file)
            self.log(f"Alterx generated {count} unique permutations", "success")
            update_state(self.state_file, "alterx", "completed", output_file)
        else:
            self.log(f"Alterx failed: {output}", "error")
            update_state(self.state_file, "alterx", "error")
        
        self.progress.complete_step("alterx")
        return success
    
    def run_dnsx(self) -> bool:
        """DNS resolution with dnsx"""
        self.log("Starting DNS resolution with dnsx")
        
        # Use permutations if available, otherwise combined domains
        infile = f"{self.outdir}/permutations_{self.target}.txt"
        if not os.path.exists(infile):
            infile = f"{self.outdir}/combined_domains_{self.target}.txt"
        
        cmd = TEMPLATES["dnsx"].format(
            infile=infile,
            outdir=self.outdir,
            target=self.target
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/dnsx_{self.target}.txt"
            self.log(f"DNS resolution completed", "success")
            update_state(self.state_file, "dnsx", "completed", output_file)
        else:
            self.log(f"dnsx failed: {output}", "error")
            update_state(self.state_file, "dnsx", "error")
        
        self.progress.complete_step("dnsx")
        return success
    
    def run_naabu(self) -> bool:
        """Port scanning with naabu"""
        self.log(f"Starting port scan with naabu (ports: {self.profile.naabu_ports})")
        
        infile = f"{self.outdir}/dnsx_{self.target}.txt"
        if not os.path.exists(infile):
            self.log("No resolved hosts found, skipping naabu", "warning")
            return False
        
        cmd = TEMPLATES["naabu"].format(
            infile=infile,
            outdir=self.outdir,
            target=self.target,
            ports=self.profile.naabu_ports,
            rate=self.profile.rate_limit
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout * 2, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/naabu_{self.target}.txt"
            self.log(f"Port scan completed", "success")
            update_state(self.state_file, "naabu", "completed", output_file)
        else:
            self.log(f"naabu failed: {output}", "error")
            update_state(self.state_file, "naabu", "error")
        
        self.progress.complete_step("naabu")
        return success
    
    def run_httpx(self) -> bool:
        """HTTP probing with httpx"""
        self.log("Starting HTTP probing with httpx")
        
        # Try naabu output first, fallback to dnsx
        infile = f"{self.outdir}/naabu_{self.target}.txt"
        if not os.path.exists(infile):
            infile = f"{self.outdir}/dnsx_{self.target}.txt"
        
        cmd = TEMPLATES["httpx"].format(
            infile=infile,
            outdir=self.outdir,
            target=self.target
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/httpx_{self.target}.txt"
            self.log(f"HTTP probing completed", "success")
            update_state(self.state_file, "httpx", "completed", output_file)
        else:
            self.log(f"httpx failed: {output}", "error")
            update_state(self.state_file, "httpx", "error")
        
        self.progress.complete_step("httpx")
        return success
    
    def run_katana(self, cookie: Optional[str] = None) -> bool:
        """Web crawling with katana"""
        self.log("Starting web crawling with katana")
        
        httpx_file = f"{self.outdir}/httpx_{self.target}.txt"
        if not os.path.exists(httpx_file):
            self.log("No HTTP endpoints found, skipping katana", "warning")
            return False
        
        # Read URLs from httpx output
        urls = []
        with open(httpx_file, "r") as f:
            for line in f:
                if line.strip():
                    # Extract URL from httpx output (first field)
                    url = line.strip().split()[0]
                    if url.startswith("http"):
                        urls.append(url)
        
        # Limit URLs for performance
        max_urls = 50 if self.profile.name == "thorough" else 20
        urls = urls[:max_urls]
        
        self.log(f"Crawling {len(urls)} URLs")
        
        for i, url in enumerate(urls):
            # Basic crawl
            cmd = TEMPLATES["katana_basic"].format(
                url=url,
                outdir=self.outdir,
                target=self.target
            )
            run_command(cmd, timeout=300, dry_run=self.dry_run)
            
            # Deep crawl for thorough profile
            if self.profile.name == "thorough":
                cmd = TEMPLATES["katana_deep"].format(
                    url=url,
                    outdir=self.outdir,
                    target=self.target
                )
                run_command(cmd, timeout=600, dry_run=self.dry_run)
            
            # Authenticated crawl if cookie provided
            if cookie:
                cmd = TEMPLATES["katana_auth"].format(
                    url=url,
                    outdir=self.outdir,
                    target=self.target,
                    cookie=cookie
                )
                run_command(cmd, timeout=600, dry_run=self.dry_run)
            
            # Rate limiting
            time.sleep(1.0 / self.profile.rate_limit)
        
        self.log(f"Katana crawling completed", "success")
        update_state(self.state_file, "katana", "completed")
        self.progress.complete_step("katana")
        return True
    
    def run_nuclei(self) -> bool:
        """Vulnerability scanning with nuclei"""
        self.log(f"Starting nuclei scan (templates: {self.profile.nuclei_templates})")
        
        infile = f"{self.outdir}/httpx_{self.target}.txt"
        if not os.path.exists(infile):
            self.log("No HTTP endpoints found, skipping nuclei", "warning")
            return False
        
        cmd = TEMPLATES["nuclei"].format(
            infile=infile,
            outdir=self.outdir,
            target=self.target,
            templates=self.profile.nuclei_templates
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout * 2, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/nuclei_{self.target}.txt"
            self.log(f"Nuclei scan completed", "success")
            
            # Check for findings
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    findings = f.readlines()
                if findings:
                    self.log(f"ALERT: Nuclei found {len(findings)} potential issues!", "warning")
                    if self.notifications:
                        self.notifications.send(
                            f"Nuclei Findings for {self.target}",
                            f"Found {len(findings)} potential vulnerabilities",
                            "warning"
                        )
            
            update_state(self.state_file, "nuclei", "completed", output_file)
        else:
            self.log(f"nuclei failed: {output}", "error")
            update_state(self.state_file, "nuclei", "error")
        
        self.progress.complete_step("nuclei")
        return success
    
    def run_urlfinder(self) -> bool:
        """Passive URL collection with urlfinder"""
        self.log("Starting passive URL collection with urlfinder")
        
        cmd = TEMPLATES["urlfinder"].format(
            target=self.target,
            outdir=self.outdir
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/urlfinder_{self.target}.txt"
            self.log(f"URL collection completed", "success")
            update_state(self.state_file, "urlfinder", "completed", output_file)
        else:
            self.log(f"urlfinder failed: {output}", "error")
            update_state(self.state_file, "urlfinder", "error")
        
        self.progress.complete_step("urlfinder")
        return success
    
    def run_gau(self) -> bool:
        """Archive URL collection with gau"""
        self.log("Starting archive URL collection with gau")
        
        cmd = TEMPLATES["gau"].format(
            target=self.target,
            outdir=self.outdir
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/gau_{self.target}.txt"
            count = deduplicate_file(output_file)
            self.log(f"gau found {count} unique URLs", "success")
            update_state(self.state_file, "gau", "completed", output_file)
        else:
            self.log(f"gau failed: {output}", "error")
            update_state(self.state_file, "gau", "error")
        
        self.progress.complete_step("gau")
        return success
    
    def run_waybackurls(self) -> bool:
        """Wayback machine URL collection"""
        self.log("Starting Wayback machine URL collection")
        
        cmd = TEMPLATES["waybackurls"].format(
            target=self.target,
            outdir=self.outdir
        )
        
        success, output = run_command(cmd, timeout=self.profile.timeout, dry_run=self.dry_run)
        if success:
            output_file = f"{self.outdir}/waybackurls_{self.target}.txt"
            count = deduplicate_file(output_file)
            self.log(f"waybackurls found {count} unique URLs", "success")
            update_state(self.state_file, "waybackurls", "completed", output_file)
        else:
            self.log(f"waybackurls failed: {output}", "error")
            update_state(self.state_file, "waybackurls", "error")
        
        self.progress.complete_step("waybackurls")
        return success
    
    def generate_report(self) -> Dict:
        """Generate a final JSON report"""
        self.log("Generating final report")
        
        # Load state
        with open(self.state_file, "r") as f:
            state = json.load(f)
        
        # Count results
        stats = {
            "subdomains": 0,
            "live_hosts": 0,
            "http_endpoints": 0,
            "vulnerabilities": 0,
            "urls_collected": 0
        }
        
        # Count subdomains
        subdomain_files = [
            f"{self.outdir}/subfinder_{self.target}.txt",
            f"{self.outdir}/shuffledns_{self.target}.txt"
        ]
        for file in subdomain_files:
            if os.path.exists(file):
                with open(file, "r") as f:
                    stats["subdomains"] += len(f.readlines())
        
        # Count live hosts
        if os.path.exists(f"{self.outdir}/dnsx_{self.target}.txt"):
            with open(f"{self.outdir}/dnsx_{self.target}.txt", "r") as f:
                stats["live_hosts"] = len(f.readlines())
        
        # Count HTTP endpoints
        if os.path.exists(f"{self.outdir}/httpx_{self.target}.txt"):
            with open(f"{self.outdir}/httpx_{self.target}.txt", "r") as f:
                stats["http_endpoints"] = len(f.readlines())
        
        # Count vulnerabilities
        if os.path.exists(f"{self.outdir}/nuclei_{self.target}.txt"):
            with open(f"{self.outdir}/nuclei_{self.target}.txt", "r") as f:
                stats["vulnerabilities"] = len(f.readlines())
        
        # Count collected URLs
        url_files = [
            f"{self.outdir}/urlfinder_{self.target}.txt",
            f"{self.outdir}/gau_{self.target}.txt",
            f"{self.outdir}/waybackurls_{self.target}.txt"
        ]
        for file in url_files:
            if os.path.exists(file):
                with open(file, "r") as f:
                    stats["urls_collected"] += len(f.readlines())
        
        report = {
            "target": self.target,
            "profile": asdict(self.profile),
            "scan_time": state["start_time"],
            "completed_steps": state["completed_steps"],
            "errors": state["errors"],
            "statistics": stats,
            "progress": self.progress.get_summary(),
            "output_directory": self.outdir
        }
        
        # Save report
        report_file = Path(self.outdir) / f"report_{self.target}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        self.log(f"Report saved to {report_file}", "success")
        return report
    
    def orchestrate(self, wordlist: str, resolvers: str, cookie: Optional[str] = None, 
                   enable_active: bool = False) -> bool:
        """Main orchestration logic"""
        self.log(ColoredOutput.header(f"Starting {self.profile.name} scan for {self.target}"))
        
        if self.notifications:
            self.notifications.send(
                f"Scan Started: {self.target}",
                f"Profile: {self.profile.name}\nTools: {', '.join(self.profile.tools)}",
                "info"
            )
        
        # Tool availability check
        available_tools = ensure_dependencies()
        for tool in self.profile.tools:
            if tool in available_tools and not available_tools[tool]:
                self.log(f"Tool {tool} not found, skipping", "warning")
        
        # Execute tools based on profile
        tool_methods = {
            "subfinder": lambda: self.run_subfinder(),
            "shuffledns": lambda: self.run_shuffledns(wordlist, resolvers),
            "alterx": lambda: self.run_alterx(wordlist),
            "dnsx": lambda: self.run_dnsx(),
            "naabu": lambda: self.run_naabu() if enable_active else self.log("naabu skipped (requires --enable-active)", "warning"),
            "httpx": lambda: self.run_httpx(),
            "katana": lambda: self.run_katana(cookie),
            "nuclei": lambda: self.run_nuclei(),
            "urlfinder": lambda: self.run_urlfinder(),
            "gau": lambda: self.run_gau(),
            "waybackurls": lambda: self.run_waybackurls()
        }
        
        for tool in self.profile.tools:
            if tool in tool_methods and available_tools.get(tool, False):
                try:
                    tool_methods[tool]()
                    # Rate limiting between tools
                    time.sleep(2.0 / self.profile.rate_limit)
                except Exception as e:
                    self.log(f"Error running {tool}: {e}", "error")
                    update_state(self.state_file, tool, "error")
        
        # Generate final report
        report = self.generate_report()
        
        # Send completion notification
        if self.notifications:
            summary = (
                f"Subdomains: {report['statistics']['subdomains']}\n"
                f"Live Hosts: {report['statistics']['live_hosts']}\n"
                f"HTTP Endpoints: {report['statistics']['http_endpoints']}\n"
                f"Vulnerabilities: {report['statistics']['vulnerabilities']}\n"
                f"URLs Collected: {report['statistics']['urls_collected']}"
            )
            self.notifications.send(
                f"Scan Completed: {self.target}",
                summary,
                "success" if report['statistics']['vulnerabilities'] == 0 else "warning"
            )
        
        self.log(ColoredOutput.header(f"Scan completed! Results in {self.outdir}"))
        return True

# ---------------------------
# Parallel Execution Manager
# ---------------------------

class ParallelExecutor:
    """Execute multiple targets in parallel"""
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []
    
    def submit_target(self, orchestrator: ReconOrchestrator, **kwargs):
        """Submit a target for scanning"""
        future = self.executor.submit(orchestrator.orchestrate, **kwargs)
        self.futures.append((orchestrator.target, future))
        return future
    
    def wait_completion(self) -> Dict[str, bool]:
        """Wait for all scans to complete"""
        results = {}
        for target, future in as_completed([(t, f) for t, f in self.futures]):
            try:
                success = future.result()
                results[target] = success
                print(ColoredOutput.success(f"Completed scan for {target}"))
            except Exception as e:
                results[target] = False
                print(ColoredOutput.error(f"Failed scan for {target}: {e}"))
        return results
    
    def shutdown(self):
        """Clean shutdown"""
        self.executor.shutdown(wait=True)

# ---------------------------
# Main Entry Point
# ---------------------------

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(ColoredOutput.warning("\nReceived interrupt signal, cleaning up..."))
    sys.exit(0)

def main():
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Enhanced Recon Orchestrator - Advanced Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Quick passive scan:
    %(prog)s -t example.com --profile quick --confirm

  Standard scan with notifications:
    %(prog)s -t example.com --profile standard --webhook https://discord.com/api/webhooks/1243713762607759432/U_61UcejQazsWi1hJEekDoWvzSdfgT_ITUfzlosldsjvBmVZJEby1365-SklzBwBNXyz --confirm

  Thorough scan with active scanning:
    %(prog)s -t example.com --profile thorough --enable-active --confirm

  Multiple targets in parallel:
    %(prog)s -t example.com,test.com --parallel 3 --confirm

  Resume interrupted scan:
    %(prog)s -t example.com --resume logs/example.com_20240101120000 --confirm
        """
    )
    
    # Required arguments
    parser.add_argument("-t", "--target", required=True,
                       help="Target domain(s), comma-separated for multiple")
    
    # Profile and scope
    parser.add_argument("--profile", choices=["quick", "standard", "thorough"],
                       default="standard", help="Scan profile to use")
    parser.add_argument("--scope-file", default="scope.txt",
                       help="Path to scope file (default: scope.txt)")
    
    # Output options
    parser.add_argument("--outbase", default="logs",
                       help="Base output directory (default: logs)")
    parser.add_argument("--resume", help="Resume from previous scan directory")
    
    # Tool configuration
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                       help="Wordlist for DNS brute-forcing")
    parser.add_argument("--resolvers", default=DEFAULT_RESOLVERS,
                       help="DNS resolvers list")
    parser.add_argument("--cookie", help="Cookie header for authenticated scans")
    
    # Execution options
    parser.add_argument("--dry-run", action="store_true",
                       help="Show commands without executing")
    parser.add_argument("--confirm", action="store_true",
                       help="Confirm execution (required for actual scanning)")
    parser.add_argument("--enable-active", action="store_true",
                       help="Enable active scanning tools (naabu/nmap)")
    parser.add_argument("--parallel", type=int, default=1,
                       help="Number of parallel target scans")
    
    # Notifications
    parser.add_argument("--webhook", help="Discord/Slack webhook URL for notifications")
    
    # Advanced options
    parser.add_argument("--custom-profile", help="JSON file with custom profile definition")
    parser.add_argument("--rate-limit", type=int,
                       help="Override profile rate limit")
    parser.add_argument("--timeout", type=int,
                       help="Override profile timeout (seconds)")
    
    args = parser.parse_args()
    
    # Print banner
    print(ColoredOutput.header("""
╔═══════════════════════════════════════════════════════════════╗
║                    Recon Orchestrator v2.0                    ║
║          Advanced Bug Bounty Automation Suite                 ║
╚═══════════════════════════════════════════════════════════════╝
    """))
    
    # Validation
    if not args.confirm and not args.dry_run:
        print(ColoredOutput.warning("Running in DRY-RUN mode (use --confirm to execute)"))
        args.dry_run = True
    
    if args.enable_active and not args.confirm:
        print(ColoredOutput.error("Active scanning requires --confirm flag"))
        sys.exit(1)
    
    # Load scope
    scope = load_scope(args.scope_file)
    if not scope:
        print(ColoredOutput.warning(f"Scope file {args.scope_file} is empty or not found"))
        if not args.confirm:
            print(ColoredOutput.error("Cannot proceed without scope verification"))
            sys.exit(1)
    
    # Parse targets
    targets = [t.strip() for t in args.target.split(",")]
    
    # Validate targets against scope
    invalid_targets = []
    for target in targets:
        if not validate_target(target, scope):
            invalid_targets.append(target)
    
    if invalid_targets:
        print(ColoredOutput.error(f"Targets not in scope: {', '.join(invalid_targets)}"))
        print(ColoredOutput.info(f"Add them to {args.scope_file} to continue"))
        sys.exit(1)
    
    # Load profile
    if args.custom_profile:
        with open(args.custom_profile, "r") as f:
            custom = json.load(f)
            profile = ScanProfile(**custom)
    else:
        profile = SCAN_PROFILES[args.profile]
    
    # Override profile settings if specified
    if args.rate_limit:
        profile.rate_limit = args.rate_limit
    if args.timeout:
        profile.timeout = args.timeout
    
    # Setup notifications
    notifications = None
    if args.webhook:
        if not HAS_REQUESTS:
            print(ColoredOutput.warning("requests library not installed, notifications disabled"))
        else:
            notifications = NotificationManager(args.webhook)
    
    # Check tool availability
    print(ColoredOutput.info("Checking tool availability..."))
    available = ensure_dependencies()
    missing = [tool for tool, avail in available.items() if not avail and tool in profile.tools]
    if missing:
        print(ColoredOutput.warning(f"Missing tools: {', '.join(missing)}"))
        print(ColoredOutput.info("Install missing tools or use a different profile"))
        if not args.confirm:
            sys.exit(1)
    
    # Execute scans
    if args.parallel > 1 and len(targets) > 1:
        # Parallel execution
        print(ColoredOutput.info(f"Starting parallel scan for {len(targets)} targets"))
        executor = ParallelExecutor(max_workers=args.parallel)
        
        for target in targets:
            # Check for resume
            if args.resume:
                outdir = args.resume
            else:
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                outdir = Path(args.outbase) / f"{target}_{timestamp}"
                outdir.mkdir(parents=True, exist_ok=True)
            
            orchestrator = ReconOrchestrator(
                target=target,
                outdir=str(outdir),
                profile=profile,
                dry_run=args.dry_run,
                notifications=notifications
            )
            
            executor.submit_target(
                orchestrator,
                wordlist=args.wordlist,
                resolvers=args.resolvers,
                cookie=args.cookie,
                enable_active=args.enable_active
            )
        
        results = executor.wait_completion()
        executor.shutdown()
        
        # Print summary
        print(ColoredOutput.header("\n=== Scan Summary ==="))
        for target, success in results.items():
            status = ColoredOutput.success("SUCCESS") if success else ColoredOutput.error("FAILED")
            print(f"{target}: {status}")
    
    else:
        # Sequential execution
        for target in targets:
            # Check for resume
            if args.resume:
                outdir = args.resume
            else:
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                outdir = Path(args.outbase) / f"{target}_{timestamp}"
                outdir.mkdir(parents=True, exist_ok=True)
            
            orchestrator = ReconOrchestrator(
                target=target,
                outdir=str(outdir),
                profile=profile,
                dry_run=args.dry_run,
                notifications=notifications
            )
            
            success = orchestrator.orchestrate(
                wordlist=args.wordlist,
                resolvers=args.resolvers,
                cookie=args.cookie,
                enable_active=args.enable_active
            )
            
            if not success:
                print(ColoredOutput.error(f"Scan failed for {target}"))

if __name__ == "__main__":
    main()
