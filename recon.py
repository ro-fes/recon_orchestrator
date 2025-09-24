#!/usr/bin/env python3
"""
bugbounty_pipeline_full_v5.py

Full bug bounty pipeline:
subfinder -> shuffledns -> alterx -> merge -> naabu -> httpx -> nuclei -> 
katana -> merge katana -> nuclei(katana) -> urlfinder -> gau -> waybackurls -> merge all URLs -> nuclei(all URLs)
+ per-domain summary CSV + Discord notifications + overall summary CSV
"""

import os
import argparse
import subprocess
import shlex
import sys
import csv
import json

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path

def validate_input_files(wordlist, resolvers):
    """Validate input files before starting the scan"""
    print("[+] Validating input files...")
    
    # Check wordlist
    if not os.path.isfile(wordlist):
        print(f"[!] Wordlist file not found: {wordlist}")
        return False
        
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            wordlist_lines = sum(1 for line in f if line.strip())
        print(f"[+] Wordlist: {wordlist_lines} entries")
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")
        return False
    
    # Check resolvers
    if not os.path.isfile(resolvers):
        print(f"[!] Resolvers file not found: {resolvers}")
        return False
        
    try:
        with open(resolvers, 'r', encoding='utf-8', errors='ignore') as f:
            resolver_lines = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Basic IP validation
                    parts = line.split(':')[0].split('.')  # Handle IP:port format
                    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        resolver_lines.append(line)
        
        if not resolver_lines:
            print(f"[!] No valid DNS resolvers found in {resolvers}")
            return False
            
        print(f"[+] Resolvers: {len(resolver_lines)} valid DNS servers")
    except Exception as e:
        print(f"[!] Error reading resolvers: {e}")
        return False
    
    return True

def sanitize_filename(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in ("-", "_", ".",)).rstrip(" .")

def check_required_tools():
    """Check if required tools are installed"""
    required_tools = [
        'subfinder', 'shuffledns', 'alterx', 'naabu', 
        'httpx', 'nuclei', 'katana', 'urlfinder', 'gau', 'waybackurls'
    ]
    
    missing_tools = []
    
    print("[+] Checking required tools...")
    for tool in required_tools:
        try:
            result = subprocess.run([tool, '-version'], capture_output=True, timeout=10)
            if result.returncode != 0:
                # Try alternative version flags
                result = subprocess.run([tool, '--version'], capture_output=True, timeout=10)
                if result.returncode != 0:
                    result = subprocess.run([tool, '-h'], capture_output=True, timeout=10)
                    if result.returncode != 0:
                        missing_tools.append(tool)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[!] Missing tools: {', '.join(missing_tools)}")
        print("[!] Install missing tools:")
        for tool in missing_tools:
            if tool == 'gau':
                print(f"   go install github.com/lc/gau/v2/cmd/gau@latest")
            elif tool == 'waybackurls':
                print(f"   go install github.com/tomnomnom/waybackurls@latest")
            elif tool == 'urlfinder':
                print(f"   go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest")
            else:
                print(f"   go install -v github.com/projectdiscovery/{tool}/cmd/{tool}@latest")
        return False
    
    print("[+] All required tools are installed")
    return True

def run_cmd(cmd, stdout_file=None, stderr_file=None, dry_run=False):
    print(f"> {' '.join(shlex.quote(p) for p in cmd)}")
    if dry_run:
        return 0
    try:
        # Handle stdout
        if stdout_file:
            stdout_handle = open(stdout_file, "wb")
        else:
            stdout_handle = subprocess.DEVNULL
            
        # Handle stderr  
        if stderr_file:
            stderr_handle = open(stderr_file, "wb")
        else:
            stderr_handle = subprocess.DEVNULL
            
        try:
            result = subprocess.run(cmd, stdout=stdout_handle, stderr=stderr_handle, timeout=300)
            if result.returncode != 0:
                # For debugging, let's also capture stderr when command fails
                if not stderr_file:
                    debug_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if debug_result.stderr:
                        print(f"[!] Error details: {debug_result.stderr.strip()}")
                return result.returncode
            return 0
        finally:
            # Close file handles if they were opened
            if stdout_file and stdout_handle != subprocess.DEVNULL:
                stdout_handle.close()
            if stderr_file and stderr_handle != subprocess.DEVNULL:
                stderr_handle.close()
                
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after 300 seconds: {' '.join(cmd)}", file=sys.stderr)
        return 124
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed (rc={e.returncode}): {' '.join(cmd)}", file=sys.stderr)
        return e.returncode
    except FileNotFoundError:
        print(f"[!] Tool not installed: {cmd[0]}", file=sys.stderr)
        print(f"[!] Install with: go install -v github.com/projectdiscovery/{cmd[0]}/cmd/{cmd[0]}@latest")
        return 127
    except Exception as e:
        print(f"[!] Unexpected error running command: {e}", file=sys.stderr)
        return 1

def merge_files(inputs, output, dry_run=False):
    seen = set()
    results = []
    for path in inputs:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        results.append(line)
    if not dry_run:
        with open(output, "w", encoding="utf-8") as out:
            out.write("\n".join(results) + "\n" if results else "")
    print(f"[+] Merged {len(results)} unique lines → {output}")
    return output

def extract_urls_from_httpx(httpx_path, urls_out_path, dry_run=False):
    if dry_run:
        print(f"[DRY-RUN] would extract URLs from {httpx_path} -> {urls_out_path}")
        return urls_out_path

    if not os.path.isfile(httpx_path):
        print(f"[!] httpx input not found: {httpx_path}")
        return None

    seen = set()
    extracted = []
    with open(httpx_path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            ln = raw.strip()
            if not ln:
                continue
            if ln.startswith("http://") or ln.startswith("https://"):
                url = ln.split()[0]
                if url not in seen:
                    seen.add(url)
                    extracted.append(url)
                continue
            for p in ln.split():
                if p.startswith("http://") or p.startswith("https://"):
                    url = p
                    if url not in seen:
                        seen.add(url)
                        extracted.append(url)
                    break
    if extracted:
        with open(urls_out_path, "w", encoding="utf-8") as out:
            out.write("\n".join(extracted) + "\n")
        print(f"[+] Extracted {len(extracted)} URLs -> {urls_out_path}")
        return urls_out_path
    else:
        print(f"[!] No URLs extracted from {httpx_path}")
        return None

def generate_summary_csv(domain, domain_dir, safe):
    summary_file = os.path.join(domain_dir, f"summary_{safe}.csv")

    def count_lines(file_path):
        if not os.path.isfile(file_path):
            return 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    def count_nuclei(file_path):
        if not os.path.isfile(file_path):
            return 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            json.loads(line)
                            count += 1
                        except json.JSONDecodeError:
                            continue
                return count
        except Exception:
            return 0

    summary_data = {
        "domain": domain,
        "subdomains": count_lines(os.path.join(domain_dir, "all_subdomains.txt")),
        "live_hosts": count_lines(os.path.join(domain_dir, f"httpx_urls_{safe}.txt")),
        "katana_urls": count_lines(os.path.join(domain_dir, f"katana_merged_{safe}.txt")),
        "merged_urls": count_lines(os.path.join(domain_dir, f"all_urls_{safe}.txt")),
        "nuclei_findings": count_nuclei(os.path.join(domain_dir, f"nuclei_all_{safe}.json"))
    }

    try:
        with open(summary_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=summary_data.keys())
            writer.writeheader()
            writer.writerow(summary_data)
        print(f"[+] Summary CSV generated: {summary_file}")
    except Exception as e:
        print(f"[!] Failed to generate summary CSV: {e}")
    
    return summary_data

def append_overall_summary(base_results_dir, summary_data):
    overall_csv = os.path.join(base_results_dir, "summary_all_domains.csv")
    try:
        file_exists = os.path.isfile(overall_csv)
        with open(overall_csv, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=summary_data.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(summary_data)
        print(f"[+] Overall summary updated: {overall_csv}")
    except Exception as e:
        print(f"[!] Failed to update overall summary: {e}")

def notify_results(summary_data, domain_dir, safe_domain, enable_notify=False):
    """Send notification using ProjectDiscovery notify tool with bulk mode"""
    if not enable_notify:
        return
    
    # Create a comprehensive notification file with all findings
    notify_file = os.path.join(domain_dir, f"notify_data_{safe_domain}.txt")
    
    try:
        with open(notify_file, "w", encoding="utf-8") as f:
            f.write(f"🔍 Bug Bounty Scan Complete: {summary_data['domain']}\n")
            f.write(f"{'='*50}\n")
            f.write(f"📊 SUMMARY:\n")
            f.write(f"• Subdomains Found: {summary_data['subdomains']}\n")
            f.write(f"• Live Hosts: {summary_data['live_hosts']}\n")
            f.write(f"• Katana URLs: {summary_data['katana_urls']}\n")
            f.write(f"• Total URLs: {summary_data['merged_urls']}\n")
            f.write(f"• 🚨 Nuclei Findings: {summary_data['nuclei_findings']}\n")
            f.write(f"{'='*50}\n\n")
            
            # Add live hosts if available
            httpx_urls_file = os.path.join(domain_dir, f"httpx_urls_{safe_domain}.txt")
            if os.path.isfile(httpx_urls_file):
                f.write("🌐 LIVE HOSTS:\n")
                try:
                    with open(httpx_urls_file, "r", encoding="utf-8", errors="ignore") as hosts_file:
                        hosts = [line.strip() for line in hosts_file if line.strip()]
                        for i, host in enumerate(hosts[:10], 1):  # Limit to first 10
                            f.write(f"{i}. {host}\n")
                        if len(hosts) > 10:
                            f.write(f"... and {len(hosts) - 10} more hosts\n")
                except Exception:
                    f.write("Error reading hosts file\n")
                f.write("\n")
            
            # Add nuclei findings if available
            nuclei_file = os.path.join(domain_dir, f"nuclei_all_{safe_domain}.json")
            if os.path.isfile(nuclei_file):
                f.write("🚨 NUCLEI FINDINGS:\n")
                try:
                    findings_count = 0
                    with open(nuclei_file, "r", encoding="utf-8", errors="ignore") as nf:
                        for line in nf:
                            if line.strip():
                                try:
                                    finding = json.loads(line.strip())
                                    severity = finding.get('info', {}).get('severity', 'unknown')
                                    template = finding.get('template-id', 'unknown')
                                    host = finding.get('host', 'unknown')
                                    f.write(f"• [{severity.upper()}] {template} - {host}\n")
                                    findings_count += 1
                                    if findings_count >= 15:  # Limit to first 15 findings
                                        break
                                except json.JSONDecodeError:
                                    continue
                    if findings_count == 0:
                        f.write("No findings in nuclei output\n")
                except Exception:
                    f.write("Error reading nuclei findings\n")
                f.write("\n")
            
            f.write(f"📁 Full results saved in: {domain_dir}\n")
            f.write(f"🕒 Scan completed at: {os.popen('date').read().strip()}\n")
        
        # Use notify with bulk mode and discord provider
        cmd = [
            "notify", 
            "-data", notify_file,
            "-bulk",
            "-provider", "discord"
        ]
        
        # Run notify command
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=60
        )
        
        if result.returncode == 0:
            print(f"[+] Notification sent for {summary_data['domain']}")
        else:
            print(f"[!] Notification failed for {summary_data['domain']}: {result.stderr.strip()}")
            
    except subprocess.TimeoutExpired:
        print(f"[!] Notification timeout for {summary_data['domain']}")
    except FileNotFoundError:
        print("[!] notify tool not found. Install: go install -v github.com/projectdiscovery/notify/cmd/notify@latest")
    except Exception as e:
        print(f"[!] Failed to create notification: {e}")

def send_final_summary_notification(base_results_dir, total_domains, successful_domains, enable_notify=False):
    """Send final summary notification using notify"""
    if not enable_notify:
        return
        
    summary_file = os.path.join(base_results_dir, "final_summary_notification.txt")
    
    try:
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("✅ BUG BOUNTY PIPELINE COMPLETE!\n")
            f.write(f"{'='*50}\n")
            f.write(f"📈 FINAL SUMMARY:\n")
            f.write(f"• Total Domains Processed: {total_domains}\n")
            f.write(f"• Successfully Completed: {successful_domains}\n")
            f.write(f"• Failed: {total_domains - successful_domains}\n")
            f.write(f"• Success Rate: {(successful_domains/total_domains*100):.1f}%\n")
            f.write(f"{'='*50}\n")
            f.write(f"📁 All results saved in: {base_results_dir}\n")
            f.write(f"📊 Overall summary CSV: {os.path.join(base_results_dir, 'summary_all_domains.csv')}\n")
            f.write(f"🕒 Pipeline completed at: {os.popen('date').read().strip()}\n")
        
        cmd = [
            "notify",
            "-data", summary_file,
            "-bulk", 
            "-provider", "discord"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("[+] Final summary notification sent")
        else:
            print(f"[!] Final notification failed: {result.stderr.strip()}")
            
    except Exception as e:
        print(f"[!] Failed to send final notification: {e}")

def send_nuclei_findings_notification(domain_dir, safe_domain, enable_notify=False):
    """Send detailed nuclei findings as separate notification"""
    if not enable_notify:
        return
        
    nuclei_file = os.path.join(domain_dir, f"nuclei_all_{safe_domain}.json")
    if not os.path.isfile(nuclei_file):
        return
        
    findings_file = os.path.join(domain_dir, f"nuclei_findings_{safe_domain}.txt")
    
    try:
        findings_count = 0
        with open(findings_file, "w", encoding="utf-8") as f:
            f.write(f"🚨 DETAILED NUCLEI FINDINGS FOR: {safe_domain}\n")
            f.write(f"{'='*60}\n\n")
            
            with open(nuclei_file, "r", encoding="utf-8", errors="ignore") as nf:
                for line_num, line in enumerate(nf, 1):
                    if line.strip():
                        try:
                            finding = json.loads(line.strip())
                            severity = finding.get('info', {}).get('severity', 'unknown')
                            template = finding.get('template-id', 'unknown')
                            name = finding.get('info', {}).get('name', 'Unknown')
                            host = finding.get('host', 'unknown')
                            matched_at = finding.get('matched-at', 'unknown')
                            
                            f.write(f"🔍 Finding #{line_num}\n")
                            f.write(f"├── Severity: {severity.upper()}\n")
                            f.write(f"├── Template: {template}\n")
                            f.write(f"├── Name: {name}\n")
                            f.write(f"├── Host: {host}\n")
                            f.write(f"└── Matched: {matched_at}\n\n")
                            
                            findings_count += 1
                            if findings_count >= 25:  # Limit detailed findings
                                f.write("... (truncated, see full results in JSON file)\n")
                                break
                                
                        except json.JSONDecodeError:
                            continue
        
        if findings_count > 0:
            cmd = [
                "notify",
                "-data", findings_file,
                "-bulk",
                "-provider", "discord"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print(f"[+] Nuclei findings notification sent for {safe_domain}")
            else:
                print(f"[!] Nuclei findings notification failed: {result.stderr.strip()}")
                
    except Exception as e:
        print(f"[!] Failed to send nuclei findings notification: {e}")

def process_domain(domain, base_results_dir, wordlist, resolvers,
                   dry_run=False, subfinder_threads="50",
                   shuffledns_threads="500", naabu_rate="500", enable_notify=False):
    domain = domain.strip()
    if not domain:
        print("[!] Empty domain name, skipping...")
        return

    # Validate domain format
    if not domain.replace(".", "").replace("-", "").replace("_", "").isalnum():
        print(f"[!] Invalid domain format: {domain}")
        return

    safe = sanitize_filename(domain)
    domain_dir = os.path.join(base_results_dir, safe)
    
    try:
        ensure_dir(domain_dir)
    except Exception as e:
        print(f"[!] Failed to create directory {domain_dir}: {e}")
        return

    # File paths
    subfinder_out = os.path.join(domain_dir, "subfinder_output.txt")
    shuffledns_out = os.path.join(domain_dir, f"shuffledns_{safe}.txt")
    alterx_out = os.path.join(domain_dir, f"permutations_{safe}.txt")
    merged_out = os.path.join(domain_dir, "all_subdomains.txt")
    naabu_out = os.path.join(domain_dir, f"naabu_{safe}.txt")
    httpx_out = os.path.join(domain_dir, f"httpx_{safe}.txt")
    httpx_urls = os.path.join(domain_dir, f"httpx_urls_{safe}.txt")
    nuclei_out = os.path.join(domain_dir, f"nuclei_{safe}.json")
    katana_basic_out = os.path.join(domain_dir, f"katana_basic_{safe}.txt")
    katana_deep_out = os.path.join(domain_dir, f"katana_deep_{safe}.txt")
    katana_merged_out = os.path.join(domain_dir, f"katana_merged_{safe}.txt")
    nuclei_katana_out = os.path.join(domain_dir, f"nuclei_katana_{safe}.json")
    urlfinder_out = os.path.join(domain_dir, f"urlfinder_{safe}.txt")
    gau_out = os.path.join(domain_dir, f"gau_{safe}.txt")
    waybackurls_out = os.path.join(domain_dir, f"waybackurls_{safe}.txt")
    all_urls_out = os.path.join(domain_dir, f"all_urls_{safe}.txt")
    nuclei_all_out = os.path.join(domain_dir, f"nuclei_all_{safe}.json")

    print(f"\n[+] === Processing {domain} ===")

    # Step 1: Subfinder
    print("[1/17] Running subfinder...")
    run_cmd([
        "subfinder", "-d", domain,
        "-t", subfinder_threads,
        "-silent"
    ], stdout_file=subfinder_out, dry_run=dry_run)

    # Step 2: ShuffleDNS
    print("[2/17] Running shuffledns...")
    if run_cmd([
        "shuffledns", "-d", domain,
        "-w", wordlist,
        "-r", resolvers,
        "-t", shuffledns_threads,
        "-mode bruteforce -silent"
    ], stdout_file=shuffledns_out, dry_run=dry_run) != 0:
        print(f"[!] ShuffleDNS failed for {domain}, continuing with other tools...")
        # Create empty file to avoid issues with merge step
        if not dry_run:
            with open(shuffledns_out, 'w') as f:
                f.write("")

    # Step 3: Alterx
    print("[3/17] Running alterx...")
    if os.path.isfile(subfinder_out):
        run_cmd([
            "alterx", "-l", subfinder_out,
            "-silent"
        ], stdout_file=alterx_out, dry_run=dry_run)

    # Step 4: Merge all subdomains
    print("[4/17] Merging subdomains...")
    merge_files([subfinder_out, shuffledns_out, alterx_out], merged_out, dry_run)

    # Step 5: Naabu port scan
    print("[5/17] Running naabu...")
    if os.path.isfile(merged_out):
        run_cmd([
            "naabu", "-l", merged_out,
            "-rate", naabu_rate,
            "-silent"
        ], stdout_file=naabu_out, dry_run=dry_run)

    # Step 6: Httpx
    print("[6/17] Running httpx...")
    input_file = naabu_out if os.path.isfile(naabu_out) else merged_out
    if os.path.isfile(input_file):
        run_cmd([
            "httpx", "-l", input_file,
            "-silent",
            "-title",
            "-status-code",
            "-tech-detect"
        ], stdout_file=httpx_out, dry_run=dry_run)

    # Step 7: Extract URLs from httpx
    print("[7/17] Extracting URLs from httpx...")
    extract_urls_from_httpx(httpx_out, httpx_urls, dry_run)

    # Step 8: Nuclei on live hosts
    print("[8/17] Running nuclei on live hosts...")
    if os.path.isfile(httpx_urls):
        run_cmd([
            "nuclei", "-l", httpx_urls,
            "-t", "~/nuclei-templates/",
            "-jsonl",
            "-silent"
        ], stdout_file=nuclei_out, dry_run=dry_run)

    # Step 9: Katana basic crawling
    print("[9/17] Running katana (basic)...")
    if os.path.isfile(httpx_urls):
        run_cmd([
            "katana", "-list", httpx_urls,
            "-d", "3",
            "-silent"
        ], stdout_file=katana_basic_out, dry_run=dry_run)

    # Step 10: Katana deep crawling
    print("[10/17] Running katana (deep)...")
    if os.path.isfile(httpx_urls):
        run_cmd([
            "katana", "-list", httpx_urls,
            "-d", "5",
            "-js-crawl",
            "-headless",
            "-silent"
        ], stdout_file=katana_deep_out, dry_run=dry_run)

    # Step 11: Merge katana results
    print("[11/17] Merging katana results...")
    merge_files([katana_basic_out, katana_deep_out], katana_merged_out, dry_run)

    # Step 12: Nuclei on katana URLs
    print("[12/17] Running nuclei on katana URLs...")
    if os.path.isfile(katana_merged_out):
        run_cmd([
            "nuclei", "-l", katana_merged_out,
            "-t", "~/nuclei-templates/",
            "-jsonl",
            "-silent"
        ], stdout_file=nuclei_katana_out, dry_run=dry_run)

    # Step 13: Urlfinder
    print("[13/17] Running urlfinder...")
    run_cmd([
        "urlfinder", "-d", domain,
        "-s"
    ], stdout_file=urlfinder_out, dry_run=dry_run)

    # Step 14: GAU
    print("[14/17] Running gau...")
    run_cmd([
        "gau", domain
    ], stdout_file=gau_out, dry_run=dry_run)

    # Step 15: Waybackurls
    print("[15/17] Running waybackurls...")
    run_cmd([
        "waybackurls", domain
    ], stdout_file=waybackurls_out, dry_run=dry_run)

    # Step 16: Merge all URLs
    print("[16/17] Merging all URLs...")
    url_files = []
    if os.path.isfile(katana_merged_out):
        url_files.append(katana_merged_out)
    if os.path.isfile(urlfinder_out):
        url_files.append(urlfinder_out)
    if os.path.isfile(gau_out):
        url_files.append(gau_out)
    if os.path.isfile(waybackurls_out):
        url_files.append(waybackurls_out)
    
    if url_files:
        merge_files(url_files, all_urls_out, dry_run)

    # Step 17: Final nuclei scan on all URLs
    print("[17/17] Running nuclei on all URLs...")
    if os.path.isfile(all_urls_out):
        run_cmd([
            "nuclei", "-l", all_urls_out,
            "-t", "~/nuclei-templates/",
            "-jsonl",
            "-silent"
        ], stdout_file=nuclei_all_out, dry_run=dry_run)

    # Step 18: Generate summary CSV
    print("[18/21] Generating summary CSV...")
    summary = generate_summary_csv(domain, domain_dir, safe)

    # Step 19: Send main notification
    print("[19/21] Sending main notification...")
    notify_results(summary, domain_dir, safe, enable_notify)
    
    # Step 20: Send detailed nuclei findings if any
    print("[20/21] Sending nuclei findings notification...")
    send_nuclei_findings_notification(domain_dir, safe, enable_notify)

    # Step 21: Append to overall summary CSV
    print("[21/21] Updating overall summary...")
    append_overall_summary(base_results_dir, summary)

    print(f"[+] Done {domain}: outputs in {domain_dir}")

def main():
    parser = argparse.ArgumentParser(description="Full bug bounty pipeline v5")
    parser.add_argument("--domains", "-D", required=True, help="File containing domains to scan")
    parser.add_argument("--wordlist", "-w", required=True, help="Wordlist file for subdomain enumeration")
    parser.add_argument("--resolvers", "-r", required=True, help="DNS resolvers file")
    parser.add_argument("--notify", action="store_true", help="Enable notifications via notify tool (uses: notify -data file.txt -bulk -provider discord)")
    parser.add_argument("--results-dir", default="results", help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing")
    parser.add_argument("--skip-validation", action="store_true", help="Skip input file validation and tool checks")
    parser.add_argument("--subfinder-threads", default="50", help="Subfinder thread count")
    parser.add_argument("--shuffledns-threads", default="500", help="ShuffleDNS thread count")
    parser.add_argument("--naabu-rate", default="500", help="Naabu rate limit")
    args = parser.parse_args()

    # Validate input files and check tools (unless skipped)
    if not args.skip_validation:
        if not validate_input_files(args.wordlist, args.resolvers):
            sys.exit(1)
        if not check_required_tools():
            print("[!] Install missing tools or use --skip-validation to continue anyway")
            sys.exit(1)

    # Validate input files
    for path in (args.domains, args.wordlist, args.resolvers):
        if not os.path.isfile(path):
            print(f"[!] Missing input file: {path}", file=sys.stderr)
            sys.exit(1)

    ensure_dir(args.results_dir)

    # Load domains
    try:
        with open(args.domains, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[!] Failed to read domains file: {e}", file=sys.stderr)
        sys.exit(1)

    if not domains:
        print("[!] No domains found in file", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loaded {len(domains)} domains. Results → {args.results_dir}")
    if args.dry_run:
        print("[!] Dry-run mode active")
    if args.notify:
        print("[+] Notifications enabled (using: notify -data file.txt -bulk -provider discord)")

    successful_domains = 0

    # Process each domain
    for i, domain in enumerate(domains, 1):
        print(f"\n[+] Processing domain {i}/{len(domains)}: {domain}")
        try:
            process_domain(
                domain,
                args.results_dir,
                args.wordlist,
                args.resolvers,
                dry_run=args.dry_run,
                subfinder_threads=args.subfinder_threads,
                shuffledns_threads=args.shuffledns_threads,
                naabu_rate=args.naabu_rate,
                enable_notify=args.notify
            )
            successful_domains += 1
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            sys.exit(1)
        except Exception as e:
            import traceback
            print(f"[!] Error processing {domain}: {e}")
            print(f"[!] Full traceback:")
            traceback.print_exc()
            print(f"[!] Continuing with next domain...")
            continue

    print(f"\n[+] All domains processed. Results in {args.results_dir}")
    
    # Send final summary notification
    if args.notify:
        send_final_summary_notification(args.results_dir, len(domains), successful_domains, args.notify)
        
    print(f"[+] Pipeline complete: {successful_domains}/{len(domains)} domains processed successfully")

if __name__ == "__main__":
    main()
