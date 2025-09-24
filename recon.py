#!/usr/bin/env python3
"""
bugbounty_pipeline_full_v6.py

Full bug bounty pipeline:
subfinder -> shuffledns -> alterx -> merge -> naabu -> httpx -> nuclei -> 
katana -> merge katana -> nuclei(katana) -> urlfinder -> gau -> waybackurls -> merge all URLs -> nuclei(all URLs)
+ per-domain summary CSV + Discord notifications + overall summary CSV

Fixed issues:
- Nuclei template path resolution
- Better error handling
- Improved timeout management
- Enhanced validation
"""

import os
import argparse
import subprocess
import shlex
import sys
import csv
import json
import time
from pathlib import Path

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

def get_nuclei_templates_path():
    """Find and return the correct nuclei templates path"""
    possible_paths = [
        # Standard installation paths
        os.path.expanduser("~/nuclei-templates"),
        "/usr/local/share/nuclei-templates",
        "/opt/nuclei-templates",
        # Check if nuclei can find templates automatically
        None  # Let nuclei use default path
    ]
    
    for path in possible_paths[:-1]:  # Skip None for now
        if path and os.path.isdir(path):
            template_count = sum(1 for f in Path(path).rglob("*.yaml") if f.is_file())
            if template_count > 0:
                print(f"[+] Found {template_count} nuclei templates in {path}")
                return path
    
    # Try to update templates first
    print("[+] Attempting to update nuclei templates...")
    try:
        result = subprocess.run(["nuclei", "-update-templates"], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            # Try again after update
            for path in possible_paths[:-1]:
                if path and os.path.isdir(path):
                    template_count = sum(1 for f in Path(path).rglob("*.yaml") if f.is_file())
                    if template_count > 0:
                        print(f"[+] Found {template_count} nuclei templates in {path}")
                        return path
        else:
            print(f"[!] Template update failed: {result.stderr}")
    except Exception as e:
        print(f"[!] Could not update templates: {e}")
    
    # Fall back to letting nuclei handle it
    print("[+] Using nuclei default template resolution")
    return None

def check_required_tools():
    """Check if required tools are installed"""
    required_tools = [
        'subfinder', 'shuffledns', 'alterx', 'naabu', 
        'httpx', 'nuclei', 'katana', 'urlfinder', 'gau', 'waybackurls', 'unfurl'
    ]
    
    python_tools = ['paramspider', 'arjun']
    
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
                    else:
                        print(f"[+] {tool}: installed")
                else:
                    print(f"[+] {tool}: installed")
            else:
                print(f"[+] {tool}: installed")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing_tools.append(tool)
    
    # Check Python tools
    for tool in python_tools:
        try:
            result = subprocess.run([tool, '--help'], capture_output=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] {tool}: installed")
            else:
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
            elif tool == 'unfurl':
                print(f"   go install github.com/tomnomnom/unfurl@latest")
            elif tool == 'paramspider':
                print(f"   pip3 install paramspider")
            elif tool == 'arjun':
                print(f"   pip3 install arjun")
            else:
                print(f"   go install -v github.com/projectdiscovery/{tool}/cmd/{tool}@latest")
        return False
    
    print("[+] All required tools are installed")
    return True

def run_cmd(cmd, stdout_file=None, stderr_file=None, dry_run=False, timeout=600):
    """Run command with improved error handling and timeout management"""
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
            
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, stdout=stdout_handle, stderr=stderr_handle, timeout=timeout)
            elapsed = time.time() - start_time
            
            if result.returncode != 0:
                print(f"[!] Command failed (rc={result.returncode}) after {elapsed:.1f}s: {cmd[0]}")
                # For debugging, let's also capture stderr when command fails
                if not stderr_file:
                    try:
                        debug_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        if debug_result.stderr:
                            print(f"[!] Error details: {debug_result.stderr.strip()}")
                    except:
                        pass
                return result.returncode
            else:
                print(f"[+] Command completed successfully in {elapsed:.1f}s")
            return 0
            
        finally:
            # Close file handles if they were opened
            if stdout_file and stdout_handle != subprocess.DEVNULL:
                stdout_handle.close()
            if stderr_file and stderr_handle != subprocess.DEVNULL:
                stderr_handle.close()
                
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout} seconds: {' '.join(cmd)}")
        return 124
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed (rc={e.returncode}): {' '.join(cmd)}")
        return e.returncode
    except FileNotFoundError:
        print(f"[!] Tool not installed: {cmd[0]}")
        tool = cmd[0]
        if tool == 'gau':
            print(f"[!] Install with: go install github.com/lc/gau/v2/cmd/gau@latest")
        elif tool == 'waybackurls':
            print(f"[!] Install with: go install github.com/tomnomnom/waybackurls@latest")
        elif tool == 'urlfinder':
            print(f"[!] Install with: go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest")
        else:
            print(f"[!] Install with: go install -v github.com/projectdiscovery/{tool}/cmd/{tool}@latest")
        return 127
    except Exception as e:
        print(f"[!] Unexpected error running command: {e}")
        return 1

def merge_files(inputs, output, dry_run=False):
    seen = set()
    results = []
    total_processed = 0
    
    for path in inputs:
        if os.path.isfile(path):
            file_count = 0
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in seen:
                            seen.add(line)
                            results.append(line)
                            file_count += 1
                        total_processed += 1
                print(f"[+] Processed {file_count} unique lines from {os.path.basename(path)}")
            except Exception as e:
                print(f"[!] Error reading {path}: {e}")
        else:
            print(f"[!] File not found: {path}")
    
    if not dry_run and results:
        try:
            with open(output, "w", encoding="utf-8") as out:
                out.write("\n".join(results) + "\n")
        except Exception as e:
            print(f"[!] Error writing to {output}: {e}")
            return None
    
    print(f"[+] Merged {len(results)} unique lines from {total_processed} total → {output}")
    return output

def extract_parameters_from_urls(urls_file, params_out_path, dry_run=False):
    """Extract parameters from URLs using multiple methods"""
    if dry_run:
        print(f"[DRY-RUN] would extract parameters from {urls_file} -> {params_out_path}")
        return params_out_path

    if not os.path.isfile(urls_file):
        print(f"[!] URLs file not found: {urls_file}")
        return None

    params_set = set()
    
    # Method 1: Use unfurl to extract parameters
    print("[+] Extracting parameters with unfurl...")
    try:
        cmd = f"cat {shlex.quote(urls_file)} | unfurl --unique keys"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    params_set.add(line.strip())
    except Exception as e:
        print(f"[!] Unfurl extraction failed: {e}")

    # Method 2: Manual parameter extraction from URLs
    print("[+] Manual parameter extraction...")
    try:
        with open(urls_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if '?' in url:
                    query_part = url.split('?', 1)[1]
                    # Handle fragments
                    if '#' in query_part:
                        query_part = query_part.split('#')[0]
                    
                    # Extract parameter names
                    for param_pair in query_part.split('&'):
                        if '=' in param_pair:
                            param_name = param_pair.split('=')[0]
                            if param_name:
                                params_set.add(param_name)
    except Exception as e:
        print(f"[!] Manual parameter extraction failed: {e}")

    # Write results
    if params_set:
        try:
            with open(params_out_path, 'w', encoding='utf-8') as out:
                sorted_params = sorted(list(params_set))
                out.write('\n'.join(sorted_params) + '\n')
            print(f"[+] Extracted {len(params_set)} unique parameters -> {params_out_path}")
            return params_out_path
        except Exception as e:
            print(f"[!] Error writing parameters: {e}")
            return None
    else:
        print(f"[!] No parameters extracted from {urls_file}")
        return None

def create_fuzz_endpoints(urls_file, params_file, fuzz_endpoints_out, dry_run=False):
    """Create fuzz endpoints by combining URLs with extracted parameters"""
    if dry_run:
        print(f"[DRY-RUN] would create fuzz endpoints from {urls_file} + {params_file} -> {fuzz_endpoints_out}")
        return fuzz_endpoints_out

    if not os.path.isfile(urls_file):
        print(f"[!] URLs file not found: {urls_file}")
        return None
    
    if not os.path.isfile(params_file):
        print(f"[!] Parameters file not found: {params_file}")
        return None

    fuzz_endpoints = set()
    
    try:
        # Load parameters
        with open(params_file, 'r', encoding='utf-8', errors='ignore') as f:
            parameters = [line.strip() for line in f if line.strip()]
        
        if not parameters:
            print(f"[!] No parameters found in {params_file}")
            return None

        # Load URLs
        with open(urls_file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"[+] Creating fuzz endpoints from {len(urls)} URLs and {len(parameters)} parameters...")

        for url in urls:
            # Skip URLs that already have parameters to avoid duplication
            base_url = url.split('?')[0]
            
            # Create endpoints with single parameters
            for param in parameters:
                # Basic parameter injection
                fuzz_url = f"{base_url}?{param}=FUZZ"
                fuzz_endpoints.add(fuzz_url)
                
                # Add common parameter combinations for APIs
                if any(api_indicator in base_url.lower() for api_indicator in ['/api/', '/v1/', '/v2/', '/graphql', '/rest']):
                    # API-specific parameter patterns
                    fuzz_endpoints.add(f"{base_url}?{param}=1&debug=true")
                    fuzz_endpoints.add(f"{base_url}?{param}={{{{FUZZ}}}}")  # Template injection
                    fuzz_endpoints.add(f"{base_url}?{param}[]={{{{FUZZ}}}}")  # Array parameter
                
                # Add path-based parameter injection
                if base_url.endswith('/'):
                    fuzz_endpoints.add(f"{base_url}?{param}=../../../etc/passwd")
                    fuzz_endpoints.add(f"{base_url}?{param}=http://{{{{interactsh-url}}}}")

        # Write fuzz endpoints
        if fuzz_endpoints:
            with open(fuzz_endpoints_out, 'w', encoding='utf-8') as out:
                sorted_endpoints = sorted(list(fuzz_endpoints))
                out.write('\n'.join(sorted_endpoints) + '\n')
            
            print(f"[+] Created {len(fuzz_endpoints)} fuzz endpoints -> {fuzz_endpoints_out}")
            return fuzz_endpoints_out
        else:
            print(f"[!] No fuzz endpoints generated")
            return None
            
    except Exception as e:
        print(f"[!] Error creating fuzz endpoints: {e}")
        return None

def create_parameter_wordlist(params_file, param_wordlist_out, dry_run=False):
    """Create a comprehensive parameter wordlist for additional fuzzing"""
    if dry_run:
        print(f"[DRY-RUN] would create parameter wordlist from {params_file} -> {param_wordlist_out}")
        return param_wordlist_out

    if not os.path.isfile(params_file):
        print(f"[!] Parameters file not found: {params_file}")
        return None

    try:
        # Load discovered parameters
        with open(params_file, 'r', encoding='utf-8', errors='ignore') as f:
            discovered_params = set(line.strip() for line in f if line.strip())

        # Common parameter patterns based on discovered ones
        extended_params = set(discovered_params)
        
        # Generate variations of discovered parameters
        for param in discovered_params:
            # Add common variations
            variations = [
                f"{param}[]",           # Array parameter
                f"{param}_id",          # ID variation
                f"{param}Id",           # CamelCase ID
                f"{param}_name",        # Name variation
                f"{param}Name",         # CamelCase name
                f"get_{param}",         # Method prefix
                f"set_{param}",         # Setter prefix
                f"{param}_list",        # List variation
                f"{param}List",         # CamelCase list
                f"old_{param}",         # Old value
                f"new_{param}",         # New value
                f"{param}_backup",      # Backup variation
                f"{param}_tmp",         # Temporary variation
                f"admin_{param}",       # Admin variation
                f"debug_{param}",       # Debug variation
            ]
            extended_params.update(variations)

        # Add common security-related parameters
        security_params = {
            "debug", "test", "admin", "dev", "development", "staging", "prod", "production",
            "callback", "redirect", "return", "url", "link", "path", "file", "dir", "directory",
            "cmd", "command", "exec", "system", "shell", "eval", "include", "require",
            "user", "username", "email", "pass", "password", "token", "key", "secret",
            "api_key", "access_token", "auth", "authorization", "session", "sid",
            "format", "output", "type", "method", "action", "function", "mode",
            "lang", "language", "locale", "country", "region", "timezone",
            "limit", "offset", "page", "size", "count", "max", "min",
            "sort", "order", "filter", "search", "query", "q", "term",
            "version", "v", "api_version", "format", "output_format"
        }
        extended_params.update(security_params)

        # Write extended parameter wordlist
        if extended_params:
            with open(param_wordlist_out, 'w', encoding='utf-8') as out:
                sorted_params = sorted(list(extended_params))
                out.write('\n'.join(sorted_params) + '\n')
            
            print(f"[+] Created extended parameter wordlist with {len(extended_params)} parameters -> {param_wordlist_out}")
            return param_wordlist_out
        else:
            print(f"[!] No parameters to write")
            return None
            
    except Exception as e:
        print(f"[!] Error creating parameter wordlist: {e}")
        return None
    """Run ParamSpider for advanced parameter discovery"""
    if dry_run:
        print(f"[DRY-RUN] would run paramspider on {domain} -> {paramspider_out_path}")
        return paramspider_out_path
    
    try:
        # ParamSpider saves to results/ directory by default
        result = subprocess.run([
            "paramspider", "-d", domain, "--level", "high"
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            # ParamSpider creates files in results/ directory
            paramspider_result_file = f"results/{domain}.txt"
            if os.path.isfile(paramspider_result_file):
                # Move to our desired location
                import shutil
                shutil.move(paramspider_result_file, paramspider_out_path)
                print(f"[+] ParamSpider completed -> {paramspider_out_path}")
                return paramspider_out_path
            else:
                print(f"[!] ParamSpider output not found")
                return None
        else:
            print(f"[!] ParamSpider failed: {result.stderr}")
            return None
    except FileNotFoundError:
        print("[!] ParamSpider not found. Install: pip3 install paramspider")
        return None
    except Exception as e:
        print(f"[!] ParamSpider error: {e}")
        return None
    if dry_run:
        print(f"[DRY-RUN] would extract URLs from {httpx_path} -> {urls_out_path}")
        return urls_out_path

    if not os.path.isfile(httpx_path):
        print(f"[!] httpx input not found: {httpx_path}")
        return None

    seen = set()
    extracted = []
    
    try:
        with open(httpx_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                ln = raw.strip()
                if not ln:
                    continue
                    
                # Look for URLs in the line
                words = ln.split()
                for word in words:
                    if word.startswith(("http://", "https://")):
                        # Clean the URL (remove trailing punctuation, etc.)
                        url = word.rstrip('.,;:)')
                        if url not in seen:
                            seen.add(url)
                            extracted.append(url)
                        break
                        
    except Exception as e:
        print(f"[!] Error processing httpx output: {e}")
        return None
        
    if extracted:
        try:
            with open(urls_out_path, "w", encoding="utf-8") as out:
                out.write("\n".join(extracted) + "\n")
            print(f"[+] Extracted {len(extracted)} URLs → {urls_out_path}")
            return urls_out_path
        except Exception as e:
            print(f"[!] Error writing URLs: {e}")
            return None
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
        "parameters": count_lines(os.path.join(domain_dir, f"parameters_{safe}.txt")),
        "paramspider_urls": count_lines(os.path.join(domain_dir, f"paramspider_{safe}.txt")),
        "fuzz_endpoints": count_lines(os.path.join(domain_dir, f"fuzz_endpoints_{safe}.txt")),
        "nuclei_findings": count_nuclei(os.path.join(domain_dir, f"nuclei_all_{safe}.json")),
        "nuclei_dast_findings": count_nuclei(os.path.join(domain_dir, f"nuclei_dast_{safe}.json"))
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
            f.write(f"🕐 Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
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
            f.write(f"🕐 Pipeline completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
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
                   shuffledns_threads="500", naabu_rate="500", 
                   enable_notify=False, nuclei_templates_path=None):
    domain = domain.strip()
    if not domain:
        print("[!] Empty domain name, skipping...")
        return False

    # Validate domain format
    if not domain.replace(".", "").replace("-", "").replace("_", "").isalnum():
        print(f"[!] Invalid domain format: {domain}")
        return False

    safe = sanitize_filename(domain)
    domain_dir = os.path.join(base_results_dir, safe)
    
    try:
        ensure_dir(domain_dir)
    except Exception as e:
        print(f"[!] Failed to create directory {domain_dir}: {e}")
        return False

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
    parameters_out = os.path.join(domain_dir, f"parameters_{safe}.txt")
    paramspider_out = os.path.join(domain_dir, f"paramspider_{safe}.txt")
    fuzz_endpoints_out = os.path.join(domain_dir, f"fuzz_endpoints_{safe}.txt")
    param_wordlist_out = os.path.join(domain_dir, f"param_wordlist_{safe}.txt")
    nuclei_all_out = os.path.join(domain_dir, f"nuclei_all_{safe}.json")
    nuclei_dast_out = os.path.join(domain_dir, f"nuclei_dast_{safe}.json")

    print(f"\n[+] === Processing {domain} ===")

    # Step 1: Subfinder
    print("[1/17] Running subfinder...")
    if run_cmd([
        "subfinder", "-d", domain,
        "-t", subfinder_threads,
        "-silent"
    ], stdout_file=subfinder_out, dry_run=dry_run) != 0:
        print(f"[!] Subfinder failed for {domain}")

    # Step 2: ShuffleDNS
    print("[2/17] Running shuffledns...")
    if run_cmd([
        "shuffledns", "-d", domain,
        "-w", wordlist,
        "-r", resolvers,
        "-t", shuffledns_threads,
        "-mode", "bruteforce",
        "-silent"
    ], stdout_file=shuffledns_out, dry_run=dry_run, timeout=1200) != 0:
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
        ], stdout_file=naabu_out, dry_run=dry_run, timeout=1800)

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
        ], stdout_file=httpx_out, dry_run=dry_run, timeout=900)

    # Step 7: Extract URLs from httpx
    print("[7/17] Extracting URLs from httpx...")
    extract_urls_from_httpx(httpx_out, httpx_urls, dry_run)

    # Step 8: Nuclei on live hosts
    print("[8/17] Running nuclei on live hosts...")
    if os.path.isfile(httpx_urls):
        nuclei_cmd = ["nuclei", "-l", httpx_urls, "-jsonl", "-silent"]
        if nuclei_templates_path:
            nuclei_cmd.extend(["-t", nuclei_templates_path])
        run_cmd(nuclei_cmd, stdout_file=nuclei_out, dry_run=dry_run, timeout=1800)

    # Step 9: Katana basic crawling
    print("[9/17] Running katana (basic)...")
    if os.path.isfile(httpx_urls):
        run_cmd([
            "katana", "-list", httpx_urls,
            "-d", "3",
            "-silent"
        ], stdout_file=katana_basic_out, dry_run=dry_run, timeout=1200)

    # Step 10: Katana deep crawling
    print("[10/17] Running katana (deep)...")
    if os.path.isfile(httpx_urls):
        run_cmd([
            "katana", "-list", httpx_urls,
            "-d", "5",
            "-js-crawl",
            "-headless",
            "-silent"
        ], stdout_file=katana_deep_out, dry_run=dry_run, timeout=1800)

    # Step 11: Merge katana results
    print("[11/17] Merging katana results...")
    merge_files([katana_basic_out, katana_deep_out], katana_merged_out, dry_run)

    # Step 12: Nuclei on katana URLs
    print("[12/17] Running nuclei on katana URLs...")
    if os.path.isfile(katana_merged_out):
        nuclei_cmd = ["nuclei", "-l", katana_merged_out, "-jsonl", "-silent"]
        if nuclei_templates_path:
            nuclei_cmd.extend(["-t", nuclei_templates_path])
        run_cmd(nuclei_cmd, stdout_file=nuclei_katana_out, dry_run=dry_run, timeout=1800)

    # Step 13: Urlfinder
    print("[13/17] Running urlfinder...")
    run_cmd([
        "urlfinder", "-d", domain,
        "-s"
    ], stdout_file=urlfinder_out, dry_run=dry_run, timeout=600)

    # Step 14: GAU
    print("[14/17] Running gau...")
    run_cmd([
        "gau", domain
    ], stdout_file=gau_out, dry_run=dry_run, timeout=600)

    # Step 15: Waybackurls
    print("[15/17] Running waybackurls...")
    run_cmd([
        "waybackurls", domain
    ], stdout_file=waybackurls_out, dry_run=dry_run, timeout=600)

    # Step 16: Merge all URLs
    print("[16/19] Merging all URLs...")
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

    # Step 17: Extract parameters from all URLs
    print("[17/19] Extracting parameters from URLs...")
    if os.path.isfile(all_urls_out):
        extract_parameters_from_urls(all_urls_out, parameters_out, dry_run)

    # Step 18: Run ParamSpider for additional parameter discovery
    print("[18/22] Running ParamSpider for advanced parameter discovery...")
    run_paramspider(domain, paramspider_out, dry_run)

    # Step 19: Create fuzz endpoints for DAST scanning
    print("[19/22] Creating fuzz endpoints for DAST scanning...")
    if os.path.isfile(all_urls_out) and os.path.isfile(parameters_out):
        create_fuzz_endpoints(all_urls_out, parameters_out, fuzz_endpoints_out, dry_run)

    # Step 20: Create extended parameter wordlist
    print("[20/22] Creating extended parameter wordlist...")
    if os.path.isfile(parameters_out):
        create_parameter_wordlist(parameters_out, param_wordlist_out, dry_run)

    # Step 21: Nuclei DAST scan on fuzz endpoints
    print("[21/22] Running nuclei DAST scan on fuzz endpoints...")
    if os.path.isfile(fuzz_endpoints_out):
        nuclei_dast_cmd = ["nuclei", "-list", fuzz_endpoints_out, "-dast", "-jsonl", "-silent"]
        if nuclei_templates_path:
            nuclei_dast_cmd.extend(["-t", nuclei_templates_path])
        # Add interactsh for OOB testing
        nuclei_dast_cmd.extend(["-interactsh"])
        run_cmd(nuclei_dast_cmd, stdout_file=nuclei_dast_out, dry_run=dry_run, timeout=7200)  # 2 hours for DAST

    # Step 22: Final nuclei scan on all URLs (traditional scan)
    print("[22/22] Running nuclei traditional scan on all URLs...")
    if os.path.isfile(all_urls_out):
        nuclei_cmd = ["nuclei", "-l", all_urls_out, "-jsonl", "-silent"]
        if nuclei_templates_path:
            nuclei_cmd.extend(["-t", nuclei_templates_path])
        run_cmd(nuclei_cmd, stdout_file=nuclei_all_out, dry_run=dry_run, timeout=3600)

    # Step 23: Generate summary CSV
    print("[23/26] Generating summary CSV...")
    summary = generate_summary_csv(domain, domain_dir, safe)

    # Step 24: Send main notification
    print("[24/26] Sending main notification...")
    notify_results(summary, domain_dir, safe, enable_notify)
    
    # Step 25: Send detailed nuclei findings if any
    print("[25/26] Sending nuclei findings notification...")
    send_nuclei_findings_notification(domain_dir, safe, enable_notify)

    # Step 26: Append to overall summary CSV
    print("[26/26] Updating overall summary...")
    append_overall_summary(base_results_dir, summary)

    print(f"[+] Done {domain}: outputs in {domain_dir}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Full bug bounty pipeline v6 - Fixed version")
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
    parser.add_argument("--nuclei-templates", help="Custom nuclei templates path (auto-detected if not provided)")
    args = parser.parse_args()

    print("=" * 70)
    print("Bug Bounty Reconnaissance Pipeline v6 - Fixed")
    print("=" * 70)

    # Find nuclei templates path
    nuclei_templates_path = args.nuclei_templates or get_nuclei_templates_path()
    if nuclei_templates_path:
        print(f"[+] Using nuclei templates: {nuclei_templates_path}")
    else:
        print("[+] Using nuclei default template resolution")

    # Validate input files and check tools (unless skipped)
    if not args.skip_validation:
        print("\n[+] Validating environment...")
        if not validate_input_files(args.wordlist, args.resolvers):
            sys.exit(1)
        if not check_required_tools():
            print("[!] Install missing tools or use --skip-validation to continue anyway")
            sys.exit(1)
    else:
        print("[!] Skipping validation as requested")

    # Validate input files exist
    for path in (args.domains, args.wordlist, args.resolvers):
        if not os.path.isfile(path):
            print(f"[!] Missing input file: {path}")
            sys.exit(1)

    ensure_dir(args.results_dir)

    # Load domains
    try:
        with open(args.domains, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[!] Failed to read domains file: {e}")
        sys.exit(1)

    if not domains:
        print("[!] No domains found in file")
        sys.exit(1)

    print(f"\n[+] Configuration:")
    print(f"    Domains: {len(domains)} loaded from {args.domains}")
    print(f"    Results: {args.results_dir}")
    print(f"    Wordlist: {args.wordlist}")
    print(f"    Resolvers: {args.resolvers}")
    print(f"    Notifications: {'Enabled' if args.notify else 'Disabled'}")
    print(f"    Dry-run: {'Yes' if args.dry_run else 'No'}")
    
    if args.dry_run:
        print("\n[!] DRY-RUN MODE: Commands will be shown but not executed")
    if args.notify:
        print("[+] Notifications enabled (Discord via notify tool)")

    successful_domains = 0
    start_time = time.time()

    # Process each domain
    for i, domain in enumerate(domains, 1):
        print(f"\n{'='*70}")
        print(f"Processing domain {i}/{len(domains)}: {domain}")
        print(f"{'='*70}")
        
        domain_start = time.time()
        
        try:
            success = process_domain(
                domain,
                args.results_dir,
                args.wordlist,
                args.resolvers,
                dry_run=args.dry_run,
                subfinder_threads=args.subfinder_threads,
                shuffledns_threads=args.shuffledns_threads,
                naabu_rate=args.naabu_rate,
                enable_notify=args.notify,
                nuclei_templates_path=nuclei_templates_path
            )
            
            domain_elapsed = time.time() - domain_start
            
            if success:
                successful_domains += 1
                print(f"[+] Domain {domain} completed successfully in {domain_elapsed/60:.1f} minutes")
            else:
                print(f"[!] Domain {domain} failed after {domain_elapsed/60:.1f} minutes")
                
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            import traceback
            domain_elapsed = time.time() - domain_start
            print(f"[!] Error processing {domain} after {domain_elapsed/60:.1f} minutes: {e}")
            print(f"[!] Full traceback:")
            traceback.print_exc()
            print(f"[!] Continuing with next domain...")
            continue

    total_elapsed = time.time() - start_time
    
    print(f"\n{'='*70}")
    print("PIPELINE COMPLETE")
    print(f"{'='*70}")
    print(f"Total time: {total_elapsed/60:.1f} minutes")
    print(f"Domains processed: {successful_domains}/{len(domains)}")
    print(f"Success rate: {(successful_domains/len(domains)*100):.1f}%")
    print(f"Results directory: {args.results_dir}")
    print(f"Overall summary: {os.path.join(args.results_dir, 'summary_all_domains.csv')}")
    
    # Send final summary notification
    if args.notify:
        print("[+] Sending final summary notification...")
        send_final_summary_notification(args.results_dir, len(domains), successful_domains, args.notify)
    
    if successful_domains == len(domains):
        print("\n🎉 All domains processed successfully!")
    elif successful_domains > 0:
        print(f"\n⚠️  {len(domains) - successful_domains} domains failed, but {successful_domains} completed successfully")
    else:
        print("\n❌ All domains failed to process")

if __name__ == "__main__":
    main()
