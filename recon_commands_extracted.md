# Extracted Recon Commands — Project Discovery Video

This file contains a cleaned, deduplicated, and grouped collection of CLI commands and oneliners referenced in the video. Replace placeholders like `example.com`, `domains.txt`, and API keys with your target/test values. **Do not run destructive scans against targets you do not own or have explicit permission to test.**

---

## System & environment setup

```bash
# update & install basics (Ubuntu)
sudo apt update && sudo apt upgrade -y
sudo apt install -y zsh curl wget git build-essential

# install Oh My Zsh (official installer)
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# install Go (example installer - adjust version as needed)
wget https://go.dev/dl/go1.21.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.4.linux-amd64.tar.gz

# export GOPATH and add to PATH (append to ~/.bashrc or ~/.zshrc)
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
# then reload
source ~/.bashrc   # or `source ~/.zshrc`
```

---

## Project Discovery toolkit & Go-based tools

```bash
# toolkit manager (example usage)
toolkit -h
toolkit -i subfinder          # install single: subfinder
toolkit -i subfinder,nuclei   # install multiple via comma
toolkit -IA /path/to/install  # install all (speaker: -IA + install path)

# individual installs via 'go install'
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/shuffledns@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
# ...and other PD tools like nabuu, alterx etc.
```

---

## Installing native dependencies

```bash
# nmap
sudo apt install -y nmap

# massdns from git + build
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo cp bin/massdns /usr/local/bin/

# if `make` missing -> install build-essentials
sudo apt install -y build-essential
```

---

## Resolver wordlists & wget examples

```bash
# download a public resolvers list
wget https://raw.githubusercontent.com/projectdiscovery/public-resolvers/master/resolvers.txt -O resolvers.txt

# fetch a wordlist from GitHub
wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains-top1million-5000.txt -O wordlist.txt
```

---

## Subdomain discovery & permutation

```bash
# subfinder basic
subfinder -d example.com -o subdomains_raw.txt

# subfinder with all providers
subfinder -d example.com -all -o subdomains_all.txt

# shuffledns (brute forcing using wordlist + resolvers)
shuffledns -d example.com -w wordlist.txt -r resolvers.txt -m brute -o domains.txt

# alterx (permutations - example / pseudo)
alterx -l domains.txt -w permutations_wordlist.txt -o permutations.txt

# append results to a file using tee
echo "some-domain.example" | tee -a subdomains_dnsx.txt
```

---

## DNS resolution & filtering (dnsx)

```bash
# verify which hostnames resolve
cat domains.txt | dnsx -a -resp -o resolved.txt

# alternative patterns
dnsx -l domains.txt -a -resp -o dnsx_out.txt
```

---

## Port / host discovery (Naboo examples)

```bash
# install nabuu (example)
go install github.com/projectdiscovery/nabuu/cmd/nabuu@latest

# run nabuu (example flags, adapt to tool)
nabuu -l resolved.txt -p top-100 -e 22 -o open_ports.txt

# fallback: nmap quick scan
nmap -iL resolved.txt -T4 -Pn -p- -oA nmap_fullscan
```

---

## HTTP probing & enrichment (httpx)

```bash
# httpx examples
cat open_ports.txt | httpx -title -status-code -content-length -silent -o httpx.txt

# follow redirects and include location
cat open_ports.txt | httpx -fr -location -o httpx_follow.txt

# explicit usage
httpx -l open_ports.txt -status-code -title -content-type -content-length -o httpx_results.txt
```

---

## Crawling & JS parsing (Katana)

```bash
# simple crawl
katana -u https://example.com -o katana_urls.txt

# enable JS parsing
katana -u https://example.com -jc -o katana_jc.txt
katana -u https://example.com -jsl -o katana_jsl.txt

# authenticated crawl: pass Cookie header
katana -u https://example.com -H "Cookie: SESSION=<your_session_cookie>" -xhr -jc -jsl -aff -o katana_auth.txt
```

---

## Pipe examples (combining tools)

```bash
# pipeline example: subfinder -> alterx -> dnsx -> nabuu -> httpx
subfinder -d example.com -all | alterx | dnsx -a | nabuu -l - -p top-100 | httpx -title -status-code > httpx.txt

# simpler pipeline
cat domains.txt | alterx | dnsx | nabuu -l - | httpx -title -status-code > info_gathering.txt
```

---

## Mass-URL / passive sources (urlfinder)

```bash
# urlfinder example
urlfinder -d paypal.com --silent | httpx -status-code -o urlfinder_httpx.txt
```

---

## Misc / housekeeping

```bash
# show help
subfinder -h

# count lines
wc -l domains.txt

# view files
cat domains.txt
cat open_ports.txt
```

---

## Build & clone examples (massdns)

```bash
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo cp bin/massdns /usr/local/bin/
```

---

## Short notes
- Replace placeholders (`example.com`, `domains.txt`, `resolved.txt`) with your values.
- Verify exact flags with each tool's `-h` or documentation; some flags vary by version.
- **Always** run scans only against assets you own or are authorized to test.

---

*Generated from the transcript of: https://www.youtube.com/watch?v=evyxNUzl-HA*

