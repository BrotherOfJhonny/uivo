#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UIVO Recon Framework - Attack Surface Mapper
Uso permitido apenas em ambientes AUTORIZADOS.

Features deste script:
- Enumeração de subdomínios (crt.sh + brute force com wordlist)
- Coleta de DNS records
- Coleta de informações HTTP (status + headers)
- Coleta de informações SSL/TLS (certificado)
- Integração com Nuclei (com opção de auto-clone em ./nuclei)
- Integração com WPScan (se binário existir)
- Integração com Shodan (API key)
- Geração de:
  - uivo_results.json (resultado bruto)
  - subdomains.json (subdomínios para reuso por outros módulos)
  - uivo_findings_defectdojo.json (Generic JSON Import)
  - uivo_report.html (relatório HTML por módulo + visão de findings)
- Modo PRO (paralelização + cache em disco)
- TUI simples para seleção de módulos

Você é responsável por usar APENAS em ambientes autorizados.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.parse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Type

import html as html_module
import shutil

import requests
import dns.resolver
import tldextract
from colorama import init as colorama_init

# =====================================================================
# CORES E ASCII ART
# =====================================================================

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

ASCII_WOLF = r'''                              __       
                            .d$$b      
                          .' TO$;\     
                         /  : TP._;    
                        / _.;  :Tb|    
                       /   /   ;j$j    
                   _.-"       d$$$$    
                 .' ..       d$$$$;    
                /  /P'      d$$$$P. |\ 
               /   "      .d$$$P' |\^"l
             .'           `T$P^"""""  :
         ._.'      _.'                ;
      `-.-".-'-' ._.       _.-"    .-" 
    `.-" _____  ._              .-"    
   -(.g$$$$$$$b.              .'       
     ""^^T$$$P^)            .(:        
       _/  -"  /.'         /:/;        
    ._.'-'`-'  ")/         /;/;        
 `-.-"..--""   " /         /  ;        
.-" ..--""        -'          :        
..--""--.-"         (\      .-(\       
  ..--""              `-\(\/;`         
    _.                      :          
                            ;`-        
                           :\          
                           ;  '''

def print_banner() -> None:
    """Exibe o banner ASCII do UIVO com cores."""
    print(f"{GREEN}{ASCII_WOLF}{RESET}\n")
    print(f"{GREEN}UIVO Recon Framework - Attack Surface Mapper{RESET}")
    print("Uso permitido apenas em ambientes autorizados.\n")





def validate_domain(domain: str) -> None:
    """Valida se o domínio é resolvível via DNS simples.

    Caso não seja possível resolver o domínio, o programa é encerrado
    com uma mensagem amigável.
    """
    try:
        socket.gethostbyname(domain)
    except Exception:
        print(f"{YELLOW}[!] Domínio não resolvível: {domain}{RESET}")
        raise SystemExit(1)


def enum_html_subdomains(domain: str, base_url: str, timeout: float = 15.0) -> list[str]:
    """
    Faz um GET na página principal e tenta extrair subdomínios do HTML,
    procurando padrões como http(s)://<host> e filtrando somente os que
    terminam com o domínio informado.
    """
    subs: set[str] = set()
    try:
        resp = requests.get(base_url, timeout=timeout, verify=False)
    except Exception:
        return []
    if not (200 <= resp.status_code < 300):
        return []
    import re as _re
    for match in _re.findall(r"https?://([A-Za-z0-9_.-]+)", resp.text):
        host = match.lower().strip()
        # remove trailing punctuation comum em HTML/texto
        host = host.rstrip(").,;\"' ")
        if host.endswith("." + domain) or host == domain:
            if host != domain:
                subs.add(host)
    return sorted(subs)


def classify_subdomains_activity(subdomains: list[str], threads: int = 10) -> tuple[list[str], list[str]]:
    """
    Verifica se os subdomínios respondem em HTTP/HTTPS simples (HEAD/GET),
    classificando em ativos e inativos.
    """
    active: list[str] = []
    inactive: list[str] = []

    def check(sub: str) -> tuple[str, bool]:
        urls = [f"http://{sub}", f"https://{sub}"]
        for u in urls:
            try:
                r = requests.get(u, timeout=5, verify=False)
                if r.status_code < 600:
                    return sub, True
            except Exception:
                continue
        return sub, False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for sub, ok in executor.map(check, subdomains):
            if ok:
                active.append(sub)
            else:
                inactive.append(sub)

    return active, inactive





# =====================================================================
# FUNÇÕES AUXILIARES (PORTADAS DO SCRIPT ORIGINAL)
# =====================================================================

def run_command(cmd: List[str], cwd: Optional[str]=None, timeout: int=600) -> str:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False, cwd=cwd)
        return res.stdout
    except Exception as e:
        return f"[error running {' '.join(cmd)}] {e}"

def get_dns_information(domain: str) -> Dict[str, Any]:

    def _q(rtype: str) -> List[str]:
        out: List[str] = []
        try:
            ans = dns.resolver.resolve(domain, rtype)
            for r in ans:
                out.append(r.to_text())
        except Exception:
            pass
        return out
    return {'A': _q('A'), 'AAAA': _q('AAAA'), 'MX': _q('MX'), 'NS': _q('NS'), 'TXT': _q('TXT')}

def get_ssl_information(domain: str, port: int=443) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info['subject'] = dict((x[0] for x in cert.get('subject', [])))
                info['issuer'] = dict((x[0] for x in cert.get('issuer', [])))
                info['version'] = cert.get('version')
                info['not_before'] = cert.get('notBefore')
                info['not_after'] = cert.get('notAfter')
    except Exception as e:
        info['error'] = str(e)
    return info

def get_http_information(domain: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    urls = [f'https://{domain}', f'http://{domain}']
    for url in urls:
        try:
            r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            info['url'] = url
            info['status_code'] = r.status_code
            info['headers'] = dict(r.headers)
            info['final_url'] = r.url
            break
        except Exception:
            continue
    return info

def find_or_install_nuclei(nuclei_bin: str, auto_install: bool) -> Optional[str]:
    explicit = Path(nuclei_bin)
    if explicit.is_file() and os.access(explicit, os.X_OK):
        return str(explicit)
    path = shutil.which(nuclei_bin)
    if path:
        return path
    nuclei_dir = Path('nuclei')
    local_bin = nuclei_dir / 'nuclei'
    if local_bin.is_file() and os.access(local_bin, os.X_OK):
        return str(local_bin)
    print('[!] Nuclei não encontrado em PATH nem em ./nuclei')
    if not auto_install:
        try:
            resp = input('[?] Clonar projectdiscovery/nuclei em ./nuclei? (y/N): ').strip().lower()
        except EOFError:
            resp = 'n'
        if resp not in ('y', 'yes', 's', 'sim'):
            print('[!] Nuclei será ignorado.')
            return None
    else:
        print('[*] Auto-install habilitado, clonando Nuclei...')
    repo_url = 'https://github.com/projectdiscovery/nuclei.git'
    print(f'[*] Clonando {repo_url} em ./nuclei ...')
    out = run_command(['git', 'clone', repo_url, 'nuclei'], timeout=300)
    print(out)
    if not local_bin.is_file():
        print('[!] Repositório Nuclei clonado, mas o binário nuclei não foi encontrado em ./nuclei/nuclei')
        return None
    return str(local_bin)

def run_nuclei(bin_path: str, targets: List[str], profile: str='pentest', timeout: int=900) -> str:
    """
    Executa Nuclei contra a lista de targets.

    O parâmetro `profile` permite ajustar o conjunto de templates/severidades
    de acordo com o objetivo do scan (ex.: evidências para DefectDojo ou
    varredura de pentest mais ampla).
    """
    try:
        base_cmd: list[str] = [bin_path, '-silent']
        if profile == 'defectdojo':
            base_cmd += ['-severity', 'critical,high,medium,low']
        else:
            base_cmd += ['-severity', 'critical,high,medium']
        proc = subprocess.Popen(base_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stdin_data = '\n'.join(targets) + '\n'
        out, _ = proc.communicate(stdin_data, timeout=timeout)
    except Exception as e:
        out = f'[error while running nuclei] {e}'
    return out

def run_wpscan(url: str, api_token: Optional[str]) -> Dict[str, Any]:
    res: Dict[str, Any] = {'url': url, 'available': False, 'raw_output': '', 'cmd': []}
    wpscan_bin = shutil.which('wpscan')
    if not wpscan_bin:
        res['error'] = 'wpscan binary not found in PATH'
        return res
    cmd = [wpscan_bin, '--no-update', '--url', url]
    if api_token:
        cmd.extend(['--api-token', api_token])
    res['cmd'] = cmd
    out = run_command(cmd, timeout=1800)
    res['raw_output'] = out
    res['available'] = True
    return res

def run_shodan_host(ip: str, api_key: str) -> Dict[str, Any]:
    base = 'https://api.shodan.io/shodan/host'
    url = f'{base}/{ip}?key={api_key}'
    try:
        r = requests.get(url, timeout=20)
        if r.headers.get('content-type', '').startswith('application/json'):
            body = r.json()
        else:
            body = r.text
        return {'ip': ip, 'status_code': r.status_code, 'body': body}
    except Exception as e:
        return {'ip': ip, 'error': str(e)}

SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    mitigation: str = ''
    impact: str = ''
    references: str = ''
    cwe: Optional[int] = None
    cve: Optional[str] = None
    unsaved_endpoints: Optional[List[dict]] = None
    tags: Optional[List[str]] = None
    unique_id_from_tool: Optional[str] = None

    def to_defectdojo_dict(self) -> Dict[str, Any]:
        """
        Apenas os campos necessários para Generic JSON Import.
        """
        return {'title': self.title, 'severity': self.severity, 'description': self.description, 'mitigation': self.mitigation, 'impact': self.impact, 'references': self.references, 'cwe': self.cwe, 'cve': self.cve, 'unsaved_endpoints': self.unsaved_endpoints or [], 'tags': self.tags or [], 'unique_id_from_tool': self.unique_id_from_tool}

def sort_findings(findings: List[Finding]) -> List[Finding]:

    def key(f: Finding):
        try:
            idx = SEVERITY_ORDER.index(f.severity)
        except ValueError:
            idx = len(SEVERITY_ORDER)
        return (idx, f.title.lower())
    return sorted(findings, key=key)

def build_findings_from_results(domain: str, results: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    uid = 1

    def next_uid() -> str:
        nonlocal uid
        val = f'uivo-{domain}-{uid}'
        uid += 1
        return val
    http = results.get('http', {})
    headers = http.get('headers', {}) if isinstance(http, dict) else {}
    url = http.get('url', f'https://{domain}')
    endpoint = {'host': domain, 'path': '/', 'protocol': url.split('://')[0] if '://' in url else 'https', 'port': 443}
    missing = []
    for h in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']:
        if h not in headers:
            missing.append(h)
    if missing:
        findings.append(Finding(title='HTTP security headers missing', severity='Medium', description='Missing headers: ' + ', '.join(missing), mitigation='Configure CSP, HSTS, X-Frame-Options, X-Content-Type-Options.', impact='Increased risk of XSS, clickjacking and other browser-based attacks.', references='https://owasp.org/www-project-secure-headers/', cwe=693, unsaved_endpoints=[endpoint], tags=['uivo', 'http', 'headers'], unique_id_from_tool=next_uid()))
    subs = results.get('subdomains') or []
    if subs:
        findings.append(Finding(title='Subdomain surface mapped', severity='Info', description=f'{len(subs)} subdomains identified for {domain}.', mitigation='Review which subdomains must be exposed and ensure proper hardening.', impact='Larger attack surface offers more potential entry points.', tags=['uivo', 'subdomains', 'attack-surface'], unique_id_from_tool=next_uid()))
    ssl_info = results.get('ssl', {})
    if isinstance(ssl_info, dict) and ssl_info:
        issues = []
        if ssl_info.get('error'):
            issues.append(f"Error: {ssl_info['error']}")
        if ssl_info.get('not_after'):
            issues.append(f"Valid until: {ssl_info['not_after']}")
        if issues:
            findings.append(Finding(title='SSL/TLS configuration notes', severity='Low', description='\n'.join(issues), mitigation='Review certificate configuration and expiration.', impact='Improper TLS configuration may impact confidentiality and integrity.', references='https://owasp.org/www-project-top-ten/2017/A3-Sensitive_Data_Exposure', tags=['uivo', 'ssl'], unsaved_endpoints=[endpoint], unique_id_from_tool=next_uid()))
    nuclei = results.get('nuclei', {})
    for item in nuclei.get('findings', []):
        line = item.get('raw') if isinstance(item, dict) else str(item)
        findings.append(Finding(title='Nuclei finding', severity='Medium', description=line, mitigation='Review the corresponding Nuclei template and apply recommended fixes.', impact='Potential vulnerability or exposure detected by Nuclei.', references='https://github.com/projectdiscovery/nuclei-templates', tags=['uivo', 'nuclei'], unique_id_from_tool=next_uid()))
    wpscan_res = results.get('wpscan', {})
    if isinstance(wpscan_res, dict) and wpscan_res.get('available'):
        findings.append(Finding(title='WordPress scan executed (WPScan)', severity='Info', description='WPScan was executed. Review raw output in uivo_results.json.', mitigation='Review WPScan output and fix reported issues.', impact='Potential WordPress-related findings.', tags=['uivo', 'wpscan', 'wordpress'], unique_id_from_tool=next_uid()))
    shodan_res = results.get('shodan', {})
    if isinstance(shodan_res, dict) and shodan_res.get('available'):
        host_count = len(shodan_res.get('hosts', []))
        if host_count:
            findings.append(Finding(title='Shodan exposure overview', severity='Info', description=f'Shodan returned data for {host_count} IP(s). Check uivo_results.json for details.', mitigation='Review Shodan data and reduce unnecessary exposed services.', impact='Information about exposed services may ease attacker reconnaissance.', tags=['uivo', 'shodan', 'attack-surface'], unique_id_from_tool=next_uid()))
    return sort_findings(findings)

def save_raw_results(domain: str, results: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_file = out_dir / 'uivo_results.json'
    results_file.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print('[+] Results saved:', results_file)
    return results_file

def save_defectdojo_findings(domain: str, results: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = build_findings_from_results(domain, results)
    payload = {'scan_type': 'UIVO Attack Surface Mapping', 'tool': 'uivo', 'target': domain, 'findings': [f.to_defectdojo_dict() for f in findings]}
    dd_file = out_dir / 'uivo_findings_defectdojo.json'
    dd_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    print('[+] DefectDojo-style findings saved:', dd_file)
    return dd_file


def html_escape(text: str) -> str:
    """Escapa caracteres especiais para uso seguro em HTML."""
    if text is None:
        return ""
    # Usa o módulo html da stdlib para evitar problemas de escaping manual.
    return html_module.escape(str(text), quote=True)


def generate_html_report(domain: str, results: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = build_findings_from_results(domain, results)
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
        else:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    rows = []
    for f in findings:
        sev = f.severity
        badge = {'Critical': 'danger', 'High': 'danger', 'Medium': 'warning', 'Low': 'info', 'Info': 'secondary'}.get(sev, 'secondary')
        endpoint = ''
        if f.unsaved_endpoints:
            ep = f.unsaved_endpoints[0]
            endpoint = f"{ep.get('protocol', 'https')}://{ep.get('host', '')}"
        rows.append(f"<tr><td><span class='badge bg-{badge}'>{html_escape(sev)}</span></td><td>{html_escape(f.title)}</td><td>{html_escape(endpoint)}</td><td><pre class='mb-0'>{html_escape(f.description)}</pre></td></tr>")
    total = sum(sev_counts.values()) or 1
    sev_bars = []
    for sev in SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        pct = int(count / total * 100)
        color = {'Critical': 'danger', 'High': 'danger', 'Medium': 'warning', 'Low': 'info', 'Info': 'secondary'}.get(sev, 'secondary')
        sev_bars.append(f"<div class='mb-1'><span class='small'>{html_escape(sev)} ({count})</span><div class='progress' style='height:6px;'><div class='progress-bar bg-{color}' style='width:{pct}%;'></div></div></div>")
    subs_all = results.get('subdomains') or []
    subs_active = results.get('subdomains_active') or []
    subs_inactive = results.get('subdomains_inactive') or []
    active_rows = []
    for s in subs_active:
        host = str(s).strip()
        http = f'http://{host}'
        https = f'https://{host}'
        active_rows.append(f"<tr><td>{html_escape(host)}</td><td><a href='{html_escape(http)}' target='_blank'>HTTP</a></td><td><a href='{html_escape(https)}' target='_blank'>HTTPS</a></td></tr>")
    inactive_rows = []
    for s in subs_inactive:
        host = str(s).strip()
        http = f'http://{host}'
        https = f'https://{host}'
        inactive_rows.append(f"<tr><td>{html_escape(host)}</td><td><a href='{html_escape(http)}' target='_blank'>HTTP</a></td><td><a href='{html_escape(https)}' target='_blank'>HTTPS</a></td></tr>")
    if subs_all:
        subs_section = f"""\n        <div class="card mb-4">\n          <div class="card-header d-flex justify-content-between align-items-center">\n            <h2 class="h6 mb-0">Subdomains</h2>\n            <small class="text-muted">\n              Total: {len(subs_all)} | Active: {len(subs_active)} | Inactive: {len(subs_inactive)}\n            </small>\n          </div>\n          <div class="card-body">\n            <ul class="nav nav-tabs" id="subsTabs" role="tablist">\n              <li class="nav-item" role="presentation">\n                <button class="nav-link active" id="subs-active-tab" data-bs-toggle="tab"\n                        data-bs-target="#subs-active" type="button" role="tab">\n                  Active ({len(subs_active)})\n                </button>\n              </li>\n              <li class="nav-item" role="presentation">\n                <button class="nav-link" id="subs-inactive-tab" data-bs-toggle="tab"\n                        data-bs-target="#subs-inactive" type="button" role="tab">\n                  Inactive ({len(subs_inactive)})\n                </button>\n              </li>\n            </ul>\n            <div class="tab-content mt-3" id="subsTabsContent">\n              <div class="tab-pane fade show active" id="subs-active" role="tabpanel"\n                   aria-labelledby="subs-active-tab">\n                <div class="table-responsive">\n                  <table class="table table-dark table-striped table-sm align-middle">\n                    <thead><tr><th>Subdomain</th><th>HTTP</th><th>HTTPS</th></tr></thead>\n                    <tbody>{(''.join(active_rows) if active_rows else "<tr><td colspan='3' class='text-muted'>No active subdomains.</td></tr>")}</tbody>\n                  </table>\n                </div>\n              </div>\n              <div class="tab-pane fade" id="subs-inactive" role="tabpanel"\n                   aria-labelledby="subs-inactive-tab">\n                <div class="table-responsive">\n                  <table class="table table-dark table-striped table-sm align-middle">\n                    <thead><tr><th>Subdomain</th><th>HTTP</th><th>HTTPS</th></tr></thead>\n                    <tbody>{(''.join(inactive_rows) if inactive_rows else "<tr><td colspan='3' class='text-muted'>No inactive subdomains.</td></tr>")}</tbody>\n                  </table>\n                </div>\n              </div>\n            </div>\n          </div>\n        </div>\n        """
    else:
        subs_section = '\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">Subdomains</h2></div>\n          <div class="card-body"><p class="mb-0 text-muted">No subdomains collected.</p></div>\n        </div>\n        '
    dns_info = results.get('dns')
    if isinstance(dns_info, dict) and dns_info:
        dns_section = f'\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">DNS Records</h2></div>\n          <div class="card-body">\n            <pre>{html_escape(json.dumps(dns_info, indent=2, ensure_ascii=False))}</pre>\n          </div>\n        </div>\n        '
    else:
        dns_section = ''
    http_info = results.get('http')
    if isinstance(http_info, dict) and http_info:
        http_section = f'\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">HTTP Information</h2></div>\n          <div class="card-body">\n            <pre>{html_escape(json.dumps(http_info, indent=2, ensure_ascii=False))}</pre>\n          </div>\n        </div>\n        '
    else:
        http_section = ''
    ssl_info = results.get('ssl')
    if isinstance(ssl_info, dict) and ssl_info:
        ssl_section = f'\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">SSL/TLS Information</h2></div>\n          <div class="card-body">\n            <pre>{html_escape(json.dumps(ssl_info, indent=2, ensure_ascii=False))}</pre>\n          </div>\n        </div>\n        '
    else:
        ssl_section = ''
    nuclei = results.get('nuclei', {})
    nuclei_block = ''
    if isinstance(nuclei, dict) and nuclei.get('available'):
        raw_out = nuclei.get('raw_output', '')
        targets = nuclei.get('targets', [])
        nuclei_block = f"""\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">Nuclei</h2></div>\n          <div class="card-body">\n            <p class="small text-muted mb-2">Targets: {html_escape(', '.join(targets))}</p>\n            <pre>{html_escape(raw_out)}</pre>\n          </div>\n        </div>\n        """
    elif nuclei:
        nuclei_block = '\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">Nuclei</h2></div>\n          <div class="card-body">\n            <p class="mb-0 text-muted">Nuclei configured but binary not found or not executed.</p>\n          </div>\n        </div>\n        '
    wpscan = results.get('wpscan', {})
    wpscan_block = ''
    if isinstance(wpscan, dict) and wpscan.get('available'):
        all_raw = wpscan.get('raw_output', '')
        targets = wpscan.get('targets', [])
        wpscan_block = f"""\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">WPScan</h2></div>\n          <div class="card-body">\n            <p class="small text-muted mb-2">Targets: {html_escape(', '.join(targets))}</p>\n            <pre>{html_escape(all_raw)}</pre>\n          </div>\n        </div>\n        """
    elif wpscan:
        wpscan_block = f"""\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">WPScan</h2></div>\n          <div class="card-body">\n            <p class="mb-0 text-muted">WPScan not available: {html_escape(str(wpscan.get('error', 'Unknown error')))}</p>\n          </div>\n        </div>\n        """
    shodan_info = results.get('shodan', {})
    shodan_block = ''
    if isinstance(shodan_info, dict) and shodan_info.get('available'):
        shodan_block = f'\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">Shodan</h2></div>\n          <div class="card-body">\n            <pre>{html_escape(json.dumps(shodan_info, indent=2, ensure_ascii=False))}</pre>\n          </div>\n        </div>\n        '
    elif shodan_info:
        shodan_block = f"""\n        <div class="card mb-4">\n          <div class="card-header"><h2 class="h6 mb-0">Shodan</h2></div>\n          <div class="card-body">\n            <p class="mb-0 text-muted">Shodan not executed: {html_escape(str(shodan_info.get('error', 'No data')))}</p>\n          </div>\n        </div>\n        """

    js_info = results.get('js_leaks', {})
    js_block = ''
    if isinstance(js_info, dict) and js_info.get('scripts'):
        rows_js = []
        for s in js_info.get('scripts', []):
            url = str(s.get('url', '')).strip()
            leaks = s.get('potential_secrets', []) or []
            types = sorted({str(leak.get('type', 'unknown')) for leak in leaks})
            types_str = ", ".join(types) if types else "None"
            count = len(leaks)
            rows_js.append(f"<tr><td>{html_escape(url)}</td><td>{html_escape(types_str)}</td><td>{count}</td></tr>")
        table_js = "<table class='table table-sm table-striped'><thead><tr><th>Script</th><th>Tipos detectados</th><th>Possíveis secrets</th></tr></thead><tbody>" + "".join(rows_js) + "</tbody></table>"
        js_block = f"\n        <div class='card mb-4'>\n          <div class='card-header'><h2 class='h6 mb-0'>JavaScript Secrets / JS Key Hunter</h2></div>\n          <div class='card-body'>\n            <p class='text-muted mb-2'>Análise heurística de arquivos .js para detectar possíveis chaves/tokens sensíveis. Resultados exigem validação manual.</p>\n            {table_js}\n          </div>\n        </div>\n        "
    elif js_info:
        js_block = "\n        <div class='card mb-4'>\n          <div class='card-header'><h2 class='h6 mb-0'>JavaScript Secrets / JS Key Hunter</h2></div>\n          <div class='card-body'><p class='text-muted mb-0'>JS scan executado, mas nenhum dado relevante foi registrado.</p></div>\n        </div>\n        "

    ascii_block = ASCII_WOLF
    html_doc = f"<!DOCTYPE html>\n<html lang='en'>\n<head>\n  <meta charset='utf-8'>\n  <title>UIVO Report - {html_escape(domain)}</title>\n  <meta name='viewport' content='width=device-width, initial-scale=1'>\n  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>\n  <style>\n    body {{ background-color:#0b0c10; color:#c5c6c7; }}\n    .uivo-header {{ border-bottom:1px solid #45a29e; margin-bottom:1.5rem; padding-bottom:.75rem; }}\n    pre {{ background-color:#1f2833; color:#c5c6c7; padding:.5rem; border-radius:.25rem; font-size:0.8rem; white-space:pre-wrap; }}\n    .ascii-wolf {{ font-family:monospace; white-space:pre; line-height:1.1; font-size:8px; }}\n    a, a:visited {{ color:#66fcf1; }}\n  </style>\n</head>\n<body>\n  <div class='container my-4'>\n    <div class='uivo-header d-flex justify-content-between align-items-center'>\n      <div>\n        <h1 class='h3 mb-1'>UIVO Attack Surface Report</h1>\n        <div>Target: <strong>{html_escape(domain)}</strong></div>\n      </div>\n      <div class='ascii-wolf d-none d-md-block'>\n{ascii_block}\n      </div>\n    </div>\n\n    <div class='row mb-4'>\n      <div class='col-md-4'>\n        <div class='card'>\n          <div class='card-header'><h2 class='h6 mb-0'>Summary</h2></div>\n          <div class='card-body'>\n            <p class='mb-1'>Total findings: <strong>{len(findings)}</strong></p>\n            {''.join(sev_bars)}\n          </div>\n        </div>\n      </div>\n      <div class='col-md-8'>\n        <div class='card'>\n          <div class='card-header'><h2 class='h6 mb-0'>Findings</h2></div>\n          <div class='card-body'>\n            <div class='table-responsive'>\n              <table class='table table-dark table-striped table-sm align-middle'>\n                <thead>\n                  <tr>\n                    <th>Severity</th><th>Title</th><th>Endpoint</th><th>Details</th>\n                  </tr>\n                </thead>\n                <tbody>\n                  {''.join(rows)}\n                </tbody>\n              </table>\n            </div>\n          </div>\n        </div>\n      </div>\n    </div>\n\n    {subs_section}\n    {dns_section}\n    {http_section}\n    {ssl_section}\n    {nuclei_block}\n    {wpscan_block}\n    {shodan_block}{js_block}\n\n  </div>\n  <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>\n</body>\n</html>\n"
    out_path = out_dir / 'uivo_report.html'
    out_path.write_text(html_doc, encoding='utf-8')
    print('[+] HTML report saved:', out_path)
    return out_path


# =====================================================================
# CONTEXTO E PLUGINS
# =====================================================================

@dataclass
class ReconContext:
    domain: str
    store: bool = False
    output_dir: Optional[Path] = None
    threads: int = 10
    version: str = "3.0.0"
    results: Dict[str, Any] = field(default_factory=dict)

    def ensure_output_dir(self) -> None:
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)



_PLUGIN_REGISTRY: list[type["UivoPlugin"]] = []


def register_plugin(cls: "UivoPlugin") -> "UivoPlugin":
    """
    Decorator simples para registrar plugins do UIVO.
    As classes decoradas são armazenadas em _PLUGIN_REGISTRY.
    """
    _PLUGIN_REGISTRY.append(cls)
    return cls


def get_all_plugins() -> list[type["UivoPlugin"]]:
    """
    Retorna todos os plugins registrados, ordenados pelo atributo 'order'.
    """
    return sorted(_PLUGIN_REGISTRY, key=lambda c: getattr(c, "order", 100))


class UivoPlugin:
    slug: str = ""
    name: str = ""
    description: str = ""
    order: int = 100

    def should_run(self, args) -> bool:
        return False

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        raise NotImplementedError


@register_plugin
class SubdomainsPlugin(UivoPlugin):
    slug = "subdomains"
    name = "Subdomain Enumeration"
    description = "Enumeração de subdomínios via crt.sh, APIs e brute force."
    order = 10

    def should_run(self, args) -> bool:
        return getattr(args, "subdomains", False)

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        from src import subdomains as _sd  # usa módulo dedicado

        all_subs: set[str] = set()

        # 1) crt.sh
        print("[*] Enumerating subdomains (crt.sh) ...")
        try:
            crt_subs = _sd.enum_crtsh(ctx.domain)
        except Exception as e:
            print(f"[!] crt.sh enumeration failed: {e}")
            crt_subs = []
        all_subs.update(crt_subs)

        # 2) SecurityTrails
        st_key = getattr(args, "securitytrails_api_key", None)
        if st_key:
            print("[*] Enumerating subdomains (SecurityTrails) ...")
            try:
                st_subs = _sd.enum_securitytrails(ctx.domain, st_key)
                all_subs.update(st_subs)
            except Exception as e:
                print(f"[!] SecurityTrails enumeration failed: {e}")

        # 3) CertSpotter
        cs_key = getattr(args, "certspotter_api_key", None)
        if cs_key:
            print("[*] Enumerating subdomains (CertSpotter) ...")
            try:
                cs_subs = _sd.enum_certspotter(ctx.domain, cs_key)
                all_subs.update(cs_subs)
            except Exception as e:
                print(f"[!] CertSpotter enumeration failed: {e}")

        # 4) Scraping simples da página principal (quando possível)
        base_url = f"http://{ctx.domain}"
        print("[*] Trying to discover subdomains from HTML content ...")
        try:
            html_subs = enum_html_subdomains(ctx.domain, base_url)
            if html_subs:
                print(f"[+] Found {len(html_subs)} subdomains via HTML scraping.")
                all_subs.update(html_subs)
        except Exception as e:
            print(f"[!] HTML scraping for subdomains failed: {e}")

        # 5) Brute force opcional
        wl = getattr(args, "subs_wordlist", None)
        if wl:
            print(f"[*] Brute forcing with wordlist: {wl} ...")
            try:
                brute = _sd.brute_force_subdomains(ctx.domain, wl, threads=ctx.threads)
                if brute:
                    print(f"[+] Found {len(brute)} subdomains via brute force.")
                    all_subs.update(brute)
            except Exception as e:
                print(f"[!] Brute force subdomain enumeration failed: {e}")

        subs_sorted = sorted(all_subs)
        print(f"[+] Total unique subdomains collected: {len(subs_sorted)}")

        # 6) classificar ativos / inativos
        if subs_sorted:
            print("[*] Checking HTTP activity for subdomains ...")
            active, inactive = classify_subdomains_activity(subs_sorted, threads=ctx.threads)
            print(f"[+] Active subdomains: {len(active)} | Inactive: {len(inactive)}")
        else:
            active, inactive = [], []

        ctx.results["subdomains"] = subs_sorted
        ctx.results["subdomains_active"] = active
        ctx.results["subdomains_inactive"] = inactive

        # salva subdomains.json para reuso por Nuclei/WPScan
        if ctx.store and ctx.output_dir:
            sub_file = ctx.output_dir / "subdomains.json"
            data = {
                "domain": ctx.domain,
                "subdomains": subs_sorted,
                "active": active,
                "inactive": inactive,
            }
            sub_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            print("[+] Subdomains saved:", sub_file)

        return {
            "subdomains": subs_sorted,
            "subdomains_active": active,
            "subdomains_inactive": inactive,
        }


@register_plugin
class DNSPlugin(UivoPlugin):
    slug = "dns"
    name = "DNS"
    description = "DNS records."
    order = 20

    def should_run(self, args) -> bool:
        if args.all or getattr(args, "dns", False):
            return True
        modules = args.modules or ""
        return "dns" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        print("[*] Collecting DNS information ...")
        info = get_dns_information(ctx.domain)
        ctx.results["dns"] = info
        print("[+] DNS info collected.")
        return {"dns": info}


@register_plugin
class HTTPPlugin(UivoPlugin):
    slug = "http"
    name = "HTTP"
    description = "HTTP status + headers."
    order = 25

    def should_run(self, args) -> bool:
        if args.all or getattr(args, "http", False):
            return True
        modules = args.modules or ""
        return "http" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        print("[*] Fetching HTTP information ...")
        info = get_http_information(ctx.domain)
        ctx.results["http"] = info
        print("[+] HTTP info collected.")
        return {"http": info}


@register_plugin
class SSLPlugin(UivoPlugin):
    slug = "ssl"
    name = "SSL/TLS"
    description = "Certificate info."
    order = 30

    def should_run(self, args) -> bool:
        if args.all or getattr(args, "ssl", False):
            return True
        modules = args.modules or ""
        return "ssl" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        print("[*] Collecting SSL/TLS information ...")
        info = get_ssl_information(ctx.domain)
        ctx.results["ssl"] = info
        print("[+] SSL/TLS info collected.")
        return {"ssl": info}



@register_plugin
class NucleiPlugin(UivoPlugin):
    slug = "nuclei"
    name = "Nuclei"
    description = "Basic Nuclei scan."
    order = 40

    def should_run(self, args) -> bool:
        if args.all or getattr(args, "nuclei", False):
            return True
        modules = args.modules or ""
        return "nuclei" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        nuclei_results = {"available": False, "findings": []}
        bin_path = find_or_install_nuclei(args.nuclei_bin, args.nuclei_auto_install)
        if not bin_path:
            ctx.results["nuclei"] = nuclei_results
            return {"nuclei": nuclei_results}

        nuclei_results["available"] = True

        # tentar usar subdomínios ATIVOS, depois todos, depois carregar de arquivo
        subs = ctx.results.get("subdomains_active") or ctx.results.get("subdomains") or []
        if ctx.output_dir and not subs:
            sub_file = ctx.output_dir / "subdomains.json"
            if sub_file.is_file():
                try:
                    data = json.loads(sub_file.read_text(encoding="utf-8"))
                    subs = data.get("active") or data.get("subdomains", [])
                except Exception:
                    pass

        targets: list[str] = []

        http_info = ctx.results.get("http", {})
        url = http_info.get("url") or f"http://{ctx.domain}"
        targets.append(url)

        for host in subs:
            host = str(host).strip()
            if not host:
                continue
            targets.append(f"http://{host}")
            targets.append(f"https://{host}")

        targets = sorted(set(targets))

        print("[*] Running Nuclei against:")
        for t in targets:
            print("   -", t)

        out = run_nuclei(bin_path, targets, getattr(args, "nuclei_profile", "pentest"))
        nuclei_results["raw_output"] = out

        findings = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            findings.append({"raw": line})

        nuclei_results["findings"] = findings
        nuclei_results["binary"] = bin_path
        nuclei_results["targets"] = targets

        ctx.results["nuclei"] = nuclei_results
        print(f"[+] Nuclei findings: {len(findings)}")
        return {"nuclei": nuclei_results}



@register_plugin
class JSLeaksPlugin(UivoPlugin):
    slug = "jsleaks"
    name = "JS Secrets Hunter"
    description = "Analisa arquivos .js em busca de possíveis chaves/tokens expostos."
    order = 45

    def should_run(self, args) -> bool:
        if args.all or getattr(args, "jsleaks", False):
            return True
        modules = args.modules or ""
        return "jsleaks" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        import re
        import urllib.parse
        import requests

        http_info = ctx.results.get("http", {})
        base_url = http_info.get("url") or f"http://{ctx.domain}"

        print("[*] JS leaks: analisando possíveis scripts em", base_url)

        visited_pages: set[str] = set()
        js_urls: set[str] = set()

        def fetch(url: str) -> str:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code >= 400:
                    return ""
                return r.text or ""
            except Exception:
                return ""

        def collect_js_from_html(url: str, html: str, source: str) -> None:
            script_pattern = re.compile(r'<script[^>]+src=[\"\']([^"\']+\.js[^"\']*)[\"\']', re.IGNORECASE)
            for m in script_pattern.finditer(html):
                src = m.group(1)
                full = urllib.parse.urljoin(url, src)
                js_urls.add(full)

        # 1) Página principal
        main_html = fetch(base_url)
        if main_html:
            visited_pages.add(base_url)
            collect_js_from_html(base_url, main_html, "main")

            # 2) Crawling leve (nível 1) - apenas links internos
            link_pattern = re.compile(r'<a[^>]+href=[\"\']([^"\']+)[\"\']', re.IGNORECASE)
            for m in link_pattern.finditer(main_html):
                href = m.group(1)
                full = urllib.parse.urljoin(base_url, href)
                if full in visited_pages:
                    continue
                if urllib.parse.urlparse(full).netloc and urllib.parse.urlparse(full).netloc != urllib.parse.urlparse(base_url).netloc:
                    continue
                visited_pages.add(full)
                sub_html = fetch(full)
                if sub_html:
                    collect_js_from_html(full, sub_html, "crawl")

        # 3) Brute-force básico de JS em caminhos comuns
        common_paths = ["/js/", "/static/js/", "/scripts/", "/assets/js/"]
        common_files = [
            "app.js",
            "main.js",
            "bundle.js",
            "vendor.js",
            "index.js",
            "config.js",
            "auth.js",
            "keys.js",
            "settings.js",
        ]
        for path in common_paths:
            for fname in common_files:
                url = urllib.parse.urljoin(base_url, path + fname)
                js_urls.add(url)

        print(f"[*] JS leaks: total de scripts para análise: {len(js_urls)}")

        # padrões heurísticos de possíveis segredos
        secret_patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
            (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
            (re.compile(r"(?i)(api_key|apikey|api-key|token|secret|authorization|auth|password|passwd)\s*[:=]\s*[\"\']([^\"\']{8,})[\"\']"), "generic_credential"),
            (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"), "jwt_token"),
            (re.compile(r"Bearer\s+([A-Za-z0-9._\-]{20,})"), "bearer_token"),
        ]

        scripts: list[dict] = []

        for js_url in sorted(js_urls):
            entry: dict = {"url": js_url, "potential_secrets": []}
            try:
                r = requests.get(js_url, timeout=10)
                content = r.text or ""
            except Exception as e:
                entry["error"] = str(e)
                scripts.append(entry)
                print(f"[!] JS leaks: erro ao baixar {js_url}: {e}")
                continue

            entry["length"] = len(content)
            leaks: list[dict] = []

            for pattern, stype in secret_patterns:
                try:
                    for m in pattern.finditer(content):
                        val = m.group(0)
                        leaks.append({"type": stype, "match": val[:120]})
                except Exception:
                    continue

            entry["potential_secrets"] = leaks
            scripts.append(entry)

        result = {"base_url": base_url, "scripts": scripts}
        ctx.results["js_leaks"] = result
        print(f"[+] JS leaks: análise concluída. Scripts analisados: {len(scripts)}")
        return {"js_leaks": result}




@register_plugin


@register_plugin
class WPScanPlugin(UivoPlugin):
    slug = "wpscan"
    name = "WPScan"
    description = "WordPress scan using wpscan."
    order = 50

    def should_run(self, args) -> bool:
        if getattr(args, "wpscan", False):
            return True
        modules = args.modules or ""
        return "wpscan" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        wpscan_summary: Dict[str, Any] = {"available": False, "targets": [], "results": [], "raw_output": ""}

        # usar subdomínios ATIVOS de preferência
        subs = ctx.results.get("subdomains_active") or ctx.results.get("subdomains") or []
        if ctx.output_dir and not subs:
            sub_file = ctx.output_dir / "subdomains.json"
            if sub_file.is_file():
                try:
                    data = json.loads(sub_file.read_text(encoding="utf-8"))
                    subs = data.get("active") or data.get("subdomains", [])
                except Exception:
                    pass

        http_info = ctx.results.get("http", {})
        main_url = http_info.get("url") or f"http://{ctx.domain}"

        # targets: domínio principal + alguns subdomínios ATIVOS (limite para evitar scan infinito)
        targets: List[str] = [main_url]
        for host in subs[:5]:
            host = str(host).strip()
            if not host:
                continue
            targets.append(f"http://{host}")

        print("[*] Running WPScan against targets:")
        for t in targets:
            print("   -", t)

        all_raw_parts: list[str] = []
        for t in targets:
            res = run_wpscan(t, args.wpscan_api_token)
            wpscan_summary["results"].append(res)
            if res.get("available"):
                wpscan_summary["available"] = True
                if res.get("raw_output"):
                    all_raw_parts.append(f"===== {t} =====\n{res['raw_output']}\n")

        wpscan_summary["targets"] = targets
        wpscan_summary["raw_output"] = "\n".join(all_raw_parts)

        ctx.results["wpscan"] = wpscan_summary
        if wpscan_summary.get("available"):
            print("[+] WPScan executed for one or more targets.")
        else:
            print("[!] WPScan not available.")
        return {"wpscan": wpscan_summary}


@register_plugin

@register_plugin
class ShodanPlugin(UivoPlugin):
    slug = "shodan"
    name = "Shodan"
    description = "Shodan host lookup using API key."
    order = 60

    def should_run(self, args) -> bool:
        if getattr(args, "shodan", False):
            return True
        modules = args.modules or ""
        return "shodan" in [m.strip() for m in modules.split(",") if m.strip()]

    def run(self, ctx: ReconContext, args) -> Dict[str, Any]:
        api_key = args.shodan_api_key
        shodan_res = {"available": False, "hosts": []}
        if not api_key:
            shodan_res["error"] = "no shodan API key provided"
            ctx.results["shodan"] = shodan_res
            print("[!] Shodan API key not provided, skipping.")
            return {"shodan": shodan_res}

        dns_info = ctx.results.get("dns", {})
        ips: set[str] = set()
        for ip in dns_info.get("A", []):
            ips.add(ip.split()[0])

        subs = ctx.results.get("subdomains") or []
        if ctx.output_dir and not subs:
            sub_file = ctx.output_dir / "subdomains.json"
            if sub_file.is_file():
                try:
                    data = json.loads(sub_file.read_text(encoding="utf-8"))
                    subs = data.get("subdomains", [])
                except Exception:
                    pass

        for host in subs:
            try:
                ip = socket.gethostbyname(host)
                ips.add(ip)
            except Exception:
                continue

        ips_list = list(ips)[:10]
        if not ips_list:
            print("[!] No IPs found for Shodan lookup.")
            shodan_res["error"] = "no IPs found from DNS/subdomains"
            ctx.results["shodan"] = shodan_res
            return {"shodan": shodan_res}

        print("[*] Querying Shodan for IPs:", ", ".join(ips_list))
        hosts_data = [run_shodan_host(ip, api_key) for ip in ips_list]

        shodan_res["available"] = True
        shodan_res["hosts"] = hosts_data
        ctx.results["shodan"] = shodan_res
        print(f"[+] Shodan info for {len(hosts_data)} host(s).")
        return {"shodan": shodan_res}


# =====================================================================
# TUI
# =====================================================================

def tui_select_plugins(plugin_classes: List[Type[UivoPlugin]]) -> List[str]:
    print(f"{CYAN}[*] TUI - Selecione módulos para executar (use números separados por vírgula){RESET}")
    for idx, cls in enumerate(plugin_classes, start=1):
        print(f"  {idx:2d}) {cls.slug:10} :: {cls.name}")
    print("  0 ) TODOS")

    try:
        choice = input("\nSeleção (ex: 1,3,4 ou 0): ").strip()
    except EOFError:
        choice = "0"

    if not choice or choice == "0":
        return [c.slug for c in plugin_classes]

    selected = []
    parts = [x.strip() for x in choice.split(",") if x.strip()]
    for p in parts:
        if not p.isdigit():
            continue
        i = int(p)
        if 1 <= i <= len(plugin_classes):
            selected.append(plugin_classes[i - 1].slug)

    if not selected:
        selected = [c.slug for c in plugin_classes]
    return selected


# =====================================================================
# CLI / EXECUÇÃO
# =====================================================================

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="UIVO Recon Framework (authorized use only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain (ex: example.com)")
    p.add_argument("-o", "--output", action="store_true", help="Save results to JSON and HTML")
    p.add_argument("--threads", type=int, default=10, help="Number of worker threads")
    p.add_argument("-A", "--all", action="store_true", help="Run all modules")
    p.add_argument("--modules", help="Comma list: subdomains,dns,ssl,http,nuclei,wpscan,shodan,jsleaks")
    p.add_argument("--plugins", action="store_true", help="List available plugins and exit")

    p.add_argument("--subdomains", action="store_true", help="Enable subdomains module")
    p.add_argument("--subs-wordlist", dest="subs_wordlist", type=str, help="Wordlist for subdomain brute force")

    p.add_argument("--securitytrails-api-key", type=str, default=None, help="SecurityTrails API key for subdomain enumeration")
    p.add_argument("--certspotter-api-key", type=str, default=None, help="CertSpotter API key for subdomain enumeration")

    p.add_argument("--dns", action="store_true", help="Enable DNS module")
    p.add_argument("--ssl", action="store_true", help="Enable SSL module")
    p.add_argument("--http", action="store_true", help="Enable HTTP module")
    p.add_argument("--jsleaks", action="store_true", help="Scan JavaScript files for possible secrets (JS Key Hunter)")

    p.add_argument("--nuclei", action="store_true", help="Enable Nuclei module")
    p.add_argument("--nuclei-bin", default="nuclei", help="Nuclei binary path/name")
    p.add_argument(
        "--nuclei-auto-install",
        action="store_true",
        help="Auto-clone Nuclei repo in ./nuclei if not found",
    )

    p.add_argument(
        "--nuclei-profile",
        dest="nuclei_profile",
        choices=["defectdojo", "pentest"],
        default="pentest",
        help="Perfil de execução do Nuclei (defectdojo ou pentest).",
    )

    p.add_argument("--wpscan", action="store_true", help="Enable WPScan module")
    p.add_argument("--wpscan-api-token", type=str, default=None, help="WPScan API token (optional)")

    p.add_argument("--shodan", action="store_true", help="Enable Shodan module")
    p.add_argument("--shodan-api-key", type=str, default=None, help="Shodan API key")

    p.add_argument("--pro", action="store_true", help="PRO mode (parallel + cache)")
    p.add_argument("--nocache", action="store_true", help="Disable cache in PRO mode")
    p.add_argument("--tui", action="store_true", help="Interactive TUI module selection")
    p.add_argument("--serve", action="store_true", help="Serve report directory via http.server after run")
    return p


def get_default_modules() -> List[str]:
    """Módulos padrão quando o usuário não especifica nada.

    Mantemos um conjunto enxuto para não surpreender: subdomínios, DNS e HTTP.
    SSL, Nuclei, WPScan e Shodan ficam como opt-in ou via --all.
    """
    return ["subdomains", "dns", "http"]



def select_plugin_slugs(plugin_classes: List[Type[UivoPlugin]], args) -> List[str]:
    if args.tui:
        return tui_select_plugins(plugin_classes)

    if args.all:
        return [c.slug for c in plugin_classes]

    selected = []
    if args.modules:
        for part in args.modules.split(","):
            p = part.strip()
            if p:
                selected.append(p)

    if args.subdomains:
        selected.append("subdomains")
    if args.dns:
        selected.append("dns")
    if args.ssl:
        selected.append("ssl")
    if args.http:
        selected.append("http")
    if args.nuclei:
        selected.append("nuclei")
    if args.wpscan:
        selected.append("wpscan")
    if args.shodan:
        selected.append("shodan")
    if getattr(args, 'jsleaks', False):
        selected.append('jsleaks')
    # auto-run JS leaks scan when Nuclei is selected
    if 'nuclei' in selected and 'jsleaks' not in selected:
        selected.append('jsleaks')

    if not selected:
        selected = get_default_modules()

    final = []
    seen = set()
    for s in selected:
        if s not in seen:
            final.append(s)
            seen.add(s)
    return final


def run_sequential(ctx: ReconContext, args, plugin_classes: List[Type[UivoPlugin]]) -> None:
    slug_to_cls = {c.slug: c for c in plugin_classes}
    selected = select_plugin_slugs(plugin_classes, args)
    plugins = [slug_to_cls[s] for s in selected if s in slug_to_cls]
    print("[*] Running modules:", ", ".join(p.slug for p in plugins))
    for cls in plugins:
        plugin = cls()
        if not plugin.should_run(args):
            continue
        res = plugin.run(ctx, args)
        if isinstance(res, dict):
            ctx.results.update(res)



# =====================================================================
# CACHE EM DISCO PARA PRO MODE
# =====================================================================

class DiskCache:
    """
    Cache simples baseado em arquivo JSON, protegido por lock de thread.

    O formato armazenado é um dicionário:
        { "chave": valor_serializavel_em_JSON }
    """
    _lock = threading.Lock()

    def __init__(self, path: Path):
        self.path = Path(path)
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
        tmp.replace(self.path)

    def get(self, key: str):
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value
            self._save()


def cacheable(cache: Optional[DiskCache], key_builder=None):
    """
    Decorator para facilitar o cache de resultados de funções em disco.

    Se `cache` for None, a função é executada normalmente.
    Caso contrário, a chave é construída por `key_builder(*args, **kwargs)`.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if cache is None:
                return func(*args, **kwargs)
            key = key_builder(*args, **kwargs) if key_builder else func.__name__
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value
            result = func(*args, **kwargs)
            cache.set(key, result)
            return result
        return wrapper
    return decorator

def run_pro(ctx: ReconContext, args, plugin_classes: List[Type[UivoPlugin]]) -> None:
    slug_to_cls = {c.slug: c for c in plugin_classes}
    selected = select_plugin_slugs(plugin_classes, args)
    plugins = [slug_to_cls[s] for s in selected if s in slug_to_cls]
    print("[*] Running modules (PRO):", ", ".join(p.slug for p in plugins))

    cache_dir = Path(".uivo_cache")
    cache_dir.mkdir(exist_ok=True)
    cache = DiskCache(cache_dir / "uivo_cache.json") if not args.nocache else None
    domain = ctx.domain

    def run_plugin_with_cache(plugin_cls: Type[UivoPlugin]):
        plugin = plugin_cls()

        def inner_run():
            local_ctx = ReconContext(
                domain=ctx.domain,
                store=False,
                output_dir=None,
                threads=ctx.threads,
                version=ctx.version,
            )
            plugin.run(local_ctx, args)
            return local_ctx.results

        if cache is None:
            return plugin_cls.slug, inner_run()

        @cacheable(cache, key_builder=lambda *a, **kw: f"{plugin_cls.slug}:{domain}:{ctx.version}")
        def cached():
            return inner_run()

        return plugin_cls.slug, cached()

    with ThreadPoolExecutor(max_workers=ctx.threads) as executor:
        future_to_slug = {
            executor.submit(run_plugin_with_cache, plugin_cls): plugin_cls.slug
            for plugin_cls in plugins
        }
        for future in as_completed(future_to_slug):
            slug = future_to_slug[future]
            try:
                slug_key, result = future.result()
                if isinstance(result, dict):
                    ctx.results.update(result)
                else:
                    ctx.results[slug_key] = result
                print(f"[+] Plugin '{slug}' done.")
            except Exception as exc:
                print(f"[!] Plugin '{slug}' failed: {exc}")


def serve_report_with_http_server(output_dir: Path, port: int = 8000) -> None:
    print(f"[*] Starting HTTP server in {output_dir} (port {port})...")
    subprocess.Popen(
        ["python3", "-m", "http.server", str(port)],
        cwd=str(output_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[+] Access: http://localhost:{port}/uivo_report.html")


# =====================================================================
# MAIN
# =====================================================================


def main_with_args(args) -> int:
    """
    Núcleo de execução do UIVO a partir de um objeto de argumentos já preenchido.
    Isso permite reuso tanto pela CLI tradicional quanto pelo modo interativo.
    """
    ext = tldextract.extract(args.domain)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else args.domain

    validate_domain(domain)
    print(f"[*] Iniciando recon para {domain} (modo {'PRO' if getattr(args, 'pro', False) else 'normal'}) ...")


    output_dir = Path(domain) if args.output else None
    ctx = ReconContext(
        domain=domain,
        store=bool(args.output),
        output_dir=output_dir,
        threads=args.threads,
        version="3.0.0-PRO" if getattr(args, "pro", False) else "3.0.0",
    )
    if ctx.store and ctx.output_dir:
        ctx.ensure_output_dir()

    plugin_classes = get_all_plugins()

    if getattr(args, "plugins", False):
        print(f"\n{CYAN}[+] Available plugins:{RESET}\n")
        for cls in plugin_classes:
            print(f" - {cls.slug:12} :: {cls.name}")
        print()
        return 0

    if getattr(args, "tui", False):
        # Permite seleção interativa de plugins mesmo na CLI tradicional
        selected_slugs = run_tui(plugin_classes)
        args.modules = ",".join(selected_slugs)

    if getattr(args, "pro", False):
        run_pro(ctx, args, plugin_classes)
    else:
        run_sequential(ctx, args, plugin_classes)

    if ctx.store and ctx.output_dir:
        save_raw_results(domain, ctx.results, ctx.output_dir)
        save_defectdojo_findings(domain, ctx.results, ctx.output_dir)
        generate_html_report(domain, ctx.results, ctx.output_dir)
        if getattr(args, "serve", False):
            serve_report_with_http_server(ctx.output_dir)

    print(f"\n{GREEN}[OK] Finished.{RESET}")
    return 0


def interactive_main() -> int:
    """
    Modo interativo de configuração inicial, pensado para o uso:
        python uivo.py .
    """
    print_banner()
    print(f"{CYAN}[*] Modo interativo de configuração do UIVO{RESET}\n")

    # 1) Perguntar domínio/URL
    while True:
        try:
            raw_target = input("Informe o domínio a ser pesquisado (ex: exemplo.com): ").strip()
        except EOFError:
            print(f"\n{YELLOW}[!] Entrada encerrada sem domínio informado.{RESET}")
            return 1
        if not raw_target:
            print(f"{YELLOW}[!] Valor vazio. Tente novamente.{RESET}")
            continue

        parsed = urllib.parse.urlparse(raw_target)
        host = parsed.netloc or parsed.path or raw_target
        host = host.split("/")[0].strip()
        if not host:
            print(f"{YELLOW}[!] Não foi possível extrair um host válido. Tente novamente.{RESET}")
            continue

        domain = host.lower()
        break

    # 2) Selecionar módulos
    options = [
        ("all", "Todos os testes"),
        ("subdomains", "Pesquisar Subdomínios"),
        ("dns", "Pesquisa DNS"),
        ("ssl", "Pesquisa Certificado (SSL/TLS)"),
        ("shodan", "Pesquisa Shodan"),
        ("nuclei", "Scan Nuclei"),
        ("wpscan", "Scan WPScan"),
    ]

    print("\nSelecione os módulos a serem executados (ex: 1,3,5).")
    print("Deixe em branco para utilizar o conjunto padrão (subdomains,dns,http).\n")
    for idx, (_, label) in enumerate(options, 1):
        print(f"[{idx}] {label}")

    try:
        choice = input("\nOpções: ").strip()
    except EOFError:
        choice = ""

    selected_keys: set[str] = set()
    if choice:
        for part in choice.split(","):
            part = part.strip()
            if not part.isdigit():
                continue
            i = int(part)
            if 1 <= i <= len(options):
                selected_keys.add(options[i - 1][0])

    
    # Se o usuário escolheu 'Todos os testes'
    if "all" in selected_keys:
        selected_keys = {"subdomains", "dns", "ssl", "shodan", "nuclei", "wpscan", "http", "jsleaks"}

    if not selected_keys:
        # Usa o conjunto padrão definido pela própria CLI
        selected_keys.update(get_default_modules())

    # 3) Caso Nuclei tenha sido selecionado, escolher o perfil
    nuclei_profile = "pentest"
    if "nuclei" in selected_keys:
        print("\nPerfil de execução do Nuclei:")
        print("  [1] Scan para gerar evidências DefectDojo")
        print("  [2] Scan modelo pentest (padrão)")
        try:
            choice_n = input("Escolha (1/2) [2]: ").strip()
        except EOFError:
            choice_n = ""
        if choice_n == "1":
            nuclei_profile = "defectdojo"
        else:
            nuclei_profile = "pentest"

    # 4) Perguntar por credenciais de Shodan e WPScan (se selecionados)
    # JS leaks: quando Nuclei for selecionado, também ativamos o módulo de análise de .js
    if "nuclei" in selected_keys:
        selected_keys.add("jsleaks")
    shodan_key: str | None = None
    if "shodan" in selected_keys:
        print("\nShodan:")
        try:
            use_shodan = input("Deseja informar a API key do Shodan agora? [s/N]: ").strip().lower()
        except EOFError:
            use_shodan = ""
        if use_shodan in ("s", "sim", "y", "yes"):
            try:
                shodan_key_input = input("Informe a API key do Shodan: ").strip()
            except EOFError:
                shodan_key_input = ""
            if shodan_key_input:
                shodan_key = shodan_key_input

    wpscan_token: str | None = None
    if "wpscan" in selected_keys:
        print("\nWPScan:")
        try:
            use_wpscan = input("Deseja informar o API token do WPScan agora? [s/N]: ").strip().lower()
        except EOFError:
            use_wpscan = ""
        if use_wpscan in ("s", "sim", "y", "yes"):
            try:
                wpscan_token_input = input("Informe o API token do WPScan: ").strip()
            except EOFError:
                wpscan_token_input = ""
            if wpscan_token_input:
                wpscan_token = wpscan_token_input

    # 5) APIs adicionais para enumeração de subdomínios (SecurityTrails / CertSpotter)
    securitytrails_key: str | None = None
    certspotter_key: str | None = None
    if "subdomains" in selected_keys:
        print("\nFontes adicionais para subdomínios (opcional):")
        try:
            use_st = input("Deseja informar API key do SecurityTrails? [s/N]: ").strip().lower()
        except EOFError:
            use_st = ""
        if use_st in ("s", "sim", "y", "yes"):
            try:
                st_input = input("Informe a API key do SecurityTrails: ").strip()
            except EOFError:
                st_input = ""
            if st_input:
                securitytrails_key = st_input

        try:
            use_cs = input("Deseja informar API key do CertSpotter? [s/N]: ").strip().lower()
        except EOFError:
            use_cs = ""
        if use_cs in ("s", "sim", "y", "yes"):
            try:
                cs_input = input("Informe a API key do CertSpotter: ").strip()
            except EOFError:
                cs_input = ""
            if cs_input:
                certspotter_key = cs_input

    # 6) Wordlist para brute force de subdomínios (opcional)
    subs_wordlist: str | None = None
    if "subdomains" in selected_keys:
        print("\nSubdomínios (brute force opcional):")
        try:
            use_wordlist = input("Deseja informar uma wordlist para brute force de subdomínios? [s/N]: ").strip().lower()
        except EOFError:
            use_wordlist = ""
        if use_wordlist in ("s", "sim", "y", "yes"):
            try:
                wl = input("Informe o caminho da wordlist: ").strip()
            except EOFError:
                wl = ""
            if wl:
                subs_wordlist = wl

    # 6) Montar lista de argumentos equivalente à CLI
    argv = [
        "--domain", domain,
        "-o",          # sempre gerar JSON/HTML em modo interativo
        "--pro",       # modo PRO por padrão no fluxo interativo
    ]

    if "subdomains" in selected_keys:
        argv.append("--subdomains")
    if "dns" in selected_keys:
        argv.append("--dns")
    if "ssl" in selected_keys:
        argv.append("--ssl")
    if "shodan" in selected_keys:
        argv.append("--shodan")
    if "nuclei" in selected_keys:
        argv.append("--nuclei")
        argv.extend(["--nuclei-profile", nuclei_profile])
    if "wpscan" in selected_keys:
        argv.append("--wpscan")

    # parâmetros opcionais adicionais
    if subs_wordlist:
        argv.extend(["--subs-wordlist", subs_wordlist])
    if shodan_key:
        argv.extend(["--shodan-api-key", shodan_key])
    if wpscan_token:
        argv.extend(["--wpscan-api-token", wpscan_token])
    if securitytrails_key:
        argv.extend(["--securitytrails-api-key", securitytrails_key])
    if certspotter_key:
        argv.extend(["--certspotter-api-key", certspotter_key])

    # HTTP costuma ser útil como apoio a outros módulos
    if any(k in selected_keys for k in ("subdomains", "nuclei", "wpscan", "shodan")):
        argv.append("--http")

    parser = build_cli()
    args = parser.parse_args(argv)
    return main_with_args(args)


def main(argv: list[str] | None = None) -> int:
    """
    Ponto de entrada principal.

    - Se chamado sem argumentos ou apenas com '.', entra no modo interativo.
    - Caso contrário, segue o fluxo tradicional da CLI.
    """
    colorama_init(autoreset=True)

    if argv is None:
        argv = sys.argv[1:]

    if not argv or (len(argv) == 1 and argv[0] == "."):
        return interactive_main()

    print_banner()
    parser = build_cli()
    args = parser.parse_args(argv)
    return main_with_args(args)


if __name__ == "__main__":
    raise SystemExit(main())