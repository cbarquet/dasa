import signal
import sys
import requests
import asyncio
import aiohttp
from requests_html import HTMLSession
import requests
from urllib.parse import urlparse, urljoin
import argparse
import os
import re
import json
import logging
import time
import random
from collections import deque
from urllib.robotparser import RobotFileParser
from tqdm import tqdm

def signal_handler(sig, frame):
    print("\nCtrl+C pressed. Do you want to abort the script? (y/N): ", end="")
    user_input = input().strip().lower()
    if user_input == 'y':
        print("Aborting script...")
        sys.exit(0)
    else:
        print("Continuing script...")

signal.signal(signal.SIGINT, signal_handler)

# --- Advanced global settings ---
COMMON_DIRECTORIES_FILE = "common_directories.txt"
COMMON_FILES_FILE = "common_files.txt"
DEFAULT_TIMEOUT = 20
JS_RENDER_TIMEOUT = 45
CRAWL_DEPTH_LIMIT = 3
RATE_LIMIT_DELAY = 1
MAX_RETRIES = 3
RETRY_DELAY = 5
FUZZING_PAYLOADS_EXTENDED = [
    "'", "\"", "\\", "`", "<", ">", ";", "%27", "%22", "%3C", "%3E",
    "/*", "*/", "--", ";--", "#", "%00", "or 1=1--", "or 1=1#", "or 1=1/*",
    "睡眠",
    "<script>alert('XSS')</script>",
    "\"/><script>alert('XSS')</script><\"",
    "'><svg/onload=alert('XSS')>",
    "../", "../../", "../../../",
    "%2e%2e%2f", "%252e%252e%2f",
    "../../../../etc/passwd",
    "&", "?", "=", "%", "+", "$", "{", "}", "[", "]", "(", ")", "*", "^", "~", "!",
    " AND 1=1", " OR 1=1",
    "admin", "administrator", "root", "user", "guest",
    "test", "demo", "backup", "config", "debug", "staging"
]
INTERESTING_PARAMS_REGEX = re.compile(r"(id|user|name|search|query|debug|page|action|view|lang|category|product|item|article|dir|file|auth|token|session|api_key|password|email)", re.IGNORECASE)
API_ENDPOINT_REGEX = re.compile(r"(/api/|/v\d+/|\.json|\.xml)", re.IGNORECASE)
SQL_ERROR_REGEX = re.compile(r"(SQL syntax|MySQL|MariaDB|syntax error|ORA-|OLE DB Provider for SQL Server|Invalid query|org\.postgresql\.util\.PSQLException|Microsoft SQL Server)", re.IGNORECASE)
COMMAND_INJECTION_ERROR_REGEX = re.compile(r"(command not found|permission denied|sh:|bash:|shell:|/bin/sh:)", re.IGNORECASE)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Lynx/2.8.9rel.1 libwww-FM/2.14 SSL-MM/1.4 GNUTLS/3.7.2"
]
NOT_FOUND_PATTERNS = re.compile(r"(Not Found|Error 404|404 Not Found|Page Not Found|no se encontró la página|Página no encontrada|El recurso solicitado no se encuentra)", re.IGNORECASE)

SCRIPT_VERSION = "0.4.0"

def print_banner(target_url, wordlist_size): 
    """Print the banner at the beginning of the execution."""
    banner = r"""
    ____  ___   _____ ___                ___                             ______    ___ __  _           
   / __ \/   | / ___//   |              /   |  _______  ______  _____   / ____/___/ (_) /_(_)___  ____ 
  / / / / /| | \__ \/ /| |    ______   / /| | / ___/ / / / __ \/ ___/  / __/ / __  / / __/ / __ \/ __ \
 / /_/ / ___ |___/ / ___ |   /_____/  / ___ |(__  ) /_/ / / / / /__   / /___/ /_/ / / /_/ / /_/ / / / /
/_____/_/  |_/____/_/  |_|           /_/  |_/____/\__, /_/ /_/\___/  /_____/\__,_/_/\__/_/\____/_/ /_/ 
                                                 /____/                                                
[*] Dynamic Attack Surface Analyzer - Async Edition
[*] Offensive Security & Recon Tool
[*] Script Verision: v0.4 - By Cbnhub                                       
    """.format(SCRIPT_VERSION)
    http_method = "GET"
    threads = "Async"

    print(banner)
    print(f"HTTP method: {http_method} | Threads: {threads} | Wordlist size: {wordlist_size}\n")
    print(f"\nTarget: {target_url}\n")


def detect_waf(url):
    """
    Try to detect a WAF on the target URL using basic and enhanced heuristics.
    Returns a dictionary with detection details.
    """
    detection_details = {
        'detected': False,
        'confidence_score': 0,
        'matches': [],
        'potential_waf_products': [],
        'debug': {} # For storing debug information during development
    }

    try:
        session_sync = HTMLSession()
        session_sync.headers['User-Agent'] = get_random_user_agent()
        response = session_sync.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        detection_details['debug']['response_headers'] = response.headers # Capture headers for debugging

        server_header = response.headers.get('Server', '').lower()

        # Enhanced and expanded WAF/CDN header list with categories and weights
        waf_signatures = {
            'strong_indicators': { # High confidence WAF indicators
                'Server': [
                    'cloudflare', 'incapsula', 'imperva', 'distil networks',
                    'fortinet-waf', 'f5-waf', 'mod_security', 'barracuda',
                    'akamai', 'maxcdn', 'azion', 'cloudfront', # CDNs often act as WAFs
                    'sophos', 'radware', 'citrix-netscaler', 'cisco-ace',
                    'juniper-netscreen', 'sonicwall', 'paloalto-firewall',
                    'stackpath', 'fastly', 'sucuri', 'perimeterx',
                    'signal sciences', 'reblaze', 'shieldsquare', 'wallarm',
                    'hyperguard', 'tencent cloud cdn', 'aliyun cdn',
                    'azure-application-gateway', 'google cloud armor',
                    'amazonaws', 'azion'
                ],
                'X-WAF-Active': ['true', 'yes', 'on', 'enabled'],
                'X-CDN': ['cloudflare', 'imperva', 'akamai', 'maxcdn', 'azion', 'cloudfront', 'fastly', 'tencent', 'aliyun', 'amazonaws'],
                'X-Firewall': ['.*'], # Generic firewall indicator
                'X-Backend-Server': ['(?:cloudflare|incapsula|imperva).*'], # Backend server names can sometimes leak WAF info
                'X-Akamai-Gzip-Encoding': ['.*'], # Akamai specific header
                'X-Incap-Request-ID': ['.*'], # Incapsula specific header
                'X-Iinfo': ['.*'], # Imperva specific header
                'X-Distil-CS': ['.*'], # Distil Networks specific header
                'X-Frame-Options': ['SAMEORIGIN', 'DENY'],  # WAFs/CDNs often enforce/add this
                'Strict-Transport-Security': ['max-age='],  # WAFs/CDNs often enforce HSTS
            },
            'medium_indicators': { # Medium confidence, might be present without a WAF but common with them
                'X-XSS-Protection': ['1; mode=block', '1;mode=block', '1', '0'], #  WAFs often configure XSS protection
                'X-Content-Type-Options': ['nosniff'], # Security hardening often done by WAFs
                'X-Content-Filter': ['true', 'enabled', 'on'], # Content filtering presence
                'X-Request-ID': ['.*'], # Request tracing, can be done by WAFs
                'X-Proxy-Cache': ['HIT', 'MISS', 'BYPASS'], # Caching behavior, WAFs/CDNs cache
                'Cache-Control': ['(?:private|no-cache|no-store|must-revalidate)'], # Caching directives often controlled by WAFs
                'Pragma': ['no-cache'], # Caching directives
                'Expires': ['.*'], # Caching directives
                'Server': ['(?:nginx|apache).*'], # Common web servers, but WAFs often sit in front
            },
            'weak_indicators': { # Low confidence, general security headers, but might contribute to score
                'Content-Security-Policy': ['.*'], # CSP, security header, might be set by WAF
                'Referrer-Policy': ['.*'], # Security header
                'Permissions-Policy': ['.*'], # Security header (formerly Feature-Policy)
                'Access-Control-Allow-Origin': ['.*'], # CORS can be managed by WAFs
                'Vary': ['Accept-Encoding', 'User-Agent'], # CDN/WAF influence on Vary header
            }
        }

        # Scoring and detection logic
        score = 0
        matched_headers_list = []
        potential_products = set()

        for category, headers_group in waf_signatures.items():
            weight = 0
            if category == 'strong_indicators':
                weight = 3
            elif category == 'medium_indicators':
                weight = 2
            elif category == 'weak_indicators':
                weight = 1

            for header_name, patterns in headers_group.items():
                header_value = response.headers.get(header_name, '')
                if not header_value: # Header not present, skip to next
                    continue

                for pattern in patterns:
                    if pattern == '.*': # Wildcard pattern
                        if header_name not in ['Server']: # Avoid overly broad server matches
                            score += weight
                            matched_headers_list.append({'header': header_name, 'value': header_value, 'pattern': pattern, 'category': category})
                            break # Avoid multiple matches on wildcard

                    elif pattern.lower() in header_value.lower(): # Simple substring match (case-insensitive)
                        score += weight
                        matched_headers_list.append({'header': header_name, 'value': header_value, 'pattern': pattern, 'category': category})
                        if header_name == 'Server': # Infer potential product from Server header
                            potential_products.add(pattern.lower())
                        elif header_name == 'X-CDN':
                            potential_products.add(pattern.lower())
                        elif header_name == 'X-WAF-Active':
                             potential_products.add("Generic WAF (X-WAF-Active)")
                        break # Move to next header after finding a match

                    elif pattern.startswith('(?:') and pattern.endswith(').*'): # Regex pattern (start with (?: and end with ).*)
                        import re
                        regex_pattern = pattern[4:-3] # Extract regex part
                        if re.search(regex_pattern, header_value, re.IGNORECASE):
                            score += weight
                            matched_headers_list.append({'header': header_name, 'value': header_value, 'pattern': pattern, 'category': category})
                            break # Move to next header after finding a match


        detection_details['confidence_score'] = score
        detection_details['matches'] = matched_headers_list
        detection_details['potential_waf_products'] = list(potential_products)


        # Determine if detected based on score threshold (adjust as needed)
        if score >= 4: # Tunable threshold based on scoring system
            detection_details['detected'] = True


    except Exception as e:
        detection_details['debug']['error'] = str(e)
        detection_details['debug']['error_type'] = type(e).__name__
        detection_details['detected'] = False # Detection failed due to error
        detection_details['confidence_score'] = -1 # Indicate error in score


    return detection_details


async def dynamic_attack_surface_analyzer(url_objetivo, output_file=None, deep_crawl=False, detect_hidden=False, detailed_analysis=False, enable_fuzzing=False, crawl_depth=CRAWL_DEPTH_LIMIT, verbose=False, accurate_hidden=False):
    """
    Dynamic web attack surface analyzer (asynchronous, realistic, and powerful version).
    """
    if verbose:
        logging.info(f"[*] Starting dynamic attack surface analyzer for:: {url_objetivo}")
        logging.info(f"    Options: Deep Crawl={deep_crawl}, Detect Hidden={detect_hidden}, Detailed Analysis={detailed_analysis}, Fuzzing={enable_fuzzing}, Crawl Depth={crawl_depth}, Accurate Hidden Detection={accurate_hidden}")
        logging.debug("[DEBUG] Entering the DASA function")
    else:
        print(f"[*] Starting dynamic attack surface analyzer for: {url_objetivo}...")

    # --- WAF Detection ---
    waf_detection = detect_waf(url_objetivo)
    if waf_detection and waf_detection['detected']: # Check if waf_detection is not none AND if WAF is detected
        print("\n[!] Possible WAF Detected:")
        print(f"    Confidence Score: {waf_detection['confidence_score']}")
        if waf_detection['potential_waf_products']:
            print(f"    Potential WAF Products: {', '.join(waf_detection['potential_waf_products'])}")

        # Filter matched headers to show only strong and medium indicators for less noise
        filtered_matches = [match for match in waf_detection['matches'] if match['category'] in ['strong_indicators', 'medium_indicators']]
        weak_matches_count = len([match for match in waf_detection['matches'] if match['category'] == 'weak_indicators'])


        if filtered_matches:
            print("    Matched Headers (Strong & Medium Indicators):")
            for match in filtered_matches:
                print(f"      - {match['header']}: '{match['value']}' (Pattern: '{match['pattern']}', Category: {match['category']})")
        if weak_matches_count > 0:
            print(f"    ...and {weak_matches_count} weak indicators were also detected (for informational purposes).")


        user_response = input("[?] Do you want to continue the scan despite the possible presence of a WAF? (y/N): ").lower()
        if user_response != 'y':
            print("[*] Scan aborted by user due to possible WAF.")
            return
        else:
            print("[*] Continuing with the scan despite the possible presence of a WAF. Proceed with CAUTION.")

    elif waf_detection and waf_detection['confidence_score'] > 0:
        print(f"[*] No strong WAF detected, but some potential security headers found (Confidence Score: {waf_detection['confidence_score']}).")
        if waf_detection['matches']:
                print("    Potentially relevant headers (below detection threshold):")
                for match in waf_detection['matches']:
                    print(f"      - {match['header']}: '{match['value']}' (Pattern: '{match['pattern']}', Category: {match['category']})")

    elif waf_detection and waf_detection['confidence_score'] == -1:
        print(f"[!] WAF detection encountered an error. Scan continuing without WAF check insights. (Debug info: {waf_detection['debug'].get('error_type', 'Unknown Error')})")

    else:
        print("[*] No known WAFs detected based on headers.")


    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        visited_urls = set()
        crawl_queue = deque([(url_objetivo, 0)])
        points_of_entry = {"urls": [], "forms": [], "hidden_paths": []}
        report_data = []

        if verbose:
            logging.debug("[DEBUG] Before the while loop crawl_queue")

        # --- Progress bar and banner ---
        wordlist_directories = load_wordlist(COMMON_DIRECTORIES_FILE)
        wordlist_files = load_wordlist(COMMON_FILES_FILE)
        total_paths_to_check = 0
        if detect_hidden:
            total_paths_to_check = (len(wordlist_directories) if wordlist_directories else 0) + (len(wordlist_files) if wordlist_files else 0)

        if not verbose and detect_hidden:
            print_banner(url_objetivo, total_paths_to_check)
            pbar = tqdm(total=total_paths_to_check, unit="path", desc="Starting", dynamic_ncols=True)
        elif not verbose:
            pbar = tqdm(total=0, unit="url", desc="Crawling", dynamic_ncols=True)

        crawl_tasks = []
        while crawl_queue:
            current_url, current_depth = crawl_queue.popleft()
            task = asyncio.create_task(crawl_page(session, current_url, current_depth, visited_urls, crawl_queue, points_of_entry, report_data, url_objetivo, crawl_depth, verbose, pbar if not verbose and not detect_hidden else None))
            crawl_tasks.append(task)

        await asyncio.gather(*crawl_tasks)

        if not verbose and not detect_hidden:
            pbar.close()

        if verbose:
            logging.debug("[DEBUG] After the while loop crawl_queue")

        if detect_hidden:
            if not verbose: 
                 pbar.set_description("Starting")
            points_of_entry["hidden_paths"] = detect_hidden_paths(url_objetivo, verbose=verbose, accurate=accurate_hidden, pbar=pbar if not verbose and detect_hidden else None, total_paths=total_paths_to_check) # line 177

        analyze_contextually(points_of_entry, visited_urls, detailed_analysis, enable_fuzzing, verbose=verbose, detect_hidden=detect_hidden)

        end_time = time.time()
        execution_time = end_time - start_time
        generate_report(report_data, points_of_entry, visited_urls, output_file, execution_time, url_objetivo, deep_crawl, detect_hidden, detailed_analysis, enable_fuzzing, crawl_depth, verbose=verbose, accurate_hidden=accurate_hidden)

    if verbose:
        logging.info(f"\n[*] Dynamic attack surface analysis completed for: {url_objetivo}")
        logging.debug("[DEBUG] Exiting the dynamic_attack_surface_analyzer function")
    else:
        if detect_hidden:
            pbar.close()
        print(f"[*] Dynamic attack surface analysis completed for: {url_objetivo}")
        print(f"[*] Report saved to: {output_file if output_file else 'console'}")
        print(f"[*] Execution time: {execution_time:.2f} seconds")
        print(f"[*] To view the full report, please check the file: {output_file if output_file else 'console'}")
    logging.debug("[DEBUG] Exiting the DASA function")


async def crawl_page(session, url, depth, visited_urls, crawl_queue, points_of_entry, report_data, url_objetivo, crawl_depth, verbose, pbar=None):
    """
    Asynchronously crawl a webpage with synchronous js rendering using requests-html.
    """
    if depth > crawl_depth:
        if verbose:
            logging.info(f"  [>] Maximum depth reached ({crawl_depth}) para: {url}. Crawling stopped on this branch.")
        return
    if url in visited_urls:
        return
    if not check_robots_txt(url_objetivo, url):
        if verbose:
            logging.info(f"  [>] URL blocked by robots.txt: {url}. Crawling skipped.")
        return

    if verbose:
        logging.info(f"  [*] Crawled url depth {depth}): {url}")

    visited_urls.add(url)
    page_report = {"url": url, "status_code": None, "forms": [], "hidden_paths_detected": []}

    retries = 0
    while retries < MAX_RETRIES:
        try:
            await asyncio.sleep(RATE_LIMIT_DELAY + random.uniform(-0.2, 0.2))
            headers={'User-Agent': get_random_user_agent()}
            async with session.get(url, timeout=DEFAULT_TIMEOUT, headers=headers) as response:
                page_report["status_code"] = response.status
                response.raise_for_status()
                if verbose:
                    logging.debug(f"[DEBUG] Successful request to {url}, Status Code: {response.status}")

                try:
                    r_html_sync = HTMLSession()
                    r_html = r_html_sync.get(url, timeout=DEFAULT_TIMEOUT, headers=headers)
                    r_html.html.render(timeout=JS_RENDER_TIMEOUT)
                    if deep_crawl:
                        absolute_links = [link for link in r_html.html.absolute_links if is_same_domain(url_objetivo, link)]
                        for link in absolute_links:
                            if link not in visited_urls and (link, depth + 1) not in crawl_queue:
                                crawl_queue.append((link, depth + 1))

                    forms = r_html.html.find('form')
                    for form in forms:
                        form_details = extract_form_details(url, form)
                        points_of_entry["forms"].append(form_details)
                        page_report["forms"].append(form_details)

                    points_of_entry["urls"].append({"url": url, "status_code": response.status})
                    report_data.append(page_report)

                    if not verbose and pbar:
                        pbar.update(1)
                        description = "[{percentage:3.0f}%] {n_fmt}/{total_fmt} {rate_fmt}  job:1/1  errors:0".format(
                            percentage=pbar.n / pbar.total * 100 if pbar.total else 0,
                            n_fmt=pbar.n,
                            total_fmt=pbar.total,
                            rate_fmt=f"{pbar.avg_time:.2f}s/it" if hasattr(pbar, 'avg_time') and pbar.avg_time else "N/A"
                        )
                        pbar.set_description(description, refresh=True)
                    return

                except Exception as e_render:
                    if verbose:
                        logging.warning(f"    [!] Warning: Error rendering javascript on {url}: {e_render}")

        except aiohttp.ClientError as e_request:
            retries += 1
            if verbose:
                logging.warning(f"    [!] Attempt {retries}/{MAX_RETRIES} failed to access {url}: {e_request}")
                logging.debug(f"[DEBUG] Failed request to {url} (ClientError): {e_request}, Retries: {retries}/{MAX_RETRIES}")
            if retries < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY)
            else:
                if verbose:
                    logging.error(f"    [X] Critical error accessing {url} After {MAX_RETRIES} Retries: {e_request}")
                page_report["status_code"] = str(e_request)
                report_data.append(page_report)
                return
        except Exception as e_general:
            if verbose:
                logging.error(f"    [!] Unexpected error processing {url}: {e_general}")
                logging.debug(f"[DEBUG] General error in crawl_page for {url}: {e_general}")
            page_report["status_code"] = str(e_general)
            report_data.append(page_report)
            return
    if verbose:
        logging.debug(f"[DEBUG] Exiting crawl_page for URL: {url}")


def extract_form_details(page_url, form_element):
    """Extract relevant details from an element <form>."""
    form_details = {
        "url": page_url,
        "form_action": form_element.attrs.get('action'),
        "form_method": form_element.attrs.get('method', 'get').lower(),
        "inputs": []
    }
    for input_field in form_element.find('input'):
        input_details = {
            "type": input_field.attrs.get('type', 'text'),
            "name": input_field.attrs.get('name'),
            "id": input_field.attrs.get('id'),
        }
        form_details["inputs"].append(input_details)
    return form_details


def detect_hidden_paths(base_url, common_dirs_file=COMMON_DIRECTORIES_FILE, common_files_file=COMMON_FILES_FILE, verbose=False, accurate=False, pbar=None, total_paths=0):
    """Detect common hidden directories and files using wordlists."""
    if verbose:
        logging.debug(f"[DEBUG] Entering detect_hidden_paths for base_url: {base_url}")
        logging.info(f"  [*] Detecting common hidden paths in: {base_url}")
    else:
        print(f"  [*] Detecting common hidden paths in: {base_url}...")

    hidden_paths_detected = []

    directories_wordlist = load_wordlist(common_dirs_file)
    files_wordlist = load_wordlist(common_files_file)
    wordlists = [] # List to iterate over both wordlists

    if directories_wordlist:
        wordlists.append({"type": "directory", "list": directories_wordlist})
    if files_wordlist:
        wordlists.append({"type": "file", "list": files_wordlist})


    for wordlist_config in wordlists:
        wordlist_type = wordlist_config["type"]
        wordlist = wordlist_config["list"]

        if verbose:
            logging.info(f"    [*] Testing {wordlist_type}s common from: {common_dirs_file if wordlist_type == 'directory' else common_files_file}")

        check_function = check_path_exists_accurate if accurate else check_path_exists_fast
        for item in wordlist:
            url_to_check = urljoin(base_url, item)
            if check_function(url_to_check, verbose=verbose):
                if verbose:
                    logging.info(f"      [+] {wordlist_type.capitalize()} common found: {url_to_check}")
                hidden_paths_detected.append({"path_type": wordlist_type, "url": url_to_check})
                if not verbose and pbar:
                    pbar.update(1)
                    description = "[{percentage:3.0f}%] {n_fmt}/{total_fmt} {rate_fmt}  job:1/1  errors:0".format(
                        percentage=pbar.n / pbar.total * 100 if pbar.total else 0,
                        n_fmt=pbar.n,
                        total_fmt=pbar.total,
                        rate_fmt=f"{pbar.avg_time:.2f}paths/s" if hasattr(pbar, 'avg_time') and pbar.avg_time else "N/A"
                    )
                    pbar.set_description(description, refresh=True)
            elif not verbose and pbar:
                pbar.update(1)
                description = "[{percentage:3.0f}%] {n_fmt}/{total_fmt} {rate_fmt}  job:1/1  errors:0".format(
                    percentage=pbar.n / pbar.total * 100 if pbar.total else 0,
                    n_fmt=pbar.n,
                    total_fmt=pbar.total,
                    rate_fmt=f"{pbar.avg_time:.2f}paths/s" if hasattr(pbar, 'avg_time') and pbar.avg_time else "N/A"
                )
                pbar.set_description(description, refresh=True)


    if verbose:
        logging.debug("[DEBUG] Exiting detect_hidden_paths")
    return hidden_paths_detected


def load_wordlist(filepath):
    """Load a wordlist from a text file."""
    if '../' in filepath or '..\\' in filepath:
        raise Exception('Invalid file path')
    if not os.path.exists(filepath):
        if verbose:
            logging.warning(f"    [!] Warning: wordlist not found at: {filepath}")
        return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f]
    except Exception as e:
        logging.error(f"    [!] Error loading wordlist from {filepath}: {e}")
        return None


def check_path_exists_fast(url, verbose=False):
    """Verify if a url exists (returns 200 status code) quickly with HEAD."""
    try:
        response = HTMLSession().head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if verbose:
            logging.debug(f"[DEBUG - check_path_exists_fast] URL: {url}, Status Code: {response.status_code}")
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def check_path_exists_accurate(url, verbose=False):
    """Verify if a url exists more accurately with GET and content analysis."""
    try:
        session_sync = HTMLSession()
        session_sync.headers['User-Agent'] = get_random_user_agent()
        response = session_sync.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if verbose:
            logging.debug(f"[DEBUG - check_path_exists_accurate] URL: {url}, Status Code: {response.status_code}")

        if response.status_code == 200:
            if NOT_FOUND_PATTERNS.search(response.text):
                if verbose:
                    logging.info(f"      [>] Detected 'not found' pattern in the content of: {url}. likely false positive.")
                return False
            else:
                return True
        return False

    except requests.exceptions.TooManyRedirects:
        if verbose:
            logging.warning(f"      [>] Too many redirects for: {url}. assuming it doesn't exist.")
        return False
    except requests.exceptions.RequestException:
        return False


def analyze_contextually(points, visited_urls, detailed=False, enable_fuzz=False, verbose=False, detect_hidden=False):
    """
    Perform an enhanced contextual analysis of entry points, including extended fuzzing.
    """
    if verbose:
        logging.debug("[DEBUG] Entering analyze_contextually")
        logging.info("\n[+] Summary of identified entry points:")
        logging.info(f"  - Total URLS crawled: {len(visited_urls)}")
        logging.info(f"  - URLS identified as entry points: {len(points['urls'])}")
        logging.info(f"  - Forms identified as entry points: {len(points['forms'])}")
        if detect_hidden:
            logging.info(f"  - Common hidden paths detected: {len(points['hidden_paths'])}")
    else:
        print("\n[+] Summary of identified entry points:")
        print(f"  - Total URLS crawled: {len(visited_urls)}")
        print(f"  - URLs identified as entry points {len(points['urls'])}")
        print(f"  - Forms identified as entry points: {len(points['forms'])}")
        if detect_hidden:
            print(f"  - Common hidden paths detected: {len(points['hidden_paths'])}")


    if points['urls']:
        if verbose:
            logging.info("\n  [+] Entry point URLs:")
        else:
            print("\n  [+] Entry point URLs:")
        for url_point in points['urls']:
            if verbose:
                logging.info(f"    - URL: {url_point['url']}, Status Code: {url_point['status_code']}")
                if detailed:
                    analyze_url_context(url_point['url'], verbose=verbose)
                if enable_fuzz:
                    fuzz_url_parameters(url_point['url'], verbose=verbose)
            else:
                print(f"    - URL: {url_point['url']}, Status Code: {url_point['status_code']}")


    if points['forms']:
        if verbose:
            logging.info("\n  [+] Entry point forms:")
        else:
            print("\n  [+] Entry point forms:")
        for form_point in points['forms']:
            if verbose:
                logging.info(f"    - URL Form: {form_point['url']}")
                logging.info(f"    - Action: {form_point['form_action']}")
                logging.info(f"    - Method: {form_point['form_method']}")
                logging.info("    - Inputs:")
                for input_detail in form_point['inputs']:
                    logging.info(f"      - Name: {input_detail['name']}, Type: {input_detail['type']}, ID: {input_detail['id']}")
                    if detailed:
                        analyze_form_input_context(input_detail, verbose=verbose)
                logging.info("-" * 20)
            else:
                print(f"    - URL Form: {form_point['url']}")
                print(f"    - Action: {form_point['form_action']}")
                print(f"    - Method: {form_point['form_method']}")
                print("    - Inputs:")
                for input_detail in form_point['inputs']:
                    print(f"      - Name: {input_detail['name']}, Type: {input_detail['type']}, ID: {input_detail['id']}")
                print("-" * 20)

    if detect_hidden and points['hidden_paths']:
        if verbose:
            logging.info("\n  [+] Common hidden paths detected:")
        else:
            print("\n  [+] Common hidden paths detected:")
        for hidden_path in points['hidden_paths']:
            if verbose:
                logging.info(f"    - Type: {hidden_path['path_type']}, URL: {hidden_path['url']}")
            else:
                print(f"    - Type: {hidden_path['path_type']}, URL: {hidden_path['url']}")
    if verbose:
        logging.debug("[DEBUG] Exiting analyze_contextually")


def analyze_url_context(url, verbose=False):
    """Detailed contextual URL analysis."""
    if verbose:
        logging.debug(f"[DEBUG] Entering analyze_url_context for URL: {url}")
        logging.info("      [Context Analysis - URL]:")
        parsed_url = urlparse(url)
        path = parsed_url.path
        query_params = parsed_url.query

        if API_ENDPOINT_REGEX.search(path):
            logging.info("        [+] It appears to be an API endpoint (due to the path or extension)")
            logging.info("          [+] Possible tests: API endpoint fuzzing, authorization/authentication testing, schema analysis (if available)")

        if query_params:
            logging.info("        [+] GET Parameters Detected:")
            params = query_params.split('&')
            for param in params:
                param_name = param.split('=')[0] if '=' in param else param
                logging.info(f"          - {param_name}")
                if INTERESTING_PARAMS_REGEX.search(param_name):
                    logging.info(f"            [+] Potentially interesting parameter: {param_name} (common names: id, user, etc.)")
                    logging.info(f"              [+] Possible tests: Parameter fuzzing, injection testing (SQLi, Command Injection, XSS), value manipulation")
                else:
                    logging.info(f"              [+] Possible tests: Parameter fuzzing (unexpected values, boundary values)")
    if verbose:
        logging.debug("[DEBUG] Exiting analyze_url_context")


def analyze_form_input_context(input_detail, verbose=False):
    """Detailed contextual analysis of form inputs"""
    if verbose:
        logging.debug(f"[DEBUG] Entering analyze_form_input_context for input: {input_detail}")
        logging.info("      [Context Analysis - Input]:")
        input_type = input_detail['type']
        input_name = input_detail['name']

        logging.info(f"        - Type: {input_type}, Name: {input_name}")

        if input_type == "password":
            logging.info("          [+] Password field detected")
            logging.info("            [+] Possible tests: Brute force (with caution, common password lists), password management testing, password recovery vulnerabilities")
        elif input_type == "email":
            logging.info("          [+] Email field detected")
            logging.info("            [+] Possible tests: Registration/login tests, possible user enumeration, email format validation, email spam/abuse attacks")
        elif input_type == "text" or input_type == "search" or input_type == "textarea":
            logging.info("          [+] Text/search/textarea field detected")
            logging.info("            [+] Possible tests: XSS (in all text fields), Command/SQL/LDAP Injection (in relevant fields), HTML Injection, input validation tests, data manipulation")
            if input_name and INTERESTING_PARAMS_REGEX.search(input_name):
                 logging.info(f"            [+] Text field with potentially interesting name: {input_name} (Common names: search, query, etc)")
        elif input_type == "hidden":
            logging.info("          [+] Hidden field detected")
            logging.info("            [+] Possible tests: Value manipulation (in requests), check if it contains sensitive information (CSRF tokens, etc.), test if the application relies on this value for security")
        elif input_type == "select" or input_type == "radio" or input_type == "checkbox":
            logging.info("          [+] Selection/radio/checkbox field detected")
            logging.info("            [+] Possible tests: Value manipulation (out of range, unexpected values), test if the application handles different options correctly, client vs. server-side validation")
    if verbose:
        logging.debug("[DEBUG] Exiting get_form_input_context_report")


def fuzz_url_parameters(url, verbose=False):
    """Perform extended GET parameter fuzzing on a URL with wider payloads and error detection."""
    if verbose:
        logging.debug(f"[DEBUG] Entering fuzz_url_parameters for URL: {url}")
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        query_params = parsed_url.query
        if not query_params:
            logging.info("        [!] No GET parameters found to fuzz on this URL.")
            return

        params = query_params.split('&')
        param_names = [param.split('=')[0] if '=' in param else param for param in params]

        for param_name in param_names:
            logging.info(f"        [*] Parameter fuzzing: {param_name}")
            if INTERESTING_PARAMS_REGEX.search(param_name):
                logging.info(f"          [~] Parameter '{param_name}' matches interesting names. More relevant injection and manipulation tests")
            for payload in FUZZING_PAYLOADS_EXTENDED:
                fuzz_url = base_url + "?" + query_params.replace(param_name + "=", param_name + "=" + payload)

                try:
                    session_sync = HTMLSession()
                    session_sync.headers['User-Agent'] = get_random_user_agent()
                    response = session_sync.get(fuzz_url, timeout=DEFAULT_TIMEOUT)
                    if response.status_code != 200 and response.status_code != 404:
                        logging.warning(f"          [!] Unusual HTTP status code ({response.status_code}) payload for: {payload}, URL: {fuzz_url}")
                        logging.warning(f"              [>] Possible point of interest. Review response manually")
                    if SQL_ERROR_REGEX.search(response.text):
                        logging.critical(f"          [!!!] Possible SQL Injection Detected (by SQL error) for payload: {payload}, URL: {fuzz_url}")
                        logging.critical(f"              [!!!] ¡¡¡POTENTIAL CRITICAL VULNERABILITY!!! Review IMMEDIATELY.")
                    if COMMAND_INJECTION_ERROR_REGEX.search(response.text):
                        logging.critical(f"          [!!!] Possible Command Injection Detected (by command error) for payload: {payload}, URL: {fuzz_url}")
                        logging.critical(f"              [!!!] ¡¡¡POTENTIAL CRITICAL VULNERABILITY!!! Review IMMEDIATELY.")
                    if len(response.content) > 6000:
                        logging.info(f"          [~] Significantly longer response length ({len(response.content)} bytes) for payload: {payload}, URL: {fuzz_url}")
                        logging.info(f"              [~] Could indicate an interesting response or vulnerability. Review.")

                except requests.exceptions.RequestException as e:
                    logging.error(f"          [!] Request error while fuzzing with payload: {payload}: {e}")
    if verbose:
        logging.debug("[DEBUG] Exiting fuzz_url_parameters")


def generate_report(report_data, points, visited_urls, output_filepath=None, execution_time=0, url_objetivo=None, deep_crawl=False, detect_hidden=False, detailed_analysis=False, enable_fuzzing=False, crawl_depth=CRAWL_DEPTH_LIMIT, verbose=False, accurate_hidden=False):
    """Generate a detailed text report with the results, including execution time and configuration."""
    if verbose:
        logging.debug("[DEBUG] Entering generate_report")
        report_content = "[+] Dynamic Attack Surface Analyzer Report (Asynchronous)\n"
        report_content += f"Target URL: {url_objetivo}\n"
        report_content += f"Execution Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_content += f"Total Execution Time: {execution_time:.2f} seconds\n"
        report_content += "\n[+] Analysis Configuration:\n"
        report_content += f"  - Deep Crawl: {deep_crawl}\n"
        report_content += f"  - Hidden Route Detection: {detect_hidden} (Precise: {accurate_hidden})\n"
        report_content += f"  - Detailed Analysis: {detailed_analysis}\n"
        report_content += f"  - Fuzzing Enabled: {enable_fuzzing}\n"
        report_content += f"  - Tracking Depth: {crawl_depth}\n\n"

        report_content += "[+] Summary of Entry Points:\n"
        report_content += f"  - Total URLs crawled: {len(visited_urls)}\n"
        report_content += f"  - URLs identified as entry points: {len(points['urls'])}\n"
        report_content += f"  - Forms identified as entry points: {len(points['forms'])}\n"
        if detect_hidden:
            report_content += f"  - Common hidden routes detected: {len(points['hidden_paths'])}\n\n"

        if points['urls']:
            report_content += "[+] URLs Entry Points:\n"
            for url_point in points['urls']:
                report_content += f"    - URL: {url_point['url']}, Status Code: {url_point['status_code']}\n"
                if detailed_analysis:
                    report_content += get_url_context_report(url_point['url'], verbose=verbose)

        if points['forms']:
            report_content += "\n[+] Entry Points Forms:\n"
            for form_point in points['forms']:
                report_content += f"    - URL Form: {form_point['url']}\n"
                report_content += f"    - Action: {form_point['form_action']}\n"
                report_content += f"    - Method: {form_point['form_method']}\n"
                report_content += "    - Inputs:\n"
                for input_detail in form_point['inputs']:
                    report_content += f"      - Name: {input_detail['name']}, Type: {input_detail['type']}, ID: {input_detail['id']}\n"
                    if detailed_analysis:
                        report_content += get_form_input_context_report(input_detail, verbose=verbose)
                report_content += "-" * 20 + "\n"

        if detect_hidden and points['hidden_paths']:
            report_content += "\n[+] Common Hidden Routes Detected:\n"
            for hidden_path in points['hidden_paths']:
                report_content += f"    - Tipo: {hidden_path['path_type']}, URL: {hidden_path['url']}\n"
        if verbose:
            logging.debug("[DEBUG] Leaving generate_report")
    else:
        report_content = "[+] Dynamic Attack Surface Analyzer (Asynchronous) report\n"
        report_content += f"Target URL {url_objetivo}\n"
        report_content += f"Date and Time of Execution: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_content += f"Total Execution Time: {execution_time:.2f} seconds\n"
        report_content += "\n[+] Summary of Entry Points::\n"
        report_content += f"  - Total URLs crawled: {len(visited_urls)}\n"
        report_content += f"  - URLs identified as entry points {len(points['urls'])}\n"
        report_content += f"  - Forms identified as entry points: {len(points['forms'])}\n"
        if detect_hidden:
            report_content += f"  - Common hidden routes detected: {len(points['hidden_paths'])}\n\n"

        if points['urls']:
            report_content += "[+] URLs Entry Points:\n"
            for url_point in points['urls']:
                report_content += f"    - URL: {url_point['url']}, Status Code: {url_point['status_code']}\n"
                if detailed_analysis:
                    report_content += get_url_context_report(url_point['url'], verbose=verbose)

        if points['forms']:
            report_content += "\n[+] Entry Points Forms:\n"
            for form_point in points['forms']:
                report_content += f"    - URL Form: {form_point['url']}\n"
                report_content += f"    - Action: {form_point['form_action']}\n"
                report_content += f"    - Method: {form_point['form_method']}\n"
                report_content += "    - Inputs:\n"
                for input_detail in form_point['inputs']:
                    report_content += f"      - Name: {input_detail['name']}, Type: {input_detail['type']}, ID: {input_detail['id']}\n"
                    if detailed_analysis:
                        report_content += get_form_input_context_report(input_detail, verbose=verbose)
            report_content += "-" * 20 + "\n"

        if detect_hidden and points['hidden_paths']:
            report_content += "\n[+] Common Hidden Routes Detected:\n"
            for hidden_path in points['hidden_paths']:
                report_content += f"    - Type: {hidden_path['path_type']}, URL: {hidden_path['url']}\n"


    if output_filepath:
        if '../' in output_filepath or '..\\' in output_filepath:
            raise Exception('Invalid file path')
        try:
            with open(output_filepath, 'w', encoding='utf-8') as outfile:
                outfile.write(report_content)
            if verbose:
                logging.info(f"[*] Report saved in: {output_filepath}")
        except Exception as e:
            logging.error(f"[!] Error saving report to file: {e}")
    else:
        if verbose:
            print("\n[+] Report Generated:\n")
            print(report_content)
    if verbose:
        logging.debug("[DEBUG] Leaving generate_report")


def get_url_context_report(url, verbose=False):
    """Generate a report fragment with detailed contextual analysis of URLs."""
    if verbose:
        logging.debug(f"[DEBUG] Entering get_url_context_report for URL: {url}")
        report_fragment = "      [Context Analysis - URL]:\n"
        parsed_url = urlparse(url)
        path = parsed_url.path
        query_params = parsed_url.query

        if API_ENDPOINT_REGEX.search(path):
            report_fragment += "        [+] It seems to be an API endpoint (by the path or extension)\n"
            report_fragment += "          [+] Possible tests: Fuzzing of API endpoints, authorization/authentication tests, schema analysis (if available)\n"

        if query_params:
            report_fragment += "        [+] Detected GET Parameters:\n"
            params = query_params.split('&')
            for param in params:
                param_name = param.split('=')[0] if '=' in param else param
                report_fragment += f"          - {param_name}\n"
                if INTERESTING_PARAMS_REGEX.search(param_name):
                    report_fragment += f"            [+] Possibly interesting parameter: {param_name} (common names: id, user, etc.)\n"
                    report_fragment += f"              [+] Possible tests: Parameter fuzzing, injection tests (SQLi, Command Injection, XSS), value manipulation\n"
                else:
                    report_fragment += f"              [+] Possible tests: Parameter fuzzing (unexpected values, boundary values)\n"
        if verbose:
            logging.debug("[DEBUG] Leaving get_url_context_report")
        return report_fragment
    else:
        return ""


def get_form_input_context_report(input_detail, verbose=False):
    """Generates report fragment with detailed contextual analysis of form inputs."""
    if verbose:
        logging.debug(f"[DEBUG] Entering get_form_input_context_report for input: {input_detail}")
        report_fragment = "      [Context Analysis - Input]:\n"
        input_type = input_detail['type']
        input_name = input_detail['name']

        report_fragment += f"        - Type: {input_type}, Name: {input_name}\n"

        if input_type == "password":
            report_fragment += "          [+] Password field detected\n"
            report_fragment += "            [+] Possible tests: Brute force (with caution, lists of common passwords), password management tests, password recovery vulnerabilities\n"
        elif input_type == "email":
            report_fragment += "          [+] Email field detected\n"
            report_fragment += "            [+] Possible tests: Registration/login tests, possible enumeration of users, email format validation, spam attacks/email abuse\n"
        elif input_type == "text" or input_type == "search" or input_type == "textarea":
            report_fragment += "          [+] Text/search/textarea field detected\n"
            report_fragment += "            [+] Possible tests: XSS (in all text fields), Command Injection/SQL/LDAP (in relevant fields), HTML Injection, input validation tests, data manipulation\n"
            if input_name and INTERESTING_PARAMS_REGEX.search(input_name):
                 report_fragment += f"            [+] Text field with possibly interesting name:: {input_name} (common names: search, query, etc.)\n"
        elif input_type == "hidden":
            report_fragment += "          [+] Hidden field detected\n"
            report_fragment += "            [+] Possible tests: Value manipulation (in requests), verify if it contains sensitive information (CSRF tokens, etc.), test if the application depends on this value for security\n"
        elif input_type == "select" or input_type == "radio" or input_type == "checkbox":
            report_fragment += "          [+] Selection field/radio/checkbox detected\n"
            report_fragment += "            [+] Possible tests: Manipulation of values (out of range, unexpected values), test if the application correctly handles different options, validation in client vs server\n"
        if verbose:
            logging.debug("[DEBUG] Leaving get_form_input_context_report")
        return report_fragment
    else:
        return ""

def get_random_user_agent():
    """Returns a random User-Agent from the list."""
    return random.choice(USER_AGENTS)

def check_robots_txt(base_url, path_to_check):
    """Check if robots.txt allows tracking of a URL."""
    parsed_url = urlparse(base_url)
    robots_url = urljoin(base_url, 'robots.txt')
    robot_parser = RobotFileParser()
    robot_parser.set_url(robots_url)
    try:
        robot_parser.read()
    except:
        return True
    return robot_parser.can_fetch("*", path_to_check) # Use a wildcard user-agent "*"


def is_same_domain(url1, url2):
    """Check if two URLs belong to the same domain."""
    return urlparse(url1).netloc == urlparse(url2).netloc
def main():
    parser = argparse.ArgumentParser(description="DASA - ASYNC EDITION")
    parser.add_argument("url", help="Target URL to analyze (ex: https://example.com)")
    parser.add_argument("-o", "--output", help="File to save the report (optional)")
    parser.add_argument("--deep", action="store_true", help="Enable deep tracking (follow links)")
    parser.add_argument("--hidden", action="store_true", help="Detect common hidden routes")
    parser.add_argument("--fuzz", action="store_true", help="Enable basic fuzzing of GET parameters")
    parser.add_argument("--accurate-hidden", action="store_true", help="More accurate hidden path detection (slow)")
    parser.add_argument("--detailed", action="store_true", help="Enable detailed contextual analysis")
    parser.add_argument("--depth", type=int, default=CRAWL_DEPTH_LIMIT, help=f"Maximum tracking depth (default: {CRAWL_DEPTH_LIMIT})")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode for more details in console")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', stream=open(os.devnull, 'w') if not args.verbose else None)

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        args.url = "https://" + args.url # Assume https if no protocol is specified

    asyncio.run(dynamic_attack_surface_analyzer(
        url_objetivo=args.url,
        output_file=args.output,
        deep_crawl=args.deep,
        detect_hidden=args.hidden,
        detailed_analysis=args.detailed,
        enable_fuzzing=args.fuzz,
        crawl_depth=args.depth,
        verbose=args.verbose,
        accurate_hidden=args.accurate_hidden
    ))

if __name__ == "__main__":
    main()