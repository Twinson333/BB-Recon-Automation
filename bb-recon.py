#!/usr/bin/env python3
"""
Bug Bounty Recon Orchestrator – Enhanced Edition
Features:
- Streaming command execution to handle massive output
- Resume with .done markers (avoid partial results)
- Single httpx JSON probe (title, server, status, etc.)
- Optional Nuclei scanning (with templates)
- Configurable naabu rate, max screenshots, hakrawler limit
- Optional port scanning (--skip-port-scan)
- Optional screenshots (--screenshots)
- Logging module integration
- Process group cleanup on interrupt
"""

import os
import re
import sys
import json
import time
import shutil
import signal
import logging
import argparse
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional, Tuple, Any

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("bb_recon")

# -----------------------------------------------------------------------------
# Helper: streaming subprocess with line callback
# -----------------------------------------------------------------------------
def run_cmd_stream(
    cmd: List[str],
    stdin_data: Optional[str] = None,
    timeout: int = 600,
    line_callback: Optional[callable] = None,
) -> int:
    """
    Execute a command, optionally feed stdin, and call line_callback for each stdout line.
    Returns returncode. Stderr is logged.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
        if stdin_data:
            proc.stdin.write(stdin_data)
            proc.stdin.close()

        # Read stdout line by line
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line_callback:
                line_callback(line)

        # Wait with timeout
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            logger.error(f"Timeout ({timeout}s) on {' '.join(cmd)}")
            return -1

        if stderr:
            logger.debug(f"Stderr from {cmd[0]}: {stderr[:500]}")

        return proc.returncode

    except Exception as e:
        logger.error(f"Exception running {' '.join(cmd)}: {e}")
        return -1


def run_cmd_collect(cmd: List[str], stdin_data: str = None, timeout: int = 600) -> str:
    """Legacy: collect all output as string (only for small outputs)."""
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
        if proc.stderr:
            logger.debug(f"Stderr from {cmd[0]}: {proc.stderr[:500]}")
        return proc.stdout or ""
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout on {' '.join(cmd)}")
        return ""
    except Exception as e:
        logger.error(f"Exception: {e}")
        return ""


# -----------------------------------------------------------------------------
# Main orchestrator class
# -----------------------------------------------------------------------------
class BugBountyRecon:
    def __init__(
        self,
        domain: str,
        threads: int = 8,
        timeout: int = 600,
        katana_depth: int = 3,
        passive_only: bool = False,
        enable_screenshots: bool = False,
        resume: bool = False,
        clean_tmp: bool = False,
        run_nuclei: bool = False,
        skip_port_scan: bool = False,
        naabu_rate: int = 1000,
        max_screenshots: int = 500,
        hakrawler_limit: int = 500,
        nuclei_templates: Optional[str] = None,
    ):
        self.domain = self._validate_domain(domain)
        self.threads = threads
        self.timeout = timeout
        self.katana_depth = katana_depth
        self.passive_only = passive_only
        self.enable_screenshots = enable_screenshots
        self.resume = resume
        self.clean_tmp = clean_tmp
        self.run_nuclei = run_nuclei
        self.skip_port_scan = skip_port_scan
        self.naabu_rate = naabu_rate
        self.max_screenshots = max_screenshots
        self.hakrawler_limit = hakrawler_limit
        self.nuclei_templates = nuclei_templates  # optional custom template path

        self.start_time = time.time()

        self.base = Path(f"bb_recon_{self.domain}")
        self.raw = self.base / "raw"
        self.logs = self.base / "logs"
        self.out = self.base / "out"
        self.tmp = self.base / "tmp"
        self.done_dir = self.base / ".done"

        for d in [self.base, self.raw, self.logs, self.out, self.tmp, self.done_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self.tools = self._detect_tools()
        self.stats: Dict[str, Any] = {
            "domain": self.domain,
            "start_time_epoch": int(self.start_time),
            "phases": {},
        }

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    def _validate_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
        # More permissive regex (allow underscores)
        if not re.match(r"^[a-z0-9_.-]+$", domain):
            raise ValueError(f"Invalid domain characters: {domain}")
        return domain

    def _phase_done(self, phase: str) -> bool:
        return (self.done_dir / phase).exists()

    def _mark_done(self, phase: str):
        (self.done_dir / phase).touch()

    def _safe_read(self, path: Path) -> List[str]:
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]

    def _write_lines(self, path: Path, lines: List[str]) -> List[str]:
        clean = sorted(set(filter(None, (x.strip() for x in lines))))
        if clean:
            path.write_text("\n".join(clean) + "\n", encoding="utf-8")
        else:
            path.write_text("", encoding="utf-8")
        return clean

    def _append_lines(self, path: Path, lines: List[str]) -> List[str]:
        existing = set(self._safe_read(path))
        existing.update(lines)
        return self._write_lines(path, list(existing))

    def _in_scope_host(self, host: str) -> bool:
        host = (host or "").lower()
        return host == self.domain or host.endswith("." + self.domain)

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url.strip())
            if parsed.scheme not in ("http", "https"):
                return ""
            host = parsed.hostname or ""
            if not host:
                return ""
            path = re.sub(r"/{2,}", "/", parsed.path or "/")
            query = parsed.query
            port = parsed.port
            if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
                netloc = host
            elif port:
                netloc = f"{host}:{port}"
            else:
                netloc = host
            return urlunparse((parsed.scheme, netloc, path.rstrip("/") or "/", "", query, ""))
        except Exception:
            return ""

    def _filter_scope_urls(self, urls: List[str]) -> List[str]:
        out = []
        for u in urls:
            norm = self._normalize_url(u)
            if norm and self._in_scope_host(urlparse(norm).hostname or ""):
                out.append(norm)
        return sorted(set(out))

    def _detect_tools(self) -> Dict[str, Optional[str]]:
        tools = [
            "subfinder", "assetfinder", "findomain", "amass", "chaos",
            "httpx", "waybackurls", "gau", "gauplus", "katana", "arjun",
            "naabu", "dnsx", "gowitness", "hakrawler", "nuclei"
        ]
        return {t: shutil.which(t) for t in tools}

    def _show_tools(self):
        logger.info("=== Tool Status ===")
        for k, v in self.tools.items():
            logger.info(f"{k:12} : {'OK' if v else 'MISSING'}")
        logger.info("===================")

    # -------------------------------------------------------------------------
    # Phase 1: Subdomains (streaming-aware)
    # -------------------------------------------------------------------------
    def _enumerate_subdomains(self) -> Path:
        logger.info("--- Phase 1: Subdomain Enumeration ---")
        out_file = self.raw / "subdomains.txt"

        if self.resume and self._phase_done("subdomains"):
            logger.info("Resume: using existing subdomains.txt")
            return out_file

        subs: Set[str] = set()
        jobs = []
        if self.tools["subfinder"]:
            jobs.append(("subfinder", ["subfinder", "-d", self.domain, "-all", "-silent"]))
        if self.tools["assetfinder"]:
            jobs.append(("assetfinder", ["assetfinder", "--subs-only", self.domain]))
        if self.tools["findomain"]:
            jobs.append(("findomain", ["findomain", "-t", self.domain, "-q"]))
        if self.tools["amass"]:
            jobs.append(("amass", ["amass", "enum", "-passive", "-d", self.domain, "-silent"]))
        if self.tools["chaos"]:
            jobs.append(("chaos", ["chaos", "-d", self.domain, "-silent"]))

        def collect_line(line: str, name: str):
            line = line.strip().lower()
            if self._in_scope_host(line):
                subs.add(line)
                logger.debug(f"{name}: {line}")

        with ThreadPoolExecutor(max_workers=min(self.threads, len(jobs))) as ex:
            futures = []
            for name, cmd in jobs:
                futures.append(ex.submit(run_cmd_stream, cmd, None, self.timeout, lambda l, n=name: collect_line(l, n)))
            for fut in futures:
                fut.result()

        self._write_lines(out_file, list(subs))
        logger.info(f"Unique subdomains: {len(subs)}")
        self.stats["phases"]["subdomains"] = {"count": len(subs)}
        self._mark_done("subdomains")
        return out_file

    # -------------------------------------------------------------------------
    # Phase 2: DNS resolve (streaming)
    # -------------------------------------------------------------------------
    def _resolve_subdomains(self, sub_file: Path) -> Path:
        logger.info("--- Phase 2: DNS Resolution ---")
        out_file = self.raw / "resolved_subdomains.txt"
        if self.resume and self._phase_done("resolve"):
            logger.info("Resume: using existing resolved_subdomains.txt")
            return out_file

        subs = self._safe_read(sub_file)
        if not subs:
            self._write_lines(out_file, [])
            self._mark_done("resolve")
            return out_file

        resolved: Set[str] = set()
        if self.tools["dnsx"]:
            stdin = "\n".join(subs) + "\n"
            def cb(line: str):
                line = line.strip()
                if self._in_scope_host(line):
                    resolved.add(line)
            run_cmd_stream(["dnsx", "-silent"], stdin, self.timeout, cb)
        else:
            resolved.update(subs)

        self._write_lines(out_file, list(resolved))
        logger.info(f"Resolved subdomains: {len(resolved)}")
        self.stats["phases"]["resolve"] = {"count": len(resolved)}
        self._mark_done("resolve")
        return out_file

    # -------------------------------------------------------------------------
    # Phase 3: Port scan (optional)
    # -------------------------------------------------------------------------
    def _scan_ports(self, resolved_file: Path) -> Path:
        logger.info("--- Phase 3: Port Discovery ---")
        out_file = self.raw / "open_ports.txt"

        # If user explicitly skips port scan
        if self.skip_port_scan:
            logger.info("Port scan skipped via --skip-port-scan")
            self._write_lines(out_file, [])
            self.stats["phases"]["ports"] = {"skipped": True}
            self._mark_done("ports")
            return out_file

        # If passive-only mode (also skips port scan and crawlers)
        if self.passive_only:
            logger.info("Passive-only: skipping port scan")
            self._write_lines(out_file, [])
            self.stats["phases"]["ports"] = {"skipped": True}
            self._mark_done("ports")
            return out_file

        if self.resume and self._phase_done("ports"):
            logger.info("Resume: using existing open_ports.txt")
            return out_file

        if not self.tools["naabu"]:
            logger.warning("naabu not found; skipping port scan")
            self._write_lines(out_file, [])
            self._mark_done("ports")
            return out_file

        hosts = self._safe_read(resolved_file)
        if not hosts:
            self._write_lines(out_file, [])
            self._mark_done("ports")
            return out_file

        stdin = "\n".join(hosts) + "\n"
        output = run_cmd_collect(
            ["naabu", "-silent", "-top-ports", "1000", "-rate", str(self.naabu_rate)],
            stdin,
            self.timeout
        )
        ports = self._write_lines(out_file, output.splitlines())
        logger.info(f"Open port findings: {len(ports)}")
        self.stats["phases"]["ports"] = {"count": len(ports)}
        self._mark_done("ports")
        return out_file

    # -------------------------------------------------------------------------
    # Phase 4: HTTP probing – single httpx JSON call
    # -------------------------------------------------------------------------
    def _probe_live_hosts(self, resolved_file: Path) -> Tuple[Path, Path]:
        logger.info("--- Phase 4: HTTP Probing (single httpx run) ---")
        live_urls_file = self.out / "live_urls.txt"
        meta_file = self.out / "live_metadata.txt"

        if self.resume and self._phase_done("http_probe"):
            logger.info("Resume: using existing live_urls.txt")
            return live_urls_file, meta_file

        hosts = self._safe_read(resolved_file)
        if not hosts or not self.tools["httpx"]:
            self._write_lines(live_urls_file, [])
            self._write_lines(meta_file, [])
            self._mark_done("http_probe")
            return live_urls_file, meta_file

        stdin = "\n".join(hosts) + "\n"
        # Use -json to get all info in one pass
        json_output = run_cmd_collect(
            ["httpx", "-silent", "-json",
             "-mc", "200,201,202,204,301,302,303,307,308,401,403,405,500",
             "-title", "-td", "-server", "-sc", "-cl", "-ip", "-cname"],
            stdin,
            self.timeout
        )

        clean_urls = []
        meta_lines = []
        for line in json_output.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                norm = self._normalize_url(url)
                if norm and self._in_scope_host(urlparse(norm).hostname or ""):
                    clean_urls.append(norm)
                    # Build human-readable metadata line
                    meta = f"{url} [{data.get('status_code',0)}] size:{data.get('content_length','?')} title:{data.get('title','')} server:{data.get('webserver','')}"
                    meta_lines.append(meta)
            except json.JSONDecodeError:
                continue

        self._write_lines(live_urls_file, clean_urls)
        self._write_lines(meta_file, meta_lines)
        logger.info(f"Live URLs: {len(clean_urls)}")
        self.stats["phases"]["http_probe"] = {"count": len(clean_urls)}
        self._mark_done("http_probe")
        return live_urls_file, meta_file

    # -------------------------------------------------------------------------
    # Phase 5: URL collection (streaming where possible)
    # -------------------------------------------------------------------------
    def _collect_urls(self, live_urls_file: Path) -> Path:
        logger.info("--- Phase 5: URL Collection ---")
        all_urls_file = self.raw / "all_urls.txt"
        archive_file = self.raw / "archive_urls.txt"
        crawl_file = self.raw / "crawl_urls.txt"

        if self.resume and self._phase_done("url_collection"):
            logger.info("Resume: using existing all_urls.txt")
            return all_urls_file

        live_urls = self._safe_read(live_urls_file)
        if not live_urls:
            for f in [all_urls_file, archive_file, crawl_file]:
                self._write_lines(f, [])
            self._mark_done("url_collection")
            return all_urls_file

        archive_set: Set[str] = set()
        crawl_set: Set[str] = set()

        # Archive tools – we can stream to avoid memory bloat
        stdin_data = "\n".join(live_urls) + "\n"

        def archive_cb(line: str, tool: str):
            line = line.strip()
            if line:
                archive_set.add(line)

        if self.tools["waybackurls"]:
            run_cmd_stream(["waybackurls"], stdin_data, self.timeout, lambda l: archive_cb(l, "wayback"))
        if self.tools["gau"]:
            run_cmd_stream(["gau", "--subs", "--threads", str(min(self.threads, 20))], stdin_data, self.timeout, lambda l: archive_cb(l, "gau"))
        if self.tools["gauplus"]:
            run_cmd_stream(["gauplus", "-t", str(min(self.threads, 20))], stdin_data, self.timeout, lambda l: archive_cb(l, "gauplus"))

        # Crawlers
        if not self.passive_only and self.tools["katana"]:
            # katana reads from file
            run_cmd_stream(["katana", "-list", str(live_urls_file), "-silent", "-jc", "-kf", "all", "-d", str(self.katana_depth), "-fs", "rdn"],
                           None, self.timeout, lambda l: crawl_set.add(l.strip()))

        if not self.passive_only and self.tools["hakrawler"]:
            # limit input URLs
            limited = live_urls[:self.hakrawler_limit]
            if limited:
                stdin_hak = "\n".join(limited) + "\n"
                run_cmd_stream(["hakrawler", "-plain"], stdin_hak, self.timeout, lambda l: crawl_set.add(l.strip()))

        archive_urls = self._filter_scope_urls(list(archive_set))
        crawl_urls = self._filter_scope_urls(list(crawl_set))
        all_urls = sorted(set(archive_urls + crawl_urls + live_urls))

        self._write_lines(archive_file, archive_urls)
        self._write_lines(crawl_file, crawl_urls)
        self._write_lines(all_urls_file, all_urls)

        logger.info(f"Archive URLs: {len(archive_urls)}")
        logger.info(f"Crawl URLs:   {len(crawl_urls)}")
        logger.info(f"Total URLs:   {len(all_urls)}")
        self.stats["phases"]["url_collection"] = {
            "archive": len(archive_urls),
            "crawl": len(crawl_urls),
            "total": len(all_urls)
        }
        self._mark_done("url_collection")
        return all_urls_file

    # -------------------------------------------------------------------------
    # Phase 6: Hidden parameters (Arjun)
    # -------------------------------------------------------------------------
    def _discover_hidden_params(self, live_urls_file: Path) -> Path:
        logger.info("--- Phase 6: Hidden Parameter Discovery ---")
        out_file = self.raw / "arjun_output.txt"
        if self.resume and self._phase_done("arjun"):
            logger.info("Resume: using existing arjun_output.txt")
            return out_file

        if not self.tools["arjun"]:
            self._write_lines(out_file, [])
            self._mark_done("arjun")
            return out_file

        live_urls = self._safe_read(live_urls_file)
        candidates = [u for u in live_urls if any(k in u.lower() for k in ["api", "search", "login", "auth", "user", "account", "query", "graphql"])]
        if not candidates:
            candidates = live_urls[:50]

        targets_file = self.tmp / "arjun_targets.txt"
        self._write_lines(targets_file, candidates)
        output = run_cmd_collect(["arjun", "-i", str(targets_file), "-t", str(min(self.threads, 15)), "--stable"],
                                 timeout=self.timeout)
        self._write_lines(out_file, output.splitlines())
        logger.info(f"Arjun output lines: {len(self._safe_read(out_file))}")
        self.stats["phases"]["arjun"] = {"count": len(self._safe_read(out_file))}
        self._mark_done("arjun")
        return out_file

    # -------------------------------------------------------------------------
    # Phase 7: JS extraction
    # -------------------------------------------------------------------------
    def _process_js(self, all_urls_file: Path) -> Path:
        logger.info("--- Phase 7: JavaScript Collection ---")
        js_file = self.out / "javascript_files.txt"
        urls = self._safe_read(all_urls_file)
        noise = re.compile(r"(jquery|bootstrap|gtm|analytics|font-awesome|cloudflare|recaptcha)", re.I)
        js_urls = [u for u in urls if ".js" in u.lower() and not noise.search(u.lower())]
        self._write_lines(js_file, js_urls)
        logger.info(f"JavaScript files: {len(js_urls)}")
        self.stats["phases"]["javascript"] = {"count": len(js_urls)}
        return js_file

    # -------------------------------------------------------------------------
    # Phase 8: Categorization
    # -------------------------------------------------------------------------
    def _categorize_urls(self, all_urls_file: Path):
        logger.info("--- Phase 8: URL Categorization ---")
        urls = self._safe_read(all_urls_file)
        buckets = {
            "api_endpoints.txt": [],
            "graphql_endpoints.txt": [],
            "params_urls.txt": [],
            "auth_urls.txt": [],
            "admin_urls.txt": [],
            "upload_urls.txt": [],
            "interesting_files.txt": [],
            "json_urls.txt": [],
            "redirect_candidates.txt": [],
        }
        api_rx = re.compile(r"(/api/|/v[0-9]+/|\.json(?:$|\?)|/rest/)", re.I)
        graphql_rx = re.compile(r"/graphql\b|/graphiql\b", re.I)
        auth_rx = re.compile(r"(login|signin|signup|register|reset|forgot|auth|oauth|sso|session)", re.I)
        admin_rx = re.compile(r"(admin|administrator|manage|dashboard|panel|backend|cpanel)", re.I)
        upload_rx = re.compile(r"(upload|import|attachment|file|avatar|image|media)", re.I)
        interesting_rx = re.compile(r"(\.bak|\.old|\.zip|\.tar|\.gz|\.sql|\.env|\.config|\.yml|\.yaml|\.xml|\.log|\.conf|\.ini)", re.I)
        redirect_rx = re.compile(r"([?&](next|url|redirect|redirect_uri|return|returnto|continue|dest|destination|redir)=)", re.I)

        for u in urls:
            if api_rx.search(u):
                buckets["api_endpoints.txt"].append(u)
            if graphql_rx.search(u):
                buckets["graphql_endpoints.txt"].append(u)
            if "?" in u:
                buckets["params_urls.txt"].append(u)
            if auth_rx.search(u):
                buckets["auth_urls.txt"].append(u)
            if admin_rx.search(u):
                buckets["admin_urls.txt"].append(u)
            if upload_rx.search(u):
                buckets["upload_urls.txt"].append(u)
            if interesting_rx.search(u):
                buckets["interesting_files.txt"].append(u)
            if u.lower().endswith(".json") or ".json?" in u.lower():
                buckets["json_urls.txt"].append(u)
            if redirect_rx.search(u):
                buckets["redirect_candidates.txt"].append(u)

        for name, lines in buckets.items():
            self._write_lines(self.out / name, lines)

        self.stats["phases"]["categorization"] = {k: len(v) for k, v in buckets.items()}
        logger.info("Categorization complete")

    # -------------------------------------------------------------------------
    # Phase 9: Parameter mining (URL parameters)
    # -------------------------------------------------------------------------
    def _mine_parameters(self, all_urls_file: Path):
        logger.info("--- Phase 9: Parameter Mining ---")
        urls = self._safe_read(all_urls_file)
        param_names = set()
        param_urls = set()
        for u in urls:
            if "?" not in u:
                continue
            parsed = urlparse(u)
            param_urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, "")))
            for part in parsed.query.split("&"):
                if "=" in part:
                    k = part.split("=", 1)[0].strip()
                    if k:
                        param_names.add(k)
        self._write_lines(self.out / "unique_parameters.txt", sorted(param_names))
        self._write_lines(self.out / "parameterized_urls_clean.txt", sorted(param_urls))
        logger.info(f"Unique parameters: {len(param_names)}")
        logger.info(f"Parameterized URLs: {len(param_urls)}")
        self.stats["phases"]["parameter_mining"] = {"params": len(param_names), "urls": len(param_urls)}

    # -------------------------------------------------------------------------
    # Phase 10: Nuclei target prep + optional run
    # -------------------------------------------------------------------------
    def _prepare_nuclei(self, live_urls_file: Path):
        logger.info("--- Phase 10: Nuclei Target Preparation ---")
        live = self._safe_read(live_urls_file)
        targets_file = self.out / "nuclei_targets.txt"
        high_signal_file = self.out / "nuclei_high_signal_targets.txt"
        self._write_lines(targets_file, live)

        high_signal = [u for u in live if any(k in u.lower() for k in ["admin", "api", "auth", "login", "graphql", "upload", "dashboard"])]
        self._write_lines(high_signal_file, high_signal)
        logger.info(f"Nuclei targets: {len(live)}")
        logger.info(f"High-signal targets: {len(high_signal)}")
        self.stats["phases"]["nuclei_prep"] = {"total": len(live), "high_signal": len(high_signal)}

        if self.run_nuclei and self.tools["nuclei"]:
            logger.info("--- Running Nuclei (optional) ---")
            nuclei_out = self.base / "nuclei_results.txt"
            cmd = ["nuclei", "-l", str(targets_file), "-o", str(nuclei_out), "-silent", "-stats", "-stats-interval", "10"]
            if self.nuclei_templates:
                cmd.extend(["-t", self.nuclei_templates])
            # Use streaming to see progress
            run_cmd_stream(cmd, timeout=self.timeout * 2, line_callback=lambda l: logger.info(f"Nuclei: {l[:200]}"))
            logger.info(f"Nuclei results saved to {nuclei_out}")
            self.stats["phases"]["nuclei_run"] = {"output": str(nuclei_out)}

    # -------------------------------------------------------------------------
    # Phase 11: Screenshots (optional)
    # -------------------------------------------------------------------------
    def _screenshots(self, live_urls_file: Path):
        logger.info("--- Phase 11: Screenshots ---")
        if not self.enable_screenshots:
            logger.info("Screenshots disabled (use --screenshots to enable)")
            self.stats["phases"]["screenshots"] = {"skipped": True}
            return
        if not self.tools["gowitness"]:
            logger.warning("gowitness not installed")
            return

        shots_dir = self.base / "screenshots"
        shots_dir.mkdir(exist_ok=True)
        urls = self._safe_read(live_urls_file)[:self.max_screenshots]
        if not urls:
            return
        temp_file = self.tmp / "screenshots_targets.txt"
        self._write_lines(temp_file, urls)
        run_cmd_stream(["gowitness", "scan", "file", "-f", str(temp_file), "--screenshot-path", str(shots_dir)],
                       timeout=self.timeout * 2)
        logger.info(f"Screenshots taken for {len(urls)} URLs")
        self.stats["phases"]["screenshots"] = {"count": len(urls)}

    # -------------------------------------------------------------------------
    # Summary & cleanup
    # -------------------------------------------------------------------------
    def _summarize(self):
        logger.info("--- Final Summary ---")
        self.stats["end_time_epoch"] = int(time.time())
        self.stats["duration_seconds"] = round(time.time() - self.start_time, 2)

        summary_paths = {
            "subdomains": self.raw / "subdomains.txt",
            "resolved_subdomains": self.raw / "resolved_subdomains.txt",
            "live_urls": self.out / "live_urls.txt",
            "all_urls": self.raw / "all_urls.txt",
            "javascript_files": self.out / "javascript_files.txt",
            "api_endpoints": self.out / "api_endpoints.txt",
            "auth_urls": self.out / "auth_urls.txt",
            "admin_urls": self.out / "admin_urls.txt",
            "upload_urls": self.out / "upload_urls.txt",
            "unique_parameters": self.out / "unique_parameters.txt",
            "redirect_candidates": self.out / "redirect_candidates.txt",
            "nuclei_targets": self.out / "nuclei_targets.txt",
        }
        counts = {name: len(self._safe_read(path)) for name, path in summary_paths.items()}
        self.stats["output_counts"] = counts

        # Write JSON
        (self.base / "summary.json").write_text(json.dumps(self.stats, indent=2), encoding="utf-8")

        # Write Markdown
        md = [f"# Bug Bounty Recon Summary: {self.domain}", "",
              f"- Duration: {self.stats['duration_seconds']} seconds", "",
              "## Output Counts"]
        md.extend(f"- {k}: {v}" for k, v in counts.items())
        md.extend(["", "## Phases"])
        for phase, data in self.stats["phases"].items():
            md.append(f"### {phase}")
            md.append("```json")
            md.append(json.dumps(data, indent=2))
            md.append("```")
        (self.base / "summary.md").write_text("\n".join(md), encoding="utf-8")

        logger.info(f"Summary written to {self.base}/summary.json and summary.md")

        if self.clean_tmp:
            shutil.rmtree(self.tmp)
            self.tmp.mkdir()
            logger.info("Temporary files cleaned")

    # -------------------------------------------------------------------------
    # Main orchestration
    # -------------------------------------------------------------------------
    def run(self):
        self._show_tools()
        try:
            sub_file = self._enumerate_subdomains()
            resolved_file = self._resolve_subdomains(sub_file)
            self._scan_ports(resolved_file)
            live_urls_file, _ = self._probe_live_hosts(resolved_file)
            all_urls_file = self._collect_urls(live_urls_file)
            self._discover_hidden_params(live_urls_file)
            self._process_js(all_urls_file)
            self._categorize_urls(all_urls_file)
            self._mine_parameters(all_urls_file)
            self._prepare_nuclei(live_urls_file)
            self._screenshots(live_urls_file)
            self._summarize()
        except KeyboardInterrupt:
            logger.error("Interrupted by user, cleaning up...")
            if os.name == "posix":
                os.killpg(0, signal.SIGTERM)
            sys.exit(1)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Enhanced Bug Bounty Recon Orchestrator")
    parser.add_argument("domain", help="Target domain (example.com)")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Parallel threads")
    parser.add_argument("--timeout", type=int, default=600, help="Per-command timeout (seconds)")
    parser.add_argument("--katana-depth", type=int, default=3, help="Katana crawl depth")
    parser.add_argument("--passive-only", action="store_true", help="Skip active scans (naabu, katana, hakrawler)")
    parser.add_argument("--screenshots", action="store_true", help="Enable gowitness screenshots")
    parser.add_argument("--resume", action="store_true", help="Resume from last completed phase")
    parser.add_argument("--clean-tmp", action="store_true", help="Remove temporary files after run")
    parser.add_argument("--run-nuclei", action="store_true", help="Run nuclei after preparing targets")
    parser.add_argument("--skip-port-scan", action="store_true", help="Disable port scanning (naabu) only")
    parser.add_argument("--naabu-rate", type=int, default=1000, help="Naabu scan rate (packets/sec)")
    parser.add_argument("--max-screenshots", type=int, default=500, help="Max URLs to screenshot")
    parser.add_argument("--hakrawler-limit", type=int, default=500, help="Max input URLs for hakrawler")
    parser.add_argument("--nuclei-templates", help="Custom nuclei template directory or file")
    args = parser.parse_args()

    recon = BugBountyRecon(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        katana_depth=args.katana_depth,
        passive_only=args.passive_only,
        enable_screenshots=args.screenshots,
        resume=args.resume,
        clean_tmp=args.clean_tmp,
        run_nuclei=args.run_nuclei,
        skip_port_scan=args.skip_port_scan,
        naabu_rate=args.naabu_rate,
        max_screenshots=args.max_screenshots,
        hakrawler_limit=args.hakrawler_limit,
        nuclei_templates=args.nuclei_templates,
    )
    recon.run()


if __name__ == "__main__":
    main()