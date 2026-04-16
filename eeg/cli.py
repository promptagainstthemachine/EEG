#!/usr/bin/env python3
"""
EEG - Extensive Exposure Guard
Multi-Cloud AI Security & Vulnerability Management Framework

Usage:
  python eeg.py --env aws --path /path/to/repo --report json
  python eeg.py --env azure --auth true --path ./my-app --avoid iac,network --report html
  python eeg.py --env gcp --vm false --thread max --report json
"""

import argparse
import sys
import os
import time
import datetime

from eeg.collector import Collector, Severity
from eeg.utils.repocrawler import RepoCrawler
from eeg.utils.threadpoolexecutor import ThreadManager
from eeg.utils.htmlreport import HTMLReportGenerator
from eeg.utils.jsonreport import JSONReportGenerator
from eeg.utils.auth import CloudAuthenticator
from eeg.detectors import load_detectors
from eeg.auth_scanner import get_auth_scanner
from eeg.vuln_manager.cve_fetcher import CVEFetcher
from eeg.vuln_manager.dependency_parser import DependencyParser


BANNER = """
    ___________  ________
   / ____/ ____/ / ____/
  / __/ / __/ / / / __
 / /___/ /___/ / /_/ /
/_____/_____/_/\\____/
Extensive Exposure Guard
Multi-Cloud AI Security Scanner
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EEG - Multi-Cloud AI Security & Vulnerability Management Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --env aws --path ./my-bedrock-app --report json
  %(prog)s --env azure --auth true --path ./foundry-app --report html
  %(prog)s --env gcp --path ./vertex-app --avoid iac,network --vm false
  %(prog)s --env aws --path ./app --thread max --report html
        """,
    )

    parser.add_argument(
        "--env",
        required=True,
        choices=["aws", "azure", "gcp"],
        help="Target cloud environment (aws, azure, gcp)",
    )
    parser.add_argument(
        "--auth",
        default="false",
        choices=["true", "false"],
        help="Enable authenticated testing (reads cloud credentials). Default: false",
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to the repository or project directory to scan",
    )
    parser.add_argument(
        "--avoid",
        default="",
        help="Comma-separated categories to skip: network,iac,iam,policy,guardrail,model,storage,prompt,secrets",
    )
    parser.add_argument(
        "--vm",
        default="true",
        choices=["true", "false"],
        help="Enable vulnerability management (NVD CVE fetching). Default: true",
    )
    parser.add_argument(
        "--thread",
        default=None,
        choices=["med", "max"],
        help="Enable parallel scanning: med(4 threads), max(8 threads). Without this flag, runs sequentially.",
    )
    parser.add_argument(
        "--report",
        default="json",
        choices=["json", "html"],
        help="Report output format. Default: json",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Save report to file (default: stdout for json, eeg_report.html for html)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    repo_path = os.path.abspath(args.path)
    if not os.path.isdir(repo_path):
        print(f"[ERROR] Path does not exist or is not a directory: {repo_path}")
        sys.exit(3)

    cloud_env = args.env
    auth_enabled = args.auth == "true"
    vm_enabled = args.vm == "true"
    avoid_categories = set(c.strip().lower() for c in args.avoid.split(",") if c.strip())
    thread_level = args.thread or "min"
    report_format = args.report

    collector = Collector()
    collector.set_metadata(
        target_path=repo_path,
        cloud_env=cloud_env,
        auth_enabled=auth_enabled,
        vm_enabled=vm_enabled,
        avoided_categories=list(avoid_categories),
        thread_level=thread_level,
    )

    # --- Phase 1: Authenticate (if --auth true) ---
    auth_context = None
    if auth_enabled:
        print(f"\n[AUTH] Attempting {cloud_env.upper()} credential discovery...")
        authenticator = CloudAuthenticator(cloud_env)
        auth_context = authenticator.authenticate()
        if auth_context:
            print(f"[AUTH] ✓ Authenticated as: {auth_context.get('identity', 'unknown')}")
        else:
            print("[AUTH] ✗ No credentials found. Proceeding with static analysis only.")

    # --- Phase 2: Crawl Repository ---
    print(f"\n[SCAN] Crawling repository: {repo_path}")
    crawler = RepoCrawler(repo_path)
    files = crawler.crawl()
    collector.set_metadata(files_scanned=len(files))
    print(f"[SCAN] Found {len(files)} scannable files")

    # --- Phase 3: Run Detectors (static analysis) ---
    print(f"\n[DETECT] Loading {cloud_env.upper()} detection rules...")
    detectors = load_detectors(cloud_env, avoid_categories)
    print(f"[DETECT] Loaded {len(detectors)} detector(s), skipping: {avoid_categories or 'none'}")

    thread_manager = ThreadManager(thread_level)
    print(f"[DETECT] Scanning with {thread_manager.pool_size} threads...\n")

    def run_detector(detector):
        return detector.scan(files, collector)

    start = time.time()
    thread_manager.execute(run_detector, detectors)
    elapsed_detect = time.time() - start
    print(f"\n[DETECT] ✓ Detection complete in {elapsed_detect:.1f}s")

    # --- Phase 3b: Authenticated Live Scan (if --auth true) ---
    if auth_enabled and auth_context:
        print(f"\n[LIVE] Running authenticated {cloud_env.upper()} resource audit...")
        auth_scanner = get_auth_scanner(cloud_env, auth_context)
        if auth_scanner:
            try:
                auth_scanner.scan(collector)
                print("[LIVE] ✓ Authenticated scan complete")
            except Exception as e:
                print(f"[LIVE] ✗ Authenticated scan error: {e}")
        else:
            print(f"[LIVE] No authenticated scanner available for {cloud_env}")

    # --- Phase 4: Vulnerability Management (CVE Fetch) ---
    if vm_enabled:
        print("\n[CVE] Parsing dependencies for AI frameworks...")
        dep_parser = DependencyParser(repo_path)
        ai_deps = dep_parser.parse()

        if ai_deps:
            print(f"[CVE] Found {len(ai_deps)} AI-related dependencies: {', '.join(ai_deps.keys())}")
            fetcher = CVEFetcher()
            cve_findings = fetcher.fetch_all(ai_deps, cloud_env)
            collector.add_findings(cve_findings)
            print(f"[CVE] ✓ Fetched {len(cve_findings)} CVE(s)")
        else:
            print("[CVE] No AI-specific dependencies detected")
    else:
        print("\n[CVE] Vulnerability management disabled (--vm false)")

    # --- Phase 5: Generate Report ---
    summary = collector.get_summary()
    print("\n" + "=" * 60)
    print("  EEG SCAN SUMMARY")
    print("=" * 60)
    print(f"  Cloud:    {cloud_env.upper()}")
    print(f"  Files:    {summary['files_scanned']}")
    print(f"  Findings: {summary['total_findings']}")
    print(f"  CRITICAL: {summary['by_severity']['CRITICAL']}")
    print(f"  HIGH:     {summary['by_severity']['HIGH']}")
    print(f"  MEDIUM:   {summary['by_severity']['MEDIUM']}")
    print(f"  LOW:      {summary['by_severity']['LOW']}")
    print(f"  Duration: {summary['scan_duration_seconds']}s")
    print("=" * 60)

    if report_format == "json":
        generator = JSONReportGenerator(collector)
    else:
        generator = HTMLReportGenerator(collector)

    report_content = generator.generate()

    output_file = args.output_file
    if output_file is None:
        app_name = os.path.basename(repo_path)
        ts = datetime.datetime.utcnow().strftime("%H-%M-%S-%d%m%Y")
        ext = "html" if report_format == "html" else "json"
        output_file = f"eeg-report-{cloud_env}-{app_name}-{ts}.{ext}"

    if output_file:
        with open(output_file, "w") as f:
            f.write(report_content)
        print(f"\n[REPORT] Saved to: {output_file}")
    else:
        print("\n" + report_content)

    exit_code = collector.exit_code
    if exit_code == 2:
        print("\n[EXIT] CRITICAL findings detected — exit code 2")
    elif exit_code == 1:
        print("\n[EXIT] HIGH findings detected — exit code 1")
    else:
        print("\n[EXIT] No critical/high findings — exit code 0")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
