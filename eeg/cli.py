#!/usr/bin/env python3
"""
EEG - Extensive Exposure Guard
Multi-Cloud AI Security & Vulnerability Management Framework

Supports:
  - Local authenticated console (az login, aws configure, gcloud auth)
  - Cloud console bash (Azure Cloud Shell, AWS CloudShell, GCP Cloud Shell)
  - Static code analysis
  - Live resource auditing

Usage:
  python eeg.py --env aws --path /path/to/repo --report json
  python eeg.py --env azure --auth true --path ./my-app --avoid iac,network --report html
  python eeg.py --env gcp --vm false --thread max --report csv
  python eeg.py --env azure --console-mode auto --path . --report html
  python eeg.py --env aws --path ./app --report csv,html,json  # Multiple formats
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
from eeg.utils.csvreport import CSVReportGenerator
from eeg.utils.auth import CloudAuthenticator
from eeg.utils.cloud_console import CloudConsoleDetector, LocalConsoleAuthenticator
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
  %(prog)s --env aws --path ./app --thread max --report csv
  %(prog)s --env azure --console-mode auto --path . --report html
  %(prog)s --env aws --path ./app --report csv,html,json
  %(prog)s --env azure --path ./app --report html,json --output-file my-report
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
        help="Enable live cloud resource audit (requires CLI login). Static code scanning works without this. Default: false",
    )
    parser.add_argument(
        "--console-mode",
        default="auto",
        choices=["auto", "local", "cloud"],
        help="Console mode: auto (detect), local (use local CLI), cloud (use cloud shell). Default: auto",
    )
    parser.add_argument(
        "--path",
        default=None,
        help="Path to repository to scan. Optional if --auth true (live-only scan)",
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
        help="Report output format(s). Comma-separated: json,html,csv. Examples: --report html or --report csv,html,json. Default: json",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Base filename for report(s). Extension will be added automatically. Default: auto-generated",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    cloud_env = args.env
    auth_enabled = args.auth == "true"
    vm_enabled = args.vm == "true"
    avoid_categories = set(c.strip().lower() for c in args.avoid.split(",") if c.strip())
    thread_level = args.thread or "min"
    console_mode = args.console_mode
    
    # Parse report formats (comma-separated)
    valid_formats = {"json", "html", "csv"}
    report_formats = [fmt.strip().lower() for fmt in args.report.split(",") if fmt.strip()]
    invalid_formats = [fmt for fmt in report_formats if fmt not in valid_formats]
    if invalid_formats:
        print(f"[ERROR] Invalid report format(s): {', '.join(invalid_formats)}. Valid options: json, html, csv")
        sys.exit(3)
    if not report_formats:
        report_formats = ["json"]  # Default
    # Remove duplicates while preserving order
    report_formats = list(dict.fromkeys(report_formats))
    print(f"[CONFIG] Report format(s): {', '.join(report_formats)}")

    # Determine if we need a path (static scanning) or can run live-only
    repo_path = None
    static_scan_enabled = False
    
    if args.path:
        repo_path = os.path.abspath(args.path)
        if not os.path.isdir(repo_path):
            print(f"[ERROR] Path does not exist or is not a directory: {repo_path}")
            sys.exit(3)
        static_scan_enabled = True
    elif not auth_enabled:
        print("[ERROR] --path is required for static analysis. Use --auth true for live-only scanning.")
        sys.exit(3)
    else:
        print("[INFO] No --path provided. Running live resource audit only (no static analysis).")
        repo_path = os.getcwd()  # Use current dir for report naming

    collector = Collector()
    collector.set_metadata(
        target_path=repo_path,
        cloud_env=cloud_env,
        auth_enabled=auth_enabled,
        vm_enabled=vm_enabled,
        avoided_categories=list(avoid_categories),
        thread_level=thread_level,
    )

    # --- Phase 0: Console Mode Detection ---
    auth_context = None
    console_detector = CloudConsoleDetector()
    is_cloud_console, detected_console, cloud_shell_context = console_detector.detect()

    if console_mode == "auto":
        if is_cloud_console:
            print(f"\n[CONSOLE] ✓ Cloud Shell detected: {detected_console.upper()}")
            auth_context = cloud_shell_context
            auth_enabled = True
            collector.set_metadata(console_mode="cloud_shell", console_type=detected_console)
        else:
            print("\n[CONSOLE] Local console mode (not in cloud shell)")
            collector.set_metadata(console_mode="local")
    elif console_mode == "cloud":
        if is_cloud_console:
            print(f"\n[CONSOLE] ✓ Cloud Shell mode: {detected_console.upper()}")
            auth_context = cloud_shell_context
            auth_enabled = True
            collector.set_metadata(console_mode="cloud_shell", console_type=detected_console)
        else:
            print("[CONSOLE] ✗ Cloud shell requested but not detected")
            collector.set_metadata(console_mode="local")
    else:  # local
        print("\n[CONSOLE] Local console mode (forced)")
        collector.set_metadata(console_mode="local")

    # --- Phase 1: Authenticate (if --auth true or cloud shell detected) ---
    if auth_enabled and not auth_context:
        # Try local CLI authentication first
        local_auth = LocalConsoleAuthenticator(cloud_env)
        is_authenticated, cli_context = local_auth.check_cli_auth()
        
        if is_authenticated:
            print(f"\n[AUTH] ✓ CLI authenticated as: {cli_context.get('identity', 'unknown')}")
            auth_context = cli_context
        else:
            # Fall back to credential file discovery
            print(f"\n[AUTH] Attempting {cloud_env.upper()} credential discovery...")
            authenticator = CloudAuthenticator(cloud_env)
            auth_context = authenticator.authenticate()
            if auth_context:
                print(f"[AUTH] ✓ Authenticated as: {auth_context.get('identity', 'unknown')}")
            else:
                print("[AUTH] ✗ No credentials found. Proceeding with static analysis only.")
    elif auth_context:
        print(f"[AUTH] ✓ Using cloud shell credentials: {auth_context.get('identity', 'unknown')}")
    else:
        print("\n[AUTH] Static analysis mode (no authentication required)")

    # --- Phase 2: Crawl Repository (skip if live-only) ---
    files = []
    if static_scan_enabled:
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
    else:
        collector.set_metadata(files_scanned=0)
        print("\n[SCAN] Skipping static analysis (live-only mode)")

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
    if vm_enabled and static_scan_enabled:
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
    elif vm_enabled and not static_scan_enabled:
        print("\n[CVE] Skipping CVE fetching (no repo path for dependency parsing)")
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
    
    # Show permission tracking if there were issues
    completed = summary.get("completed_checks", 0)
    skipped = summary.get("skipped_checks", 0)
    perm_issues = summary.get("permission_issues", 0)
    
    if completed > 0 or skipped > 0:
        print("-" * 60)
        print(f"  Checks:   {completed} completed, {skipped} skipped")
    if perm_issues > 0:
        print(f"  ⚠ {perm_issues} permission issue(s) encountered")
        print("    (Some checks skipped due to limited permissions)")
    print("=" * 60)

    # Generate reports for each requested format
    app_name = os.path.basename(repo_path)
    ts = datetime.datetime.utcnow().strftime("%H-%M-%S-%d%m%Y")
    base_output = args.output_file
    
    generated_reports = []
    for report_format in report_formats:
        if report_format == "json":
            generator = JSONReportGenerator(collector)
        elif report_format == "csv":
            generator = CSVReportGenerator(collector)
        else:
            generator = HTMLReportGenerator(collector)

        report_content = generator.generate()

        # Determine output filename
        if base_output:
            # User provided base name - add extension
            if base_output.endswith(f".{report_format}"):
                output_file = base_output
            else:
                # Strip any existing extension and add correct one
                base_name = base_output.rsplit(".", 1)[0] if "." in base_output else base_output
                output_file = f"{base_name}.{report_format}"
        else:
            output_file = f"eeg-report-{cloud_env}-{app_name}-{ts}.{report_format}"

        with open(output_file, "w") as f:
            f.write(report_content)
        generated_reports.append(output_file)
    
    print(f"\n[REPORT] Generated {len(generated_reports)} report(s):")
    for report_file in generated_reports:
        print(f"         - {report_file}")

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
