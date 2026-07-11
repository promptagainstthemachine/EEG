"""EEG command-line interface — headless scans, web serve, gateway wrap."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from eeg.rules.catalog_loader import get_scan_ids_for_profile, load_catalog
from eeg.sarif import dumps_sarif, new_fingerprint
from eeg.scans import ScanResult, run_scan

_PROFILE_CHOICES = ("full", "code", "agent", "model", "dependency")
_FORMAT_CHOICES = ("json", "sarif")
_FAIL_ON_CHOICES = ("none", "low", "medium", "high", "critical", "any")
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _merge_findings(scan_results: Dict[str, ScanResult]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    merged: List[Dict[str, Any]] = []
    for result in scan_results.values():
        if result.status == "failed" and not result.findings:
            continue
        for finding in result.findings:
            fp = new_fingerprint(finding)
            if fp in seen:
                continue
            seen.add(fp)
            merged.append(dict(finding))
    return merged


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {k: 0 for k in _SEVERITY_RANK}
    for f in findings:
        sev = str(f.get("severity", "MEDIUM")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _exit_code(findings: List[Dict[str, Any]], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1 if findings else 0
    threshold = _SEVERITY_RANK.get(fail_on.upper(), _SEVERITY_RANK["HIGH"])
    counts = _count_by_severity(findings)
    for sev, rank in _SEVERITY_RANK.items():
        if rank >= threshold and counts.get(sev, 0) > 0:
            if sev == "CRITICAL":
                return 2
            return 1
    return 0


def run_profile_scan(
    target_path: Path,
    *,
    profile: str = "code",
    cloud_env: Optional[str] = None,
    include_model: bool = False,
) -> Dict[str, Any]:
    """Run catalog scan profile against *target_path* and return report dict."""
    scan_ids = get_scan_ids_for_profile(
        profile,
        include_model=include_model,
        cloud_project_type=cloud_env,
    )
    options: Dict[str, Any] = {"cloud_env": cloud_env or "any"}
    scan_results: Dict[str, ScanResult] = {}
    errors: List[str] = []

    for scan_id in scan_ids:
        result = run_scan(scan_id, target_path, options=options)
        scan_results[scan_id] = result
        errors.extend(result.errors)

    findings = _merge_findings(scan_results)
    counts = _count_by_severity(findings)

    return {
        "profile": profile,
        "target": str(target_path.resolve()),
        "scan_ids": scan_ids,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "scans_run": len(scan_ids),
            "scans_failed": sum(1 for r in scan_results.values() if r.status == "failed"),
        },
        "scans": {sid: r.to_dict() for sid, r in scan_results.items()},
        "errors": errors,
    }


def _run_headless_scan(args: argparse.Namespace) -> int:
    target = Path(getattr(args, "target", ".") or ".").expanduser().resolve()
    if not target.is_dir():
        sys.stderr.write(f"error: not a directory: {target}\n")
        return 2

    quiet = not getattr(args, "verbose", False)
    if quiet:
        with contextlib.redirect_stdout(io.StringIO()):
            report = run_profile_scan(
                target,
                profile=args.profile,
                cloud_env=getattr(args, "cloud", None),
                include_model=bool(getattr(args, "include_model", False)),
            )
    else:
        report = run_profile_scan(
            target,
            profile=args.profile,
            cloud_env=getattr(args, "cloud", None),
            include_model=bool(getattr(args, "include_model", False)),
        )
    findings = report["findings"]

    if args.format == "sarif":
        payload = dumps_sarif(findings, target_uri=str(target))
    else:
        payload = json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload if isinstance(payload, str) else payload, encoding="utf-8")
    else:
        print(payload)

    if quiet and args.output:
        summary = report["summary"]
        sys.stderr.write(
            f"EEG: {summary['total_findings']} finding(s) "
            f"(critical={summary['by_severity']['CRITICAL']}, "
            f"high={summary['by_severity']['HIGH']}) → {args.output}\n"
        )

    return _exit_code(findings, args.fail_on)


def _cmd_scan(args: argparse.Namespace) -> int:
    return _run_headless_scan(args)


def _cmd_profiles(_args: argparse.Namespace) -> int:
    catalog = load_catalog()
    profiles = catalog.get("scan_profiles") or {}
    for name, meta in sorted(profiles.items()):
        scans = meta.get("scans") if isinstance(meta, dict) else []
        print(f"{name}: {', '.join(scans) if scans else '(empty)'}")
    return 0


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Repository directory to scan (default: .)",
    )
    parser.add_argument(
        "--profile",
        choices=_PROFILE_CHOICES,
        default="code",
        help="Scan profile from catalog.yaml (default: code)",
    )
    parser.add_argument(
        "--format",
        choices=_FORMAT_CHOICES,
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write results to FILE instead of stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="high",
        help="Exit non-zero when findings meet severity (default: high)",
    )
    parser.add_argument(
        "--cloud",
        metavar="ENV",
        choices=("aws", "azure", "gcp", "any"),
        help="Cloud project type (enables cloud_static_rules on full profile)",
    )
    parser.add_argument(
        "--include-model",
        action="store_true",
        help="Include model_artifact scan in the profile",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show scanner progress messages",
    )


def _build_headless_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eeg --headless",
        description="EEG headless — catalog static scans for CI and local use.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )
    _add_scan_options(parser)
    return parser


def _build_serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eeg --serve",
        description="EEG serve — run the full OSS web application.",
    )
    parser.add_argument("--serve", action="store_true", default=True, help=argparse.SUPPRESS)
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    return parser


def _build_gateway_wrap_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eeg --gateway-wrap",
        description="EEG gateway-wrap — put EEG runtime in front of an AI app URL.",
    )
    parser.add_argument(
        "--gateway-wrap",
        metavar="URL",
        required=True,
        help="Upstream AI app / OpenAI-compatible endpoint to wrap",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Bind port (default: 8787)")
    parser.add_argument(
        "--no-private-upstream",
        action="store_true",
        help="Reject private/loopback wrap targets",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Legacy + unified help parser (subcommands: scan, profiles)."""
    parser = argparse.ArgumentParser(
        prog="eeg",
        description=(
            "EEG — AI/agent security.\n\n"
            "Modes:\n"
            "  eeg --headless [PATH]     Static catalog scans (CI / local)\n"
            "  eeg --serve               Full EEG web application\n"
            "  eeg --gateway-wrap URL    Local gateway in front of an AI app\n\n"
            "Legacy subcommands: scan, profiles"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  eeg --headless .\n"
            "  eeg --headless ./app --profile full --format sarif -o out.sarif\n"
            "  eeg --serve --host 0.0.0.0 --port 8000\n"
            "  eeg --gateway-wrap https://myaiapp.com --port 8787\n"
            "  eeg scan . --profile code\n"
            "  eeg profiles\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a catalog scan profile (alias of --headless)")
    _add_scan_options(scan)
    scan.set_defaults(func=_cmd_scan)

    profiles = sub.add_parser("profiles", help="List scan profiles from catalog.yaml")
    profiles.set_defaults(func=_cmd_profiles)

    return parser


def _strip_flag(argv: List[str], flag: str) -> List[str]:
    """Remove a boolean flag (and optional =value form) from argv copy."""
    out: List[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == flag or arg.startswith(flag + "="):
            i += 1
            continue
        out.append(arg)
        i += 1
    return out


def _extract_gateway_wrap_url(argv: List[str]) -> tuple[Optional[str], List[str]]:
    """Return (url, remaining_argv) for --gateway-wrap URL | --gateway-wrap=URL."""
    out: List[str] = []
    url: Optional[str] = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--gateway-wrap":
            if i + 1 >= len(argv):
                raise SystemExit("eeg: error: --gateway-wrap requires a URL\n")
            url = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--gateway-wrap="):
            url = arg.split("=", 1)[1]
            i += 1
            continue
        out.append(arg)
        i += 1
    return url, out


def main(argv: Optional[List[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    if not raw or raw[0] in ("-h", "--help"):
        build_parser().print_help()
        sys.stderr.write(
            "\nAlso: eeg --headless --help | eeg --serve --help | eeg --gateway-wrap --help\n"
        )
        return 0

    # Top-level modes (preferred)
    if "--serve" in raw:
        args = _build_serve_parser().parse_args(_strip_flag(raw, "--serve"))
        from eeg.cli_serve import run_web_serve

        return run_web_serve(host=args.host, port=args.port)

    if "--gateway-wrap" in raw or any(a.startswith("--gateway-wrap=") for a in raw):
        url, rest = _extract_gateway_wrap_url(raw)
        wrap_argv = ["--gateway-wrap", url or "", *rest]
        args = _build_gateway_wrap_parser().parse_args(wrap_argv)
        from eeg.cli_serve import run_gateway_wrap

        return run_gateway_wrap(
            args.gateway_wrap,
            host=args.host,
            port=args.port,
            allow_private=not args.no_private_upstream,
        )

    if "--headless" in raw:
        args = _build_headless_parser().parse_args(_strip_flag(raw, "--headless"))
        return _run_headless_scan(args)

    # Legacy subcommands: scan / profiles
    parser = build_parser()
    args = parser.parse_args(raw)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
