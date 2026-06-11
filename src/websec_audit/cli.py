from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from websec_audit.models import DEFAULT_USER_AGENT, ScanConfig
from websec_audit.reporting.html_report import write_html_report, write_pdf_report
from websec_audit.scanner import SecurityAuditor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-audit",
        description="Authorized web application security audit scanner.",
    )
    parser.add_argument("target", help="Target base URL, for example https://example.com")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth.")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum number of pages to crawl.",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent.")
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Allow crawling subdomains of the target host.",
    )
    parser.add_argument(
        "--no-active-checks",
        action="store_true",
        help="Disable XSS and SQLi form submissions.",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS certificate verification for lab targets.",
    )
    parser.add_argument(
        "--crawl-engine",
        choices=("auto", "requests", "playwright"),
        default="auto",
        help="Crawler engine: requests, Playwright, or automatic SPA fallback.",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        default=Path("reports/report.html"),
        help="Path to the HTML report.",
    )
    parser.add_argument("--pdf-output", type=Path, help="Optional path to the PDF report.")
    parser.add_argument("--json-output", type=Path, help="Optional path to the JSON report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_target(args.target, parser)

    config = ScanConfig(
        target_url=args.target,
        max_depth=max(args.max_depth, 0),
        max_pages=max(args.max_pages, 1),
        timeout=args.timeout,
        user_agent=args.user_agent,
        include_subdomains=args.include_subdomains,
        active_checks=not args.no_active_checks,
        verify_tls=not args.no_verify_tls,
        crawl_engine=args.crawl_engine,
    )

    report = SecurityAuditor(config).run()
    write_html_report(report, args.html_output)

    if args.pdf_output:
        write_pdf_report(report, args.pdf_output)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    summary = report.summary_by_severity
    print(
        "Scan completed: "
        f"{len(report.pages)} pages, {len(report.findings)} findings "
        f"(high={summary['high']}, medium={summary['medium']}, "
        f"low={summary['low']}, info={summary['info']}). "
        f"HTML report: {args.html_output}"
    )
    return 0


def _validate_target(target: str, parser: argparse.ArgumentParser) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        parser.error("target must be an absolute http(s) URL")


if __name__ == "__main__":
    raise SystemExit(main())
