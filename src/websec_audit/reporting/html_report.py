from __future__ import annotations

from html import escape
from pathlib import Path

from playwright.sync_api import sync_playwright

from websec_audit.models import Finding, Page, ScanReport


def render_html_report(report: ScanReport) -> str:
    summary = report.summary_by_severity
    findings = "\n".join(_render_finding(finding) for finding in report.findings)
    pages = "\n".join(_render_page(page) for page in report.pages)
    finished_at = report.finished_at.isoformat() if report.finished_at else "running"

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Отчет аудита безопасности веб-приложения</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #59636f;
      --border: #d8dee6;
      --high: #b42318;
      --medium: #b54708;
      --low: #175cd3;
      --info: #475467;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.45;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 24px 48px;
    }}
    header, section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 18px;
    }}
    h1, h2, h3 {{
      margin-top: 0;
    }}
    .meta, .evidence {{
      color: var(--muted);
      font-size: 14px;
    }}
    .summary {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }}
    .metric {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }}
    .metric strong {{
      display: block;
      font-size: 28px;
    }}
    .finding {{
      border-top: 1px solid var(--border);
      padding: 18px 0;
    }}
    .finding:first-child {{
      border-top: 0;
      padding-top: 0;
    }}
    .badge {{
      border-radius: 999px;
      color: white;
      display: inline-block;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .04em;
      padding: 4px 10px;
      text-transform: uppercase;
    }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .info {{ background: var(--info); }}
    code, pre {{
      background: #f1f3f5;
      border-radius: 6px;
      font-family: Consolas, Monaco, monospace;
    }}
    pre {{
      overflow-wrap: anywhere;
      padding: 12px;
      white-space: pre-wrap;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
    }}
    th, td {{
      border-bottom: 1px solid var(--border);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Отчет аудита безопасности веб-приложения</h1>
      <p class="meta">Цель: <strong>{escape(report.target_url)}</strong></p>
      <p class="meta">Начало: {escape(report.started_at.isoformat())} |
      Завершение: {escape(finished_at)} | Длительность: {report.duration_seconds}s</p>
    </header>

    <section>
      <h2>Сводка</h2>
      <div class="summary">
        <div class="metric"><span>High</span><strong>{summary["high"]}</strong></div>
        <div class="metric"><span>Medium</span><strong>{summary["medium"]}</strong></div>
        <div class="metric"><span>Low</span><strong>{summary["low"]}</strong></div>
        <div class="metric"><span>Info</span><strong>{summary["info"]}</strong></div>
      </div>
    </section>

    <section>
      <h2>Найденные проблемы</h2>
      {findings or "<p>Проблемы безопасности не обнаружены.</p>"}
    </section>

    <section>
      <h2>Просканированные страницы</h2>
      <table>
        <thead>
          <tr><th>URL</th><th>Статус</th><th>Заголовок</th><th>Формы</th><th>Ссылки</th></tr>
        </thead>
        <tbody>{pages}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def write_html_report(report: ScanReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html_report(report), encoding="utf-8")


def write_pdf_report(report: ScanReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html_report(report)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_content(html, wait_until="networkidle")
        page.pdf(path=str(output_path), format="A4", print_background=True)
        browser.close()


def _render_finding(finding: Finding) -> str:
    poc = (
        f"<h3>Proof of Concept</h3><pre>{escape(finding.poc)}</pre>" if finding.poc else ""
    )
    refs = " ".join(filter(None, [finding.cwe, finding.owasp]))
    refs_html = f"<p class=\"meta\">Ссылки: {escape(refs)}</p>" if refs else ""
    severity = escape(finding.severity.value)
    return f"""
      <article class="finding">
        <p><span class="badge {severity}">{severity}</span></p>
        <h3>{escape(finding.title)}</h3>
        <p>{escape(finding.description)}</p>
        <p class="evidence"><strong>URL:</strong> {escape(finding.url)}</p>
        <p class="evidence"><strong>Доказательство:</strong> {escape(finding.evidence)}</p>
        <p><strong>Рекомендация:</strong> {escape(finding.recommendation)}</p>
        {refs_html}
        {poc}
      </article>
    """


def _render_page(page: Page) -> str:
    return f"""
      <tr>
        <td>{escape(page.url)}</td>
        <td>{page.status_code}</td>
        <td>{escape(page.title)}</td>
        <td>{len(page.forms)}</td>
        <td>{len(page.links)}</td>
      </tr>
    """
