from __future__ import annotations

# ruff: noqa: E501
from html import escape
from pathlib import Path

from playwright.sync_api import sync_playwright

from websec_audit.models import Finding, Page, ScanReport, Severity

SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def render_html_report(report: ScanReport) -> str:
    summary = report.summary_by_severity
    findings = _render_grouped_findings(report.findings)
    pages = "\n".join(_render_page(page) for page in report.pages)
    finished_at = report.finished_at.isoformat() if report.finished_at else "running"

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Отчет аудита безопасности веб-приложения</title>
  <style>{_styles()}</style>
</head>
<body>
  <header class="hero" id="top">
    <div>
      <p class="eyebrow">Web Security Audit</p>
      <h1>Отчет аудита безопасности</h1>
      <p class="lead">Цель: <strong>{escape(report.target_url)}</strong></p>
      <p class="meta">Начало: {escape(report.started_at.isoformat())} · Завершение: {escape(finished_at)} · Длительность: {report.duration_seconds}s</p>
    </div>
    <div class="hero-card">
      <span>просканировано</span>
      <strong>{len(report.pages)}</strong>
      <small>страниц</small>
    </div>
  </header>

  <main>
    <section class="summary" aria-label="Сводка по уровню риска">
      {_metric_link("high", summary["high"])}
      {_metric_link("medium", summary["medium"])}
      {_metric_link("low", summary["low"])}
      {_metric_link("info", summary["info"])}
    </section>

    <section class="panel">
      <div class="section-head">
        <div>
          <p class="eyebrow">Findings</p>
          <h2>Найденные проблемы</h2>
        </div>
        <p class="hint">Нажмите на High, Medium, Low или Info в сводке, чтобы перейти к началу соответствующего списка.</p>
      </div>
      {findings or "<p class=\"empty\">Проблемы безопасности не обнаружены.</p>"}
    </section>

    <section class="panel">
      <div class="section-head">
        <div>
          <p class="eyebrow">Crawl map</p>
          <h2>Просканированные страницы</h2>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>URL</th><th>Статус</th><th>Заголовок</th><th>Формы</th><th>Ссылки</th></tr>
          </thead>
          <tbody>{pages}</tbody>
        </table>
      </div>
    </section>
  </main>
  <a class="back-top" href="#top" aria-label="Вернуться наверх">↑</a>
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


def _metric_link(severity: str, count: int) -> str:
    return f"""
      <a class="metric {severity}" href="#severity-{severity}">
        <span>{severity.title()}</span>
        <strong>{count}</strong>
        <small>Перейти к списку</small>
      </a>
    """


def _render_grouped_findings(findings: list[Finding]) -> str:
    no_findings_message = (
        "<p class=\"empty\">Проблемы безопасности не обнаружены.</p>" if not findings else ""
    )
    groups: list[str] = []
    for severity in SEVERITY_ORDER:
        severity_findings = [finding for finding in findings if finding.severity == severity]
        label = severity.value.title()
        cards = "".join(_render_finding(finding) for finding in severity_findings)
        empty = "<p class=\"empty\">Для этого уровня риска находок нет.</p>" if not cards else ""
        groups.append(
            f"""
            <section class="severity-group" id="severity-{severity.value}">
              <div class="severity-title">
                <span class="badge {severity.value}">{label}</span>
                <strong>{len(severity_findings)}</strong>
              </div>
              {cards or empty}
            </section>
            """
        )
    return no_findings_message + "".join(groups)


def _render_finding(finding: Finding) -> str:
    poc = f"<h3>Proof of Concept</h3><pre>{escape(finding.poc)}</pre>" if finding.poc else ""
    refs = " ".join(filter(None, [finding.cwe, finding.owasp]))
    refs_html = f"<p class=\"meta\">Ссылки: {escape(refs)}</p>" if refs else ""
    severity = escape(finding.severity.value)
    return f"""
      <article class="finding">
        <span class="badge {severity}">{severity}</span>
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


def _styles() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #eef4f8;
  --panel: rgba(255, 255, 255, .9);
  --text: #101828;
  --muted: #667085;
  --line: rgba(148, 163, 184, .38);
  --accent: #0f766e;
  --high: #d9480f;
  --medium: #b7791f;
  --low: #2563eb;
  --info: #64748b;
  --shadow: 0 24px 76px rgba(15, 23, 42, .14);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(circle at 12% 10%, rgba(14, 165, 164, .18), transparent 32%),
    radial-gradient(circle at 85% 12%, rgba(109, 93, 252, .14), transparent 28%),
    linear-gradient(180deg, #f8fbfd 0%, var(--bg) 48%, #f9fbfd 100%);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}
body::before {
  background-image: linear-gradient(rgba(15, 23, 42, .045) 1px, transparent 1px), linear-gradient(90deg, rgba(15, 23, 42, .045) 1px, transparent 1px);
  background-size: 34px 34px;
  content: "";
  inset: 0;
  mask-image: linear-gradient(180deg, black, transparent 65%);
  pointer-events: none;
  position: fixed;
}
.hero {
  align-items: end;
  display: grid;
  gap: 28px;
  grid-template-columns: minmax(0, 1fr) 220px;
  margin: 0 auto;
  max-width: 1180px;
  padding: 54px 24px 28px;
  position: relative;
}
.eyebrow { color: #115e59; font-size: 12px; font-weight: 900; letter-spacing: .12em; margin: 0 0 12px; text-transform: uppercase; }
h1 { font-size: clamp(40px, 6vw, 76px); line-height: .94; letter-spacing: 0; margin: 0; }
h2 { font-size: 26px; letter-spacing: 0; margin: 0; }
h3 { letter-spacing: 0; }
.lead { color: #475467; font-size: 19px; line-height: 1.62; margin: 20px 0 0; }
.meta, .evidence { color: var(--muted); overflow-wrap: anywhere; }
.hero-card, .panel, .metric {
  backdrop-filter: blur(18px);
  background: var(--panel);
  border: 1px solid rgba(255,255,255,.78);
  border-radius: 8px;
  box-shadow: var(--shadow);
}
.hero-card { padding: 22px; }
.hero-card span, .hero-card small { color: var(--muted); display: block; font-weight: 850; text-transform: uppercase; }
.hero-card strong { display: block; font-size: 56px; line-height: 1; margin: 8px 0; }
main { max-width: 1180px; margin: 0 auto; padding: 0 24px 56px; position: relative; }
.summary { display: grid; gap: 14px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 24px; }
.metric {
  color: var(--text);
  padding: 20px;
  text-decoration: none;
  transition: transform .2s ease, box-shadow .2s ease;
}
.metric:hover { box-shadow: 0 32px 90px rgba(15,23,42,.2); transform: translateY(-3px); }
.metric span { color: var(--muted); display: block; font-weight: 900; text-transform: uppercase; }
.metric strong { display: block; font-size: 42px; line-height: 1; margin-top: 8px; }
.metric small { color: var(--muted); display: block; font-weight: 800; margin-top: 10px; }
.metric.high { border-top: 5px solid var(--high); }
.metric.medium { border-top: 5px solid var(--medium); }
.metric.low { border-top: 5px solid var(--low); }
.metric.info { border-top: 5px solid var(--info); }
.panel { margin-bottom: 24px; padding: 26px; }
.section-head { align-items: flex-start; display: flex; gap: 18px; justify-content: space-between; margin-bottom: 22px; }
.hint { color: var(--muted); font-weight: 750; margin: 0; max-width: 420px; }
.severity-group { scroll-margin-top: 24px; }
.severity-group + .severity-group { border-top: 1px solid var(--line); margin-top: 18px; padding-top: 18px; }
.severity-title { align-items: center; display: flex; gap: 12px; margin-bottom: 10px; }
.severity-title strong { color: var(--muted); }
.finding {
  background: rgba(248,250,252,.78);
  border: 1px solid var(--line);
  border-radius: 8px;
  margin-top: 12px;
  padding: 18px;
}
.badge { border-radius: 999px; color: white; display: inline-block; font-size: 12px; font-weight: 950; padding: 5px 11px; text-transform: uppercase; }
.high { background: var(--high); }
.medium { background: var(--medium); }
.low { background: var(--low); }
.info { background: var(--info); }
pre {
  background: #0f172a;
  border-radius: 8px;
  color: #d7f9f4;
  font-family: Consolas, Monaco, monospace;
  overflow-wrap: anywhere;
  padding: 14px;
  white-space: pre-wrap;
}
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom: 1px solid var(--line); padding: 13px; text-align: left; vertical-align: top; }
td { color: #344054; overflow-wrap: anywhere; }
.empty { color: var(--muted); }
.back-top {
  align-items: center;
  background: #0f172a;
  border-radius: 8px;
  bottom: 22px;
  box-shadow: 0 16px 40px rgba(15,23,42,.28);
  color: white;
  display: flex;
  font-size: 24px;
  font-weight: 900;
  height: 52px;
  justify-content: center;
  position: fixed;
  right: 22px;
  text-decoration: none;
  width: 52px;
}
@media print {
  .back-top { display: none; }
  body { background: white; }
  .panel, .metric, .hero-card { box-shadow: none; }
}
@media (max-width: 820px) {
  .hero { grid-template-columns: 1fr; }
  .summary { grid-template-columns: 1fr 1fr; }
  .section-head { flex-direction: column; }
}
@media (max-width: 540px) {
  .summary { grid-template-columns: 1fr; }
  h1 { font-size: 38px; }
}
"""
