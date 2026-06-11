from __future__ import annotations

# ruff: noqa: E501
import json
import re
import uuid
from argparse import ArgumentParser
from dataclasses import dataclass
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, unquote, urlparse

from websec_audit.models import Finding, ScanConfig, ScanReport, Severity
from websec_audit.reporting.html_report import write_html_report, write_pdf_report
from websec_audit.scanner import SecurityAuditor

REPORTS_DIR = Path("reports")
SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


@dataclass(frozen=True)
class WebScanResult:
    scan_id: str
    report: ScanReport
    html_path: Path
    json_path: Path
    pdf_path: Path | None
    active_checks: bool


class AuditWebApp:
    def __init__(self, reports_dir: Path = REPORTS_DIR) -> None:
        self.reports_dir = reports_dir
        self.results: dict[str, WebScanResult] = {}

    def run_scan(self, form: dict[str, list[str]]) -> WebScanResult:
        target = _form_value(form, "target").strip()
        if not _is_http_url(target):
            raise ValueError("Введите абсолютный URL, начинающийся с http:// или https://.")

        scan_id = uuid.uuid4().hex[:10]
        active_checks = _form_value(form, "mode", "passive") == "active"
        config = ScanConfig(
            target_url=target,
            max_depth=_bounded_int(_form_value(form, "max_depth", "2"), 0, 5),
            max_pages=_bounded_int(_form_value(form, "max_pages", "20"), 1, 100),
            timeout=_bounded_float(_form_value(form, "timeout", "10"), 1.0, 60.0),
            user_agent=_form_value(form, "user_agent", "web-security-audit-web/0.1").strip()
            or "web-security-audit-web/0.1",
            include_subdomains="include_subdomains" in form,
            active_checks=active_checks,
            verify_tls="no_verify_tls" not in form,
            crawl_engine=_crawl_engine(_form_value(form, "crawl_engine", "auto")),
        )

        report = SecurityAuditor(config).run()
        scan_dir = self.reports_dir / f"web-{scan_id}"
        html_path = scan_dir / "report.html"
        json_path = scan_dir / "report.json"
        pdf_path = scan_dir / "report.pdf" if "pdf_report" in form else None

        write_html_report(report, html_path)
        scan_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        if pdf_path:
            write_pdf_report(report, pdf_path)

        result = WebScanResult(
            scan_id=scan_id,
            report=report,
            html_path=html_path,
            json_path=json_path,
            pdf_path=pdf_path,
            active_checks=active_checks,
        )
        self.results[scan_id] = result
        return result


class AuditRequestHandler(BaseHTTPRequestHandler):  # pragma: no cover
    app: ClassVar[AuditWebApp]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(render_home())
            return
        if parsed.path.startswith("/reports/"):
            self._send_report_file(parsed.path)
            return
        if parsed.path.startswith("/result/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            result = self.app.results.get(scan_id)
            if result is None:
                self._send_html(render_error("Отчет не найден. Запустите новое сканирование."), HTTPStatus.NOT_FOUND)
                return
            self._send_html(render_result(result))
            return
        self._send_html(render_error("Страница не найдена."), HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/scan":
            self._send_html(render_error("Маршрут не найден."), HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body, keep_blank_values=True)
        try:
            result = self.app.run_scan(form)
        except Exception as exc:  # noqa: BLE001
            self._send_html(render_error(str(exc)), HTTPStatus.BAD_REQUEST)
            return

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/result/{result.scan_id}")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_report_file(self, path: str) -> None:
        relative = Path(unquote(path.removeprefix("/reports/")))
        if relative.is_absolute() or ".." in relative.parts:
            self.send_error(HTTPStatus.FORBIDDEN)
            return

        file_path = (self.app.reports_dir / relative).resolve()
        reports_root = self.app.reports_dir.resolve()
        if not file_path.is_file() or reports_root not in file_path.parents:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_type = {
            ".html": "text/html; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".pdf": "application/pdf",
        }.get(file_path.suffix.lower(), "application/octet-stream")
        payload = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def render_home(error: str | None = None) -> str:
    error_html = f"<div class=\"alert\">{escape(error)}</div>" if error else ""
    return _page(
        f"""
        <section class="hero">
          <div class="hero-copy">
            <p class="eyebrow">Вариант 8 · Web Security Audit</p>
            <h1>Аудит безопасности веб-приложений</h1>
            <p class="lead">Запустите краулинг, анализ форм, проверку XSS, SQLi, CSRF и небезопасных заголовков из аккуратной панели управления.</p>
            <div class="hero-actions">
              <a href="#scan-panel">Настроить аудит</a>
              <span>HTML · JSON · PDF</span>
            </div>
          </div>
          <div class="signal-card" aria-label="Показатели проекта">
            <div><span>checks</span><strong>4</strong><small>XSS, SQLi, CSRF, Headers</small></div>
            <div><span>stack</span><strong>Py</strong><small>requests, BS4, Playwright</small></div>
            <div><span>mode</span><strong>2</strong><small>Passive / Active</small></div>
          </div>
        </section>
        {error_html}
        <main class="layout" id="scan-panel">
          <form class="panel scan-form" method="post" action="/scan" data-scan-form>
            <div class="panel-head">
              <div>
                <p class="eyebrow">Новая проверка</p>
                <h2>Параметры аудита</h2>
              </div>
              <span class="trust-pill">Authorized testing only</span>
            </div>
            <label class="field wide">
              <span>Адрес сайта</span>
              <input name="target" type="url" placeholder="https://example.com" required>
            </label>
            <fieldset>
              <legend>Тип проверки</legend>
              <label class="choice">
                <input type="radio" name="mode" value="passive" checked>
                <span><strong>Пассивная</strong><small>Краулинг, формы, CSRF и заголовки без отправки payload.</small></span>
              </label>
              <label class="choice">
                <input type="radio" name="mode" value="active">
                <span><strong>Активная</strong><small>Дополнительно отправляет XSS/SQLi payload в найденные формы.</small></span>
              </label>
            </fieldset>
            <div class="grid">
              <label class="field"><span>Глубина</span><input name="max_depth" type="number" min="0" max="5" value="2"></label>
              <label class="field"><span>Страницы</span><input name="max_pages" type="number" min="1" max="100" value="20"></label>
              <label class="field"><span>Timeout, сек</span><input name="timeout" type="number" min="1" max="60" step="0.5" value="10"></label>
            </div>
            <label class="field wide">
              <span>Движок краулинга</span>
              <select name="crawl_engine">
                <option value="auto" selected>Auto: requests + Playwright fallback</option>
                <option value="requests">Requests only</option>
                <option value="playwright">Playwright for JavaScript sites</option>
              </select>
            </label>
            <label class="field wide"><span>User-Agent</span><input name="user_agent" value="web-security-audit-web/0.1"></label>
            <div class="toggles">
              <label><input type="checkbox" name="include_subdomains"> Сканировать поддомены</label>
              <label><input type="checkbox" name="no_verify_tls"> Не проверять TLS для лабораторных стендов</label>
              <label><input type="checkbox" name="pdf_report" checked> Создать PDF-отчет</label>
            </div>
            <button type="submit"><span>Запустить аудит</span></button>
          </form>
          <aside class="panel brief">
            <div class="radar">
              <span></span><span></span><span></span>
            </div>
            <h2>Что будет сделано</h2>
            <ul>
              <li>Краулинг сайта в пределах выбранной области</li>
              <li>Извлечение ссылок, заголовков и HTML-форм</li>
              <li>Оценка security headers и CSRF-защиты</li>
              <li>Активные PoC для XSS/SQLi при выбранном режиме</li>
              <li>Генерация HTML, JSON и PDF-отчетов</li>
            </ul>
          </aside>
        </main>
        <div class="loading-overlay" data-loading-overlay aria-live="polite" aria-hidden="true">
          <div class="loading-card">
            <div class="loader-ring"></div>
            <p class="eyebrow">Сканирование запущено</p>
            <h2>Пожалуйста, подождите</h2>
            <p data-loading-estimate>Примерное время: 30-60 секунд.</p>
            <div class="progress-line"><span></span></div>
          </div>
        </div>
        <script>{_scripts()}</script>
        """
    )


def render_result(result: WebScanResult) -> str:
    report = result.report
    summary = report.summary_by_severity
    findings = _render_grouped_findings(report.findings)
    pages = "".join(
        f"<tr><td>{escape(page.url)}</td><td>{page.status_code}</td><td>{escape(page.title or 'Без заголовка')}</td><td>{len(page.forms)}</td></tr>"
        for page in report.pages
    )
    pdf_link = (
        f"<a class=\"secondary\" href=\"/{_report_href(result.pdf_path)}\" target=\"_blank\">PDF</a>"
        if result.pdf_path
        else ""
    )
    return _page(
        f"""
        <section class="result-head" id="top">
          <div>
            <p class="eyebrow">Сканирование завершено</p>
            <h1>{escape(report.target_url)}</h1>
            <p class="lead">Режим: {'активный' if result.active_checks else 'пассивный'} · {len(report.pages)} страниц · {len(report.findings)} находок · {report.duration_seconds} сек.</p>
          </div>
          <nav class="actions">
            <a href="/">Новый аудит</a>
            <a class="secondary" href="/{_report_href(result.html_path)}" target="_blank">HTML</a>
            <a class="secondary" href="/{_report_href(result.json_path)}" target="_blank">JSON</a>
            {pdf_link}
          </nav>
        </section>
        <main class="result-layout">
          <section class="metrics">
            {_metric_link('high', summary['high'])}
            {_metric_link('medium', summary['medium'])}
            {_metric_link('low', summary['low'])}
            {_metric_link('info', summary['info'])}
          </section>
          <section class="panel">
            <div class="panel-head">
              <div>
                <p class="eyebrow">Findings</p>
                <h2>Найденные проблемы</h2>
              </div>
              <span class="trust-pill">Клик по метрике ведет к уровню риска</span>
            </div>
            <div class="findings">{findings or '<p class="empty">Проблемы безопасности не обнаружены.</p>'}</div>
          </section>
          <section class="panel">
            <h2>Просканированные страницы</h2>
            <div class="table-wrap"><table><thead><tr><th>URL</th><th>Статус</th><th>Заголовок</th><th>Формы</th></tr></thead><tbody>{pages}</tbody></table></div>
          </section>
        </main>
        <a class="back-top" href="#top" aria-label="Вернуться наверх">↑</a>
        """
    )


def render_error(message: str) -> str:
    return render_home(message)


def run(  # pragma: no cover
    host: str = "127.0.0.1",
    port: int = 8080,
    reports_dir: Path = REPORTS_DIR,
) -> None:
    AuditRequestHandler.app = AuditWebApp(reports_dir=reports_dir)
    server = ThreadingHTTPServer((host, port), AuditRequestHandler)
    print(f"Web Security Audit UI: http://{host}:{port}")
    server.serve_forever()


def main() -> None:  # pragma: no cover
    parser = ArgumentParser(description="Run the Web Security Audit browser UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on.")
    args = parser.parse_args()
    run(host=args.host, port=args.port)


def _page(content: str) -> str:
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Web Security Audit</title>
  <style>{_styles()}</style>
</head>
<body>
  {content}
</body>
</html>"""


def _metric_link(severity: str, count: int) -> str:
    return f"""
      <a class="metric {severity}" href="#severity-{severity}">
        <span>{severity.title()}</span>
        <strong>{count}</strong>
        <small>Перейти к списку</small>
      </a>
    """


def _render_grouped_findings(findings: list[Finding]) -> str:
    groups: list[str] = []
    for severity in SEVERITY_ORDER:
        severity_findings = [finding for finding in findings if finding.severity == severity]
        label = severity.value.title()
        cards = "".join(_finding_card(finding) for finding in severity_findings)
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
    return "".join(groups)


def _finding_card(finding: Finding) -> str:
    refs = " · ".join(filter(None, [finding.cwe, finding.owasp]))
    refs_html = f"<p class=\"meta\">{escape(refs)}</p>" if refs else ""
    poc_html = f"<pre>{escape(finding.poc)}</pre>" if finding.poc else ""
    severity = escape(finding.severity.value)
    return f"""
      <article class="finding-card">
        <span class="badge {severity}">{severity}</span>
        <h3>{escape(finding.title)}</h3>
        <p>{escape(finding.description)}</p>
        <p class="meta"><strong>URL:</strong> {escape(finding.url)}</p>
        <p class="meta"><strong>Доказательство:</strong> {escape(finding.evidence)}</p>
        <p><strong>Рекомендация:</strong> {escape(finding.recommendation)}</p>
        {refs_html}
        {poc_html}
      </article>
    """


def _styles() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #eef4f8;
  --panel: rgba(255, 255, 255, .88);
  --ink: #101828;
  --muted: #667085;
  --line: rgba(148, 163, 184, .36);
  --accent: #0f766e;
  --accent-strong: #115e59;
  --cyan: #0ea5a4;
  --violet: #6d5dfc;
  --high: #d9480f;
  --medium: #b7791f;
  --low: #2563eb;
  --info: #64748b;
  --shadow: 0 28px 90px rgba(15, 23, 42, .16);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 12% 10%, rgba(14, 165, 164, .18), transparent 32%),
    radial-gradient(circle at 85% 18%, rgba(109, 93, 252, .16), transparent 28%),
    linear-gradient(180deg, #f8fbfd 0%, var(--bg) 46%, #f9fbfd 100%);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
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
.hero, .result-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
  gap: 34px;
  align-items: end;
  max-width: 1220px;
  margin: 0 auto;
  padding: 58px 24px 28px;
  position: relative;
}
.hero-copy { max-width: 800px; }
.eyebrow { color: var(--accent-strong); font-size: 12px; font-weight: 900; letter-spacing: .12em; margin: 0 0 12px; text-transform: uppercase; }
h1 { font-size: clamp(40px, 6vw, 78px); line-height: .94; letter-spacing: 0; margin: 0; }
h2 { font-size: 24px; letter-spacing: 0; margin: 0; }
h3 { letter-spacing: 0; }
.lead { color: #475467; font-size: 19px; line-height: 1.62; margin: 20px 0 0; max-width: 780px; }
.hero-actions { align-items: center; display: flex; flex-wrap: wrap; gap: 14px; margin-top: 28px; }
.hero-actions a, .actions a, button {
  align-items: center;
  background: linear-gradient(135deg, var(--accent), #0e9384);
  border: 0;
  border-radius: 8px;
  box-shadow: 0 14px 30px rgba(15, 118, 110, .26);
  color: white;
  cursor: pointer;
  display: inline-flex;
  font: inherit;
  font-weight: 900;
  justify-content: center;
  min-height: 50px;
  padding: 13px 20px;
  text-decoration: none;
}
.hero-actions span { color: var(--muted); font-weight: 800; }
.signal-card {
  background: linear-gradient(145deg, rgba(255,255,255,.92), rgba(241,245,249,.84));
  border: 1px solid rgba(255,255,255,.72);
  border-radius: 8px;
  box-shadow: var(--shadow);
  display: grid;
  gap: 12px;
  padding: 18px;
}
.signal-card div {
  background: rgba(255,255,255,.72);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 18px;
}
.signal-card span { color: var(--muted); display: block; font-size: 12px; font-weight: 900; text-transform: uppercase; }
.signal-card strong { display: block; font-size: 42px; line-height: 1; margin: 6px 0; }
.signal-card small { color: var(--muted); font-weight: 750; }
.layout, .result-layout { max-width: 1220px; margin: 0 auto; padding: 0 24px 52px; position: relative; }
.layout { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(300px, .8fr); gap: 24px; align-items: start; }
.panel {
  backdrop-filter: blur(18px);
  background: var(--panel);
  border: 1px solid rgba(255, 255, 255, .78);
  border-radius: 8px;
  box-shadow: var(--shadow);
  padding: 26px;
}
.panel-head { align-items: center; display: flex; justify-content: space-between; gap: 18px; margin-bottom: 22px; }
.trust-pill {
  background: #ecfdf3;
  border: 1px solid #abefc6;
  border-radius: 999px;
  color: #067647;
  font-size: 12px;
  font-weight: 900;
  padding: 8px 12px;
  white-space: nowrap;
}
.scan-form { display: grid; gap: 20px; }
.field { display: grid; gap: 8px; }
.field span, legend { color: #344054; font-size: 14px; font-weight: 900; }
input[type="url"], input[type="text"], input[type="number"], input:not([type]) {
  width: 100%;
  background: rgba(255,255,255,.82);
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  color: var(--ink);
  font: inherit;
  min-height: 48px;
  padding: 12px 14px;
}
select {
  width: 100%;
  background: rgba(255,255,255,.82);
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  color: var(--ink);
  font: inherit;
  min-height: 48px;
  padding: 12px 14px;
}
input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 4px rgba(15, 118, 110, .14); outline: 0; }
fieldset { border: 0; display: grid; gap: 12px; margin: 0; padding: 0; }
.choice {
  align-items: flex-start;
  background: rgba(255,255,255,.66);
  border: 1px solid var(--line);
  border-radius: 8px;
  display: flex;
  gap: 12px;
  padding: 15px;
  transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease;
}
.choice:has(input:checked) { border-color: rgba(15,118,110,.62); box-shadow: 0 12px 28px rgba(15,118,110,.12); }
.choice:hover { transform: translateY(-1px); }
.choice small { color: var(--muted); display: block; line-height: 1.45; margin-top: 4px; }
.grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.toggles { display: grid; gap: 11px; color: #344054; }
button { width: 100%; }
button:hover, .actions a:hover, .hero-actions a:hover { filter: brightness(.96); transform: translateY(-1px); }
.brief { overflow: hidden; position: sticky; top: 20px; }
.brief ul { color: #344054; line-height: 1.78; margin: 0; padding-left: 20px; }
.radar {
  aspect-ratio: 1;
  background: conic-gradient(from 180deg, rgba(15,118,110,.08), rgba(14,165,164,.34), rgba(109,93,252,.18), rgba(15,118,110,.08));
  border: 1px solid var(--line);
  border-radius: 8px;
  margin-bottom: 22px;
  position: relative;
}
.radar span { border: 1px solid rgba(15,118,110,.28); border-radius: 50%; inset: 18%; position: absolute; }
.radar span:nth-child(2) { inset: 33%; }
.radar span:nth-child(3) { inset: 48%; background: var(--accent); box-shadow: 0 0 0 12px rgba(15,118,110,.12); }
.alert { max-width: 1220px; margin: 0 auto 18px; padding: 14px 24px; color: #9a3412; font-weight: 900; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }
.actions .secondary { background: rgba(226,232,240,.92); box-shadow: none; color: #1e293b; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 24px; }
.metric {
  background: rgba(255,255,255,.86);
  border: 1px solid rgba(255,255,255,.76);
  border-radius: 8px;
  box-shadow: var(--shadow);
  color: var(--ink);
  padding: 20px;
  text-decoration: none;
  transition: transform .2s ease, box-shadow .2s ease;
}
.metric:hover { box-shadow: 0 34px 90px rgba(15,23,42,.2); transform: translateY(-3px); }
.metric span { color: var(--muted); font-weight: 900; text-transform: uppercase; }
.metric strong { display: block; font-size: 42px; line-height: 1; margin-top: 9px; }
.metric small { color: var(--muted); display: block; font-weight: 800; margin-top: 10px; }
.metric.high { border-top: 5px solid var(--high); }
.metric.medium { border-top: 5px solid var(--medium); }
.metric.low { border-top: 5px solid var(--low); }
.metric.info { border-top: 5px solid var(--info); }
.result-layout { display: grid; gap: 24px; }
.severity-group { scroll-margin-top: 24px; }
.severity-group + .severity-group { border-top: 1px solid var(--line); margin-top: 18px; padding-top: 18px; }
.severity-title { align-items: center; display: flex; gap: 12px; margin-bottom: 10px; }
.severity-title strong { color: var(--muted); }
.finding-card { background: rgba(248,250,252,.78); border: 1px solid var(--line); border-radius: 8px; margin-top: 12px; padding: 18px; }
.badge { border-radius: 999px; color: white; display: inline-block; font-size: 12px; font-weight: 950; padding: 5px 11px; text-transform: uppercase; }
.badge.high { background: var(--high); } .badge.medium { background: var(--medium); } .badge.low { background: var(--low); } .badge.info { background: var(--info); }
.meta { color: var(--muted); overflow-wrap: anywhere; }
pre { background: #0f172a; border-radius: 8px; color: #d7f9f4; overflow-wrap: anywhere; padding: 14px; white-space: pre-wrap; }
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
.loading-overlay {
  align-items: center;
  background: rgba(15,23,42,.58);
  backdrop-filter: blur(12px);
  display: none;
  inset: 0;
  justify-content: center;
  padding: 24px;
  position: fixed;
  z-index: 20;
}
.loading-overlay.active { display: flex; }
.loading-card {
  background: rgba(255,255,255,.96);
  border: 1px solid rgba(255,255,255,.8);
  border-radius: 8px;
  box-shadow: 0 34px 120px rgba(15,23,42,.34);
  max-width: 460px;
  padding: 34px;
  text-align: center;
  width: 100%;
}
.loader-ring {
  animation: spin 1s linear infinite;
  border: 4px solid #ccfbf1;
  border-top-color: var(--accent);
  border-radius: 50%;
  height: 68px;
  margin: 0 auto 22px;
  width: 68px;
}
.progress-line { background: #e2e8f0; border-radius: 999px; height: 8px; margin-top: 22px; overflow: hidden; }
.progress-line span { animation: progress 1.6s ease-in-out infinite; background: linear-gradient(90deg, var(--accent), var(--violet)); border-radius: inherit; display: block; height: 100%; width: 42%; }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes progress { 0% { transform: translateX(-110%); } 100% { transform: translateX(260%); } }
@media (max-width: 900px) {
  .hero, .result-head, .layout { grid-template-columns: 1fr; }
  .brief { position: static; }
  .metrics, .grid { grid-template-columns: 1fr 1fr; }
  .actions { justify-content: flex-start; }
}
@media (max-width: 560px) {
  .hero, .result-head { padding-top: 36px; }
  .signal-card, .metrics, .grid { grid-template-columns: 1fr; }
  .panel-head { align-items: flex-start; flex-direction: column; }
  h1 { font-size: 38px; }
}
"""


def _scripts() -> str:
    return """
const form = document.querySelector('[data-scan-form]');
const overlay = document.querySelector('[data-loading-overlay]');
const estimate = document.querySelector('[data-loading-estimate]');
function estimateSeconds(formData) {
  const pages = Math.max(1, Number(formData.get('max_pages') || 20));
  const depth = Math.max(0, Number(formData.get('max_depth') || 2));
  const timeout = Math.max(1, Number(formData.get('timeout') || 10));
  const active = formData.get('mode') === 'active';
  const pdf = formData.get('pdf_report') !== null;
  const base = 8 + Math.min(90, pages * Math.max(1, depth + 1) * 1.2);
  const activeCost = active ? Math.min(90, pages * timeout * 0.55) : 0;
  const pdfCost = pdf ? 8 : 0;
  return Math.ceil(base + activeCost + pdfCost);
}
if (form && overlay && estimate) {
  form.addEventListener('submit', () => {
    const seconds = estimateSeconds(new FormData(form));
    const min = Math.max(10, Math.round(seconds * 0.75));
    const max = Math.max(min + 10, Math.round(seconds * 1.25));
    estimate.textContent = `Примерное время: ${min}-${max} секунд. Для больших сайтов проверка может идти дольше.`;
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
  });
}
"""


def _report_href(path: Path | None) -> str:
    if path is None:
        return ""
    return "reports/" + path.relative_to(REPORTS_DIR).as_posix()


def _form_value(form: dict[str, list[str]], key: str, default: str = "") -> str:
    values = form.get(key)
    return values[0] if values else default


def _bounded_int(value: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        parsed = minimum
    return min(max(parsed, minimum), maximum)


def _bounded_float(value: str, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except ValueError:
        parsed = minimum
    return min(max(parsed, minimum), maximum)


def _crawl_engine(value: str) -> str:
    return value if value in {"auto", "requests", "playwright"} else "auto"


def _is_http_url(value: str) -> bool:
    return re.match(r"^https?://[^/\s]+", value) is not None


if __name__ == "__main__":
    main()
