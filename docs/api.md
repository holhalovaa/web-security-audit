# API и CLI

Проект предоставляет два способа использования: командную строку и Python API.
CLI предназначен для обычного запуска сканирования, Python API — для тестов,
автоматизации и возможной интеграции с другими инструментами.

## CLI

```bash
websec-audit TARGET [options]
```

Обязательный аргумент:

| Аргумент | Описание |
| --- | --- |
| `TARGET` | Абсолютный URL с протоколом `http` или `https` |

Параметры:

| Параметр | Описание | Значение по умолчанию |
| --- | --- | --- |
| `--max-depth` | Максимальная глубина обхода | `2` |
| `--max-pages` | Максимальное количество страниц | `50` |
| `--timeout` | Таймаут HTTP-запроса в секундах | `10.0` |
| `--user-agent` | User-Agent для запросов | `web-security-audit/0.1` |
| `--include-subdomains` | Разрешить обход поддоменов | выключено |
| `--no-active-checks` | Отключить активные XSS и SQLi проверки | выключено |
| `--no-verify-tls` | Отключить проверку TLS-сертификата | выключено |
| `--crawl-engine` | Движок обхода: `auto`, `requests` или `playwright` | `auto` |
| `--html-output` | Путь к HTML-отчету | `reports/report.html` |
| `--pdf-output` | Путь к PDF-отчету | не задан |
| `--json-output` | Путь к JSON-отчету | не задан |

## Примеры CLI

Пассивный запуск:

```bash
websec-audit https://example.com --no-active-checks --html-output reports/report.html
```

Полный запуск с PDF и JSON:

```bash
websec-audit https://example.com \
  --max-depth 2 \
  --max-pages 30 \
  --crawl-engine auto \
  --html-output reports/report.html \
  --pdf-output reports/report.pdf \
  --json-output reports/report.json
```

Для SPA и сайтов, где DOM собирается JavaScript-кодом, используйте:

```bash
websec-audit https://example.com --crawl-engine playwright --no-active-checks
```

Запуск для локального стенда:

```bash
websec-audit http://localhost:8000 --max-depth 1 --max-pages 10
```

## Python API

```python
from websec_audit.models import ScanConfig
from websec_audit.scanner import SecurityAuditor

config = ScanConfig(
    target_url="https://example.com",
    max_depth=2,
    max_pages=30,
    active_checks=False,
)

report = SecurityAuditor(config).run()
print(report.summary_by_severity)
```

## Веб-интерфейс

Для демонстрации проекта и ручного запуска аудита доступен браузерный интерфейс:

```bash
websec-audit-web
```

По умолчанию интерфейс открывается на `http://127.0.0.1:8080`. В форме можно указать
целевой сайт, выбрать пассивный или активный режим, глубину краулинга, лимит страниц,
таймаут, движок обхода, проверку поддоменов, TLS-режим и создание PDF-отчета.

Для запуска в контейнере сервис `web` из Docker Compose публикует порт `8080`:

```bash
docker compose up --build web
```

Веб-интерфейс использует те же доменные модели и `SecurityAuditor`, что и CLI. После
сканирования он сохраняет HTML, JSON и опционально PDF в каталог `reports/`.
Перед отправкой формы показывается экран ожидания с примерной длительностью аудита.
В HTML-отчете сводка по `High`, `Medium`, `Low` и `Info` работает как навигация к
соответствующим группам находок, а кнопка `↑` возвращает к началу страницы.

## Основные модели

| Модель | Назначение |
| --- | --- |
| `ScanConfig` | Цель сканирования, лимиты, таймауты, режим активных проверок |
| `ScanReport` | Итоговый отчет: страницы, findings, длительность, сводка |
| `Page` | URL, статус, заголовки, title, ссылки и формы страницы |
| `Form` | URL страницы, action, method и поля формы |
| `Finding` | Найденная проблема: severity, evidence, recommendation, PoC |

## Пример JSON-отчета

```json
{
  "target_url": "https://example.com",
  "duration_seconds": 1.234,
  "summary_by_severity": {
    "info": 0,
    "low": 2,
    "medium": 1,
    "high": 1
  },
  "findings": [
    {
      "check_id": "headers.content-security-policy",
      "title": "Missing Content Security Policy",
      "severity": "high",
      "url": "https://example.com/",
      "evidence": "Observed headers: server",
      "recommendation": "Configure a strict Content-Security-Policy header."
    }
  ]
}
```

## Код завершения

CLI возвращает `0`, если сканирование завершилось корректно. Наличие findings не
считается ошибкой процесса: это результат аудита. Некорректный URL или неверные
аргументы обрабатываются через `argparse` и приводят к ненулевому коду выхода.
