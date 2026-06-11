# Web Security Audit

**Название курсового проекта:** программа для аудита безопасности веб-приложений  
**Вариант:** 8  
**Предметная область:** тестирование на проникновение  
**Студентка:** Холхалова Алина  
**Группа:** 220032-11

`Web Security Audit` — учебный production-grade инструмент для автоматического
аудита безопасности веб-приложений. Программа обходит сайт, извлекает страницы и
HTML-формы, проверяет типовые уязвимости, формирует Proof-of-Concept и сохраняет
отчет в HTML, PDF и JSON.

Инструмент реализован на Python с использованием `requests`, `BeautifulSoup` и
`Playwright`. Playwright применяется не только для PDF, но и для рендеринга
JavaScript/SPA-страниц во время краулинга. Архитектура разделена на независимые
компоненты: CLI, HTTP-клиент, краулер, парсер, проверки безопасности и генератор отчетов.

## Оглавление

- [Основные возможности](#основные-возможности)
- [Соответствие варианту](#соответствие-варианту)
- [Соответствие обязательным требованиям](#соответствие-обязательным-требованиям)
- [Стек технологий](#стек-технологий)
- [Структура проекта](#структура-проекта)
- [Сборка](#сборка)
- [Запуск](#запуск)
- [Примеры использования](#примеры-использования)
- [Проверка качества](#проверка-качества)
- [Документация](#документация)
- [Безопасное использование](#безопасное-использование)

## Основные возможности

- Краулинг сайта с ограничением по домену, глубине и количеству страниц.
- Обход JavaScript/SPA-сайтов через Playwright с автоматическим fallback-режимом.
- Извлечение ссылок, заголовков страниц и HTML-форм.
- Анализ форм и определение потенциально изменяющих состояние запросов.
- Проверка отсутствующих и небезопасно настроенных security headers.
- Проверка CSRF-защиты для `POST`, `PUT`, `PATCH` и `DELETE` форм.
- Активная проверка reflected XSS через отправку контролируемого payload.
- Активная error-based проверка SQL injection по характерным ошибкам СУБД.
- Генерация Proof-of-Concept в виде воспроизводимой `curl`-команды.
- Формирование HTML, PDF и JSON отчетов.
- Автоматические тесты с покрытием выше 90%.
- CI-пайплайн с линтингом, тестами, SAST и аудитом зависимостей.
- Docker и Docker Compose для воспроизводимого запуска.

## Соответствие варианту

| Требование варианта 8 | Реализация в проекте |
| --- | --- |
| Python | Основной язык проекта, пакет `websec_audit` |
| requests | HTTP-клиент в `src/websec_audit/http_client.py` |
| BeautifulSoup | Парсинг HTML в `src/websec_audit/parser.py` |
| Playwright | JS-краулинг в `src/websec_audit/crawler.py` и PDF-отчет в `src/websec_audit/reporting/html_report.py` |
| Сканирование XSS | `src/websec_audit/checks/xss.py` |
| Сканирование SQLi | `src/websec_audit/checks/sqli.py` |
| Проверка CSRF | `src/websec_audit/checks/csrf.py` |
| Небезопасные заголовки | `src/websec_audit/checks/headers.py` |
| Краулинг сайта | `src/websec_audit/crawler.py` |
| Анализ форм | `src/websec_audit/parser.py` и security checks |
| Proof-of-Concept | `src/websec_audit/checks/payloads.py` |
| HTML/PDF отчет | `src/websec_audit/reporting/html_report.py` |

## Соответствие обязательным требованиям

| Компонент | Статус | Где находится |
| --- | --- | --- |
| Git и семантические коммиты | Выполнено | История коммитов содержит `feat:`, `fix:`, `test:`, `docs:` |
| Git Flow | Выполнено | Используются ветки `main` и `develop`; для новых задач подходит схема `feature/* -> develop -> main` |
| Модульное тестирование | Выполнено | `tests/`, запуск через `pytest` |
| Контейнеризация | Выполнено | `Dockerfile`, `docker-compose.yml` |
| README | Выполнено | Текущий файл |
| API-документация | Выполнено | [docs/api.md](docs/api.md) |
| Диаграммы | Выполнено | Mermaid-диаграммы в README и [docs/architecture.md](docs/architecture.md) |
| SAST-анализ | Выполнено | `bandit`, CI workflow |
| Проверка зависимостей | Выполнено | `pip-audit`, CI workflow |
| Интеграция ИИ-инструментов | Выполнено | [docs/ai_usage.md](docs/ai_usage.md) |

## Стек технологий

| Технология | Назначение |
| --- | --- |
| Python 3.12 | Основная реализация CLI-инструмента |
| requests | HTTP-запросы и отправка форм |
| BeautifulSoup4 | Извлечение ссылок, заголовков и форм из HTML |
| Playwright | Рендеринг SPA-страниц при краулинге и HTML-отчета в PDF |
| pytest, pytest-cov | Модульные тесты и покрытие |
| Ruff | Линтинг и контроль стиля |
| Bandit | SAST-анализ Python-кода |
| pip-audit | Проверка зависимостей на известные уязвимости |
| Docker, Docker Compose | Контейнеризация и воспроизводимый запуск |
| GitHub Actions | CI-пайплайн качества |

## Структура проекта

```text
.
|-- src/
|   `-- websec_audit/
|       |-- checks/          # XSS, SQLi, CSRF и security headers
|       |-- reporting/       # HTML/PDF отчеты
|       |-- cli.py           # интерфейс командной строки
|       |-- crawler.py       # обход сайта
|       |-- http_client.py   # HTTP-клиент
|       |-- parser.py        # HTML-парсер
|       `-- scanner.py       # оркестратор аудита
|-- tests/                   # модульные и интеграционные тесты
|-- docs/                    # архитектура, API, безопасность, Docker, AI
|-- .github/workflows/       # CI-пайплайн
|-- Dockerfile
|-- docker-compose.yml
|-- pyproject.toml
`-- README.md
```

## Сборка

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

Если PowerShell запрещает запуск скриптов:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Linux или macOS

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m playwright install chromium
```

## Запуск

Веб-интерфейс для интерактивного запуска аудита:

```bash
websec-audit-web
```

После запуска откройте `http://127.0.0.1:8080`. В интерфейсе можно ввести URL,
выбрать пассивный или активный режим, настроить глубину краулинга, лимиты,
движок обхода (`auto`, `requests`, `playwright`), TLS-проверку, поддомены и генерацию PDF.

При запуске аудита веб-интерфейс показывает экран ожидания с примерным временем
сканирования. Итоговый отчет содержит кликабельную сводку `High`, `Medium`, `Low`
и `Info`: нажатие переводит к началу списка находок выбранного уровня. В правом
нижнем углу отчета есть кнопка `↑` для быстрого возврата наверх.

### Полная инструкция по использованию веб-интерфейса

1. Откройте PowerShell в папке проекта:

```powershell
cd "C:\Users\Alya\Documents\Курсовая"
```

2. Активируйте виртуальное окружение:

```powershell
.\.venv\Scripts\Activate.ps1
```

Если PowerShell запрещает запуск скриптов, выполните:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

3. Запустите сайт:

```powershell
websec-audit-web
```

Если команда не найдена, используйте альтернативный запуск:

```powershell
python -m websec_audit.web
```

4. Откройте в браузере `http://127.0.0.1:8080/`.

Окно PowerShell закрывать нельзя: пока процесс работает, сайт доступен. Если закрыть
PowerShell, веб-интерфейс остановится.

### Как заполнять форму проверки

| Поле | Что вводить | Для чего нужно |
| --- | --- | --- |
| Адрес сайта | Полный URL с `http://` или `https://`, например `https://example.com` | Стартовая страница, с которой начнется аудит |
| Тип проверки: пассивная | Выбирайте для публичных сайтов и первой проверки | Краулер собирает страницы, формы и заголовки без отправки XSS/SQLi payload |
| Тип проверки: активная | Используйте только для своих сайтов, учебных стендов или систем с разрешением | Дополнительно отправляет тестовые payload в найденные формы для XSS и SQLi |
| Глубина | `0`, `1`, `2` и выше | Насколько далеко переходить по ссылкам: `0` — только стартовая страница, `1` — стартовая и ссылки с нее |
| Страницы | Например `3`, `5`, `10`, `30` | Максимальное количество страниц, которое можно просканировать |
| Timeout, сек | Обычно `10`; для тяжелых сайтов `20` или `30` | Сколько секунд ждать загрузку страницы или ответа сайта |
| Движок краулинга | `Auto`, `Requests only` или `Playwright for JavaScript sites` | Способ обхода страниц |
| User-Agent | Можно оставить стандартный или указать браузерный User-Agent | Как сканер представляется сайту |
| Сканировать поддомены | Обычно выключено | Разрешает переходы на поддомены целевого сайта |
| Не проверять TLS | Только для лабораторных стендов | Отключает проверку SSL-сертификата |
| Создать PDF-отчет | По желанию | Дополнительно сохраняет отчет в PDF |

Режимы движка краулинга:

- `Auto: requests + Playwright fallback` — рекомендуемый режим по умолчанию. Сначала
  используется быстрый requests-обход, а для страниц с признаками SPA подключается Playwright.
- `Requests only` — быстрый режим без браузера. Не подходит для сайтов, где ссылки и формы
  появляются только после JavaScript.
- `Playwright for JavaScript sites` — браузерный обход через Chromium. Используйте для SPA и
  тяжелых JavaScript-сайтов.

### Рекомендуемые настройки для первой проверки

Для обычного сайта или демонстрации на защите:

```text
Адрес сайта: https://example.com
Тип проверки: Пассивная
Глубина: 1
Страницы: 5
Timeout, сек: 10
Движок краулинга: Auto: requests + Playwright fallback
Сканировать поддомены: выключено
Не проверять TLS: выключено
Создать PDF-отчет: включено
```

Для JavaScript/SPA-сайта, например Wildberries:

```text
Адрес сайта: https://www.wildberries.ru
Тип проверки: Пассивная
Глубина: 1
Страницы: 3
Timeout, сек: 30
Движок краулинга: Playwright for JavaScript sites
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36
Сканировать поддомены: выключено
Не проверять TLS: выключено
Создать PDF-отчет: лучше выключить для первого быстрого запуска
```

Для публичных сайтов не включайте активный режим без разрешения владельца. Активная проверка
предназначена для собственных приложений, локальных стендов и учебных демонстраций.

### Что смотреть в результате

После завершения аудита откроется страница результата:

- `High`, `Medium`, `Low`, `Info` показывают количество находок по уровню риска.
- Нажатие на карточку уровня риска переносит к соответствующему списку находок.
- В каждой находке есть описание, доказательство, рекомендация и при наличии Proof-of-Concept.
- В таблице просканированных страниц видно URL, HTTP-статус, заголовок, число форм и ссылок.
- Кнопки `HTML`, `JSON` и `PDF` позволяют открыть сохраненные отчеты.

### Если Wildberries или другой крупный сайт не проверяется

Крупные публичные сайты могут ограничивать автоматический доступ. Возможные причины:

- сайт блокирует автоматизированный браузер;
- контент загружается через внутренние API, cookies, регион или геолокацию;
- страница отдает капчу, редирект или пустой DOM;
- загрузка занимает больше времени, чем указан `Timeout`;
- сайт слишком большой, а лимиты глубины и страниц выбраны слишком высокими.

Что попробовать:

1. Выбрать `Пассивная`.
2. Поставить `Движок краулинга: Playwright for JavaScript sites`.
3. Поставить `Глубина: 1`, `Страницы: 3`, `Timeout: 30`.
4. Выключить `Создать PDF-отчет` для первого запуска.
5. Указать браузерный `User-Agent` из примера выше.
6. Не включать поддомены.

Для стабильной демонстрации курсовой лучше использовать `https://example.com`, локальный
учебный стенд или собственный небольшой SPA-сайт, где у вас есть разрешение на проверку.

Пассивный аудит без отправки payload в формы:

```bash
websec-audit https://example.com --no-active-checks --html-output reports/report.html
```

Полный аудит с HTML, PDF и JSON отчетами:

```bash
websec-audit https://example.com \
  --max-depth 2 \
  --max-pages 30 \
  --crawl-engine auto \
  --html-output reports/report.html \
  --pdf-output reports/report.pdf \
  --json-output reports/report.json
```

Для сайтов, где ссылки и формы появляются только после выполнения JavaScript, можно
принудительно включить браузерный обход:

```bash
websec-audit https://example.com --crawl-engine playwright --no-active-checks
```

Запуск через Docker Compose:

```bash
docker compose up --build
```

Только веб-интерфейс через Docker Compose:

```bash
docker compose up --build web
```

## Примеры использования

Сканирование локального учебного стенда:

```bash
websec-audit http://localhost:8000 --max-depth 1 --max-pages 10
```

Сканирование HTTPS-стенда с самоподписанным сертификатом:

```bash
websec-audit https://lab.local --no-verify-tls --html-output reports/lab.html
```

Сканирование с JSON-отчетом для дальнейшей автоматической обработки:

```bash
websec-audit https://example.com \
  --no-active-checks \
  --html-output reports/example.html \
  --json-output reports/example.json
```

Пример Python API:

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

## Проверка качества

Запуск тестов и проверка покрытия:

```bash
pytest
```

Контрольная строка успешного запуска:

```text
30 passed
TOTAL ... 99%
```

Линтинг:

```bash
ruff check .
```

SAST-анализ:

```bash
bandit -c pyproject.toml -r src
```

Проверка зависимостей:

```bash
pip-audit
```

На Windows при проблемах с кодировкой можно запустить:

```powershell
$env:PYTHONUTF8='1'
python -m pip_audit
```

## Документация

- [Архитектура проекта](docs/architecture.md)
- [API и CLI](docs/api.md)
- [Статический анализ](docs/static-analysis.md)
- [Проверка зависимостей](docs/dependency-security.md)
- [Docker и Docker Compose](docs/docker-check.md)
- [Использование AI-инструментов](docs/ai_usage.md)

## Безопасное использование

Сканер предназначен для учебных стендов, собственных веб-приложений и систем, на
проверку которых есть явное разрешение. Активные проверки XSS и SQLi отправляют
payload-запросы в найденные формы. Для публичных сайтов и демонстраций без
разрешения используйте режим:

```bash
websec-audit https://example.com --no-active-checks
```
