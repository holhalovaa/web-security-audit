# Docker и Docker Compose

Проект поддерживает контейнерный запуск, чтобы сканер можно было воспроизводимо
запустить без ручной настройки локального Python-окружения.

## Dockerfile

`Dockerfile` выполняет следующие шаги:

1. Берет базовый образ `python:3.12-slim`.
2. Устанавливает системные зависимости для Playwright.
3. Копирует `pyproject.toml`, `README.md` и исходный код.
4. Устанавливает пакет `web-security-audit`.
5. Устанавливает Chromium для генерации PDF через Playwright.
6. Использует `websec-audit` как entrypoint.

## Docker Compose

`docker-compose.yml` описывает сервис `scanner`.

Особенности:

- образ собирается из текущего проекта;
- папка `reports/` пробрасывается из контейнера на хост;
- по умолчанию запускается пассивное сканирование `https://example.com`;
- результат сохраняется в `reports/example-report.html`.

## Запуск

```bash
docker compose up --build
```

После успешного запуска отчет появится в папке:

```text
reports/
```

## Пользовательская цель

Для проверки другого адреса можно временно изменить `command` в
`docker-compose.yml` или запустить контейнер напрямую:

```bash
docker build -t web-security-audit:latest .
docker run --rm -v ./reports:/app/reports web-security-audit:latest \
  https://example.com \
  --no-active-checks \
  --html-output reports/report.html
```

Активные проверки следует запускать только для собственных стендов или систем,
на тестирование которых есть разрешение.
