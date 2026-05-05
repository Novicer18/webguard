# WebGuard - Automated Web Security Scanner

WebGuard is a Django-based SaaS-style web security scanner. Users can register, submit website URLs, and receive scan reports with risk ratings, vulnerability insights, and remediation recommendations.

## Features
- User registration/login/logout with Django auth
- URL submission and asynchronous background scan execution
- Security checks for headers, HTTPS, cookie flags, reflected input probes, and SQLi form-surface heuristics
- Dashboard with scan history and risk/score metrics
- Detailed vulnerability report pages with recommendations
- Export report to PDF
- Optional API endpoints via Django REST Framework
- Rate limiting per user/IP
- Env-based Neon/PostgreSQL configuration

## Apps
- `accounts`: registration and authentication
- `scanner`: scan engine, models, API, PDF export
- `dashboard`: dashboard and report pages

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Update `.env` with your Neon `DATABASE_URL`.

## Security Considerations
- CSRF middleware enabled
- Session authentication with hashed passwords
- ORM-only database access
- Escaped template rendering
- URL validation and sanitation
- Rate limiting and request timeout handling
- UI warning: "Only scan websites you own or have permission to test"

## Deployment Notes
- Gunicorn entrypoint: `gunicorn webguard.wsgi:application`
- Set `DEBUG=False` in production
- Configure `ALLOWED_HOSTS`
- Use SSL-enabled managed Postgres (Neon)
- Run `python manage.py collectstatic --noinput`

## API
- `POST /scanner/api/scans/` with JSON `{ "target_url": "https://example.com" }`
- `GET /scanner/api/scans/<id>/`
