<p align="center">
  <img src="app/static/img/logo-color.svg" alt="Evidentia" width="240">
</p>

<p align="center">
  <b>Secure Digital Evidence Locker</b><br>
  A tamper-evident case &amp; evidence management platform with cryptographic audit trails,
  two-factor authentication, login alerts, and role-based access control.
</p>

<p align="center">
  <a href="https://github.com/k-shopnil/evidentia/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/k-shopnil/evidentia?style=for-the-badge&label=License&color=0A0A0B" alt="MIT License">
  </a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-0A0A0B?style=for-the-badge&logo=python&logoColor=F8FF20" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Framework-FastAPI-0A0A0B?style=for-the-badge&logo=fastapi&logoColor=F8FF20" alt="FastAPI">
  <img src="https://img.shields.io/badge/Database-PostgreSQL-0A0A0B?style=for-the-badge&logo=postgresql&logoColor=F8FF20" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Storage-S3%20%2F%20B2-0A0A0B?style=for-the-badge&logo=amazons3&logoColor=F8FF20" alt="S3-compatible storage">
  <img src="https://img.shields.io/badge/Deployed-Vercel-0A0A0B?style=for-the-badge&logo=vercel&logoColor=F8FF20" alt="Vercel">
  <img src="https://img.shields.io/badge/Status-Active-0A0A0B?style=for-the-badge&color=67C23A" alt="Active">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Passwords-Argon2id-191A1C?style=flat-square&logo=key&logoColor=F8FF20" alt="Argon2id">
  <img src="https://img.shields.io/badge/2FA-TOTP-191A1C?style=flat-square&logo=shield&logoColor=F8FF20" alt="TOTP 2FA">
  <img src="https://img.shields.io/badge/Audit-SHA-256%20Chain-191A1C?style=flat-square&logo=git&logoColor=F8FF20" alt="SHA-256 audit chain">
  <img src="https://img.shields.io/badge/Sessions-Signed%20Cookies-191A1C?style=flat-square&logo=lock&logoColor=F8FF20" alt="Signed sessions">
  <img src="https://img.shields.io/badge/Alerts-SMTP%20%2F%20SMS-191A1C?style=flat-square&logo=mail&logoColor=F8FF20" alt="SMTP/SMS alerts">
  <img src="https://img.shields.io/badge/Code-Python-191A1C?style=flat-square&logo=python&logoColor=F8FF20" alt="Python">
</p>

> Live demo: **[https://evidentia-khaki.vercel.app](https://evidentia-khaki.vercel.app)** — the first account registered
> in any fresh instance becomes the **admin**; every account after that is an **officer**.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Security & Integrity](#security--integrity)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Demo Mode](#demo-mode)
- [Login Alerts](#login-alerts)
- [Deployment](#deployment)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [API Routes](#api-routes)
- [License](#license)

---

## Features

### Case Management
- Create, open, and **close cases** with structured metadata (title, case ID, priority, status).
- Attach **multiple pieces of evidence** per case (PDF, images, text — MIME-whitelisted, 100 MB cap).
- Evidence uploads are stored in **S3-compatible object storage** (Cloudflare R2 / Backblaze B2) with presigned download URLs.

### Integrity & Trust
- Every recorded action is appended to a **SHA-256 hash chain** — each audit record carries the hash of the previous one. Any tampering breaks the chain and is immediately detectable.
- Evidence files are **hash-verified on download** (`Integrity Verified` / `Integrity Compromised`), so corrupted or swapped files are caught.
- Hash-only evidence fingerprints are stored on the database — raw files live in object storage, unused capacity stays local on demand.

### Access Control
- **First registered user becomes admin**; subsequent users are officers.
- Role-based UI (admin panel for user management and unlocking) vs. officer workflow.
- **Account lockout** after 5 failed attempts (15 min) — admins can unlock accounts manually.
- Per-route **rate limiting** (login, register, general) with SlowAPI.

### Authentication
- **TOTP two-factor authentication** (authenticator-app style) with QR enrollment on first login.
- **Argon2id** password hashing.
- **Forgot-password flow** — one-time, hashed, 60-minute-expiring reset tokens, enumeration-safe responses, rate-limited, fully audited.
- Signed, HttpOnly session cookies (Secure flag in production).
- **Show/hide password toggles** (via eye icons) on login, register, and reset forms.
- A clean, dark "operational console" UI: near-black surfaces with a volt `#F8FF20` accent, Space Grotesk typography, status-dot indicators, and mono type for hashes/codes.

### Alerts & Notifications
- **New-device login alerts** — first sign-in from an unrecognized device fingerprints sends a branded email alert (SMS via Twilio when configured and a phone number is on file).
- Branded, dark-theme HTML emails for login alerts and password reset.
- Password reset **audit trail**: `PASSWORD_RESET_REQUESTED` / `PASSWORD_RESET_COMPLETED` / `PASSWORD_RESET_EMAIL_FAILED`.

### Demo Mode
- `DEMO_MODE=true` exposes safe, destructive-but-reversible controls: **Reset Demo Data**, **Simulate Evidence Tamper**, **Verify Chain** — perfect for showcasing integrity detection without real data risk.

---

## Architecture

```mermaid
flowchart LR
  subgraph Client
    B[Browser]
  end
  subgraph Server["FastAPI App (Vercel Serverless)"]
    R[API + Auth Router]
    D[Dashboard / Case / Audit Routers]
    S[Services<br/>audit chain, alerts,<br/>password reset]
    M[SQLAlchemy Models]
    A[Argon2id + TOTP + Sessions]
  end
  subgraph Data
    N[(PostgreSQL<br/>Neon)]
    O[(S3-compatible<br/>R2 / B2)]
  end
  subgraph Out
    SMTP[(Email<br/>Resend / SMTP)]
    TW[(SMS<br/>Twilio)]
  end

  B --> R
  B --> D
  R --> A
  D --> S
  S --> M
  M --> N
  S --> O
  S --> SMTP
  S --> TW
```

**Request flow (upload path):** browser uploads evidence -> API validates MIME/size + CSRF + auth -> file streamed to object storage -> SHA-256 computed server-side -> fingerprint + metadata stored in PostgreSQL -> audit record appended to the hash chain.

---

## Security & Integrity

| Layer | Mechanism |
| --- | --- |
| Passwords | Argon2id (via `argon2-cffi`) |
| Session | Signed HttpOnly cookie, Secure + SameSite=Lax in production, 60 min expiry |
| CSRF | Per-session token on every state-changing route |
| 2FA | TOTP (RFC 6238, `pyotp`), QR enrollment, required on login |
| Brute force | 5-attempt lockout (15 min) + SlowAPI rate limits |
| Reset tokens | 256-bit random, stored as SHA-256 hashes, single-use, 60-min TTL |
| Audit chain | SHA-256 hash chaining — every record binds to its predecessor; tampering is detectable |
| Evidence | SHA-256 fingerprints, integrity check on download, MIME whitelist |
| Errors | Enumeration-safe responses (login, password reset) |

---

## Getting Started

```bash
git clone https://github.com/k-shopnil/evidentia.git
cd evidentia
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Open **http://localhost:8000**, register the first account — it becomes the **admin** immediately.

> Local development defaults to SQLite + local disk storage for evidence — zero extra services required to start building.

---

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | dev-only | Signs session cookies — required in production |
| `DATABASE_URL` | `sqlite:///./evidentia.db` | SQLAlchemy connection string (`postgresql+psycopg://...` in production) |
| `DEBUG` | `true` | Dev mode (templates, stack traces) |
| `SESSION_COOKIE_SECURE` | `false` | Force `true` behind HTTPS |
| `DEMO_MODE` | `false` | Enables demo controls (reset / tamper / verify) |
| `STORAGE_BACKEND` | `auto` | `local` or `s3` (auto-detected when R2 vars are present) |
| `R2_ENDPOINT_URL` | — | S3-compatible endpoint (R2 / B2) |
| `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | — | Object storage credentials |
| `R2_BUCKET` | — | Storage bucket name |
| `EVIDENCE_STORAGE_PATH` | `./app/storage/evidence` | Local backend directory |
| `MAX_FILE_SIZE_MB` | `100` | Upload cap |
| `ALLOWED_MIME_TYPES` | pdf, jpeg, png, gif, txt | Upload whitelist |
| `LOCKOUT_MAX_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_DURATION_MINUTES` | `15` | Lockout window |
| `RATE_LIMIT_LOGIN` | `5/minute` | Login rate cap |
| `RATE_LIMIT_REGISTER` | `3/minute` | Registration rate cap |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` | — | Email delivery (e.g. Resend free SMTP) |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM_NUMBER` | — | Optional SMS login alerts |

---

## Demo Mode

With `DEMO_MODE=true`, an **admin-only** control panel appears on the dashboard:

| Control | What it does |
| --- | --- |
| **Reset Demo Data** | Rebuilds the demo case + evidence (keeps only the acting admin account), reseeds a clean audit chain |
| **Simulate Evidence Tamper** | Swaps a byte in a stored evidence file — integrity reports flip to `Integrity Compromised` |
| **Simulate Audit Tamper** | Edits an audit record — the chain verification reports exactly where the tampering was detected |
| **Verify Chain** | Runs the full audit-chain verification and shows the verdict |

This is the fastest way to see tamper detection in action without touching real data.

---

## Login Alerts

When a user signs in from a device the platform has never seen before (browser fingerprint + IP), it records a `SECURITY_ALERT_NEW_DEVICE` audit entry and notifies the account holder:

- **Email** — branded Evidentia HTML template via SMTP (Resend free tier works out of the box).
- **SMS** — via Twilio, used when `TWILIO_*` variables are set **and** the account has a phone number.

The dashboard shows a **Security Alerts panel** for the signed-in user: time, device, channel, and delivery status (`delivered` / reason it was not sent).

---

## Deployment

The app ships as a single serverless entrypoint (`api/index.py` -> `app.main`) with `vercel.json` routing all traffic to it.

**Recommended stack (all free tiers):**

1. **Hosting** — Vercel: `vercel deploy --prod --yes`
2. **Database** — Neon (PostgreSQL): set `DATABASE_URL`, the schema auto-initializes on first cold start.
3. **Storage** — Cloudflare R2 or Backblaze B2 (S3 API): set `STORAGE_BACKEND=s3` + the five `R2_*` variables.
4. **Email** — Resend free SMTP: set the `SMTP_*` variables (smtp.resend.com:587).
5. **SMS (optional)** — Twilio trial: set the `TWILIO_*` variables.

> The first cold start runs `init_db()` — it creates tables and `ALTER TABLE`-style `_ensure_column` migrations automatically; no manual DDL needed.

---

## Testing

The test suites are self-contained scripts (each spins up its own SQLite DB and cleans nothing — run from the repo root):

```bash
python test_demo_mode.py        # demo lifecycle: first-user admin, seed, tamper+verify, officer lockout/unlock
python test_audit_chain.py      # chain construction, tamper simulation, hash-chaining verification
python test_cases_evidence.py   # case CRUD, evidence upload/download/verify, permissions
```

Covered: first-registered-user-becomes-admin, demo reset (no fake accounts), chain validity after seed, evidence tamper -> `Integrity Compromised` -> restore -> `Integrity Verified`, audit tamper detection with record-level detail, admin unlocks, plus login/2FA/lockout flows and the full password-reset lifecycle (token hashing, single-use enforcement, enumeration resistance, audit trail).

---

## Project Structure

```
evidentia/
├── api/
│   └── index.py                # Vercel serverless entrypoint (mangum)
├── app/
│   ├── main.py                 # FastAPI app, session/CSRF/rate-limit middleware
│   ├── config.py               # Environment-driven settings
│   ├── database.py             # Engine, session factory, init_db + column migrations
│   ├── models.py               # User, Case, Evidence, AuditLog, PasswordResetToken
│   ├── routers/
│   │   ├── auth.py             # login, register, 2FA, logout, password reset
│   │   ├── dashboard.py        # overview + security alerts + demo controls
│   │   ├── cases.py            # case + evidence CRUD, downloads, close case
│   │   ├── audit.py            # audit log page + chain verification
│   │   └── admin.py            # user management, role change, unlock
│   ├── services/
│   │   ├── audit.py            # SHA-256 hash-chain ledger + verification
│   │   ├── email.py            # SMTP dispatch, branded HTML templates
│   │   ├── alerts.py           # new-device detection + notification orchestration
│   │   ├── password_reset.py   # request/complete/validate reset tokens
│   │   └── storage.py          # local + S3 backends, presigned URLs, hashing
│   ├── security/
│   │   ├── auth.py             # session management, device fingerprinting
│   │   └── password.py         # Argon2id hash/verify
│   ├── static/
│   │   ├── css/style.css       # full dark "console" design system
│   │   └── js/password-toggle.js
│   └── templates/              # Jinja2 auth / dashboard / cases / audit / admin
├── test_*.py                   # end-to-end suites (see Testing)
├── vercel.json                 # serverless routing
└── .env.example
```

---

## API Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET/POST | `/register` | Create account (first user = admin) |
| GET/POST | `/login` | Sign in (+ new-device alert) |
| GET/POST | `/verify-2fa` | TOTP enrollment & verification |
| GET/POST | `/forgot-password` | Request reset email (enumeration-safe) |
| GET/POST | `/reset-password` | Redeem one-time reset token (CSRF + length enforced) |
| GET | `/dashboard` | Overview, recent cases, security alerts, demo panel |
| GET/POST | `/cases` | List / create cases |
| GET/POST | `/cases/{id}` | Detail + evidence upload |
| GET | `/cases/{id}/evidence/{eid}/download` | Download with integrity check |
| POST | `/cases/{id}/close` | Close a case |
| GET | `/audit` | Audit log with chain verification |
| GET | `/admin/users` | User management (admin only) |
| POST | `/logout` | End session |

---

## License

[MIT](/LICENSE) — free to use, study, change, and redistribute. Built with FastAPI, SQLAlchemy, Bootstrap, and a lot of argon.