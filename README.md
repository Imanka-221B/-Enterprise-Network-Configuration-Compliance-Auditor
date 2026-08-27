# ENCCA v5 – Compliance Engine v2.1 + Risk Assessment Engine v1.0

Deterministic, local compliance auditing for Cisco enterprise configurations.

## What was improved in v2.1

### 1. Rule applicability and context
- Rules now declare their intended scope/applicability in `rules/rules.json`.
- Interface roles are parsed from configuration context.
- Active access ports, trunks, approved uplinks, DHCP-enabled access ports and unused ports are treated differently.
- DHCP Snooping trust and DAI trust controls (`TRK-003` / `TRK-004`) apply only to interfaces classified as `approved_uplink`.
- Controls that do not apply to a target are represented as `NOT_APPLICABLE` and are excluded from the compliance score.

### 2. SSH rule refinement
- `SSH-001` checks actual global SSH configuration instead of inferring SSH configuration from VTY transport alone.
- `SSH-002`, `SSH-003` and `SSH-004` remain separate controls for SSH version, authentication retries and SSH timeout.
- This keeps each SSH control independently testable and explainable.

### 3. Findings UI improvement
- Findings table is reduced to the most important columns.
- Failed findings expose Expected, Recommendation, Remediation, Reference and Applicability through expandable details.
- Status badges distinguish `PASS`, `FAIL` and `NOT_APPLICABLE`.
- Parsed interfaces now display the detected interface role.

### 4. Basic compliance score
- A deterministic compliance score is displayed:

  `Passed Applicable Checks / Total Applicable Checks × 100`

- `NOT_APPLICABLE` controls are excluded from the score.
- Severity weighting is intentionally reserved for the future Risk Assessment Engine.

## Baseline verification

### Secure sample
- Applicable checks: **39**
- Passed: **37**
- Failed: **2**
- Not applicable: **0**
- Compliance score: **94.87%**
- Remaining failures: `STORM-001` and `STORM-002` on `GigabitEthernet1/0/2`

### Insecure sample
- Applicable checks: **38**
- Passed: **0**
- Failed: **38**
- Not applicable: **6**
- Compliance score: **0.00%**

The not-applicable findings prevent controls such as port-security maximum/violation checks from being treated as independent failures when port security itself is not enabled.

## Tests

Run:

```bash
pytest -q
```

Expected result:

```text
5 passed
```

## Project characteristics

- No AI is used in the compliance decision logic.
- No external APIs are required.
- Rules are deterministic and auditable.
- Risk scoring and severity-weighted assessment are intentionally deferred to the Risk Assessment Engine.

## Risk Assessment Engine v1 Integration

Version 5 integrates the deterministic Risk Assessment Engine v1 directly after the Compliance Engine v2.1.

Workflow:
`Upload → Parse → Compliance Audit → Risk Assessment → Dashboard`

The compliance engine remains authoritative for PASS/FAIL. The risk engine uses the rule catalogue severity for both PASS and FAIL findings, even though PASS severity may be displayed as `-` in the UI.

For `parser_v2_sample.txt`, the integrated engine produces:
- 39 applicable compliance checks
- 37 passed
- 2 failed
- Failed severity weight: 3 (Medium 2 + Low 1)
- Applicable severity weight: 87
- Risk percentage: 3.45%
- Security score: 96.55/100
- Overall risk level: Low

Run the tests with:
```bash
python -m unittest discover -s tests -v
```


## Professional Enterprise UI

The Flask presentation layer has been redesigned as a Cisco-inspired enterprise security console while preserving the existing deterministic engines.

UI improvements include:
- Fixed enterprise sidebar and top navigation
- ENCCA product branding and engine/version indicators
- Audit completion and device context panels
- Compliance metric cards and scoring explanation
- Visual Risk Assessment gauge
- Risk distribution by Critical/High/Medium/Low severity
- Risk breakdown by category
- Search and severity/status filtering for findings
- Expandable evidence, expected result, recommendation and remediation details
- Structured VLAN, VTY and interface inventory views
- Professional configuration upload workflow
- Responsive layout for smaller screens

The UI is presentation-only: Compliance Engine v2.1 remains authoritative for PASS/FAIL/NOT_APPLICABLE decisions, and Risk Engine v1.0 remains authoritative for the existing severity-weighted risk calculation.


## UI v2.0 – Professional Polish Pass

The UI v2.0 pass refines the existing enterprise console based on rendered audit-result screenshots.

### Visual and interaction refinements
- More compact dashboard spacing so compliance and risk posture are visible sooner.
- Refined ENCCA/Cisco-inspired navigation, borders, shadows and information hierarchy.
- Added explicit `Local Audit` environment indicator while retaining the existing `System Operational` state.
- Removed decorative topbar controls that did not perform an application action.
- Added section-aware sidebar highlighting as the user moves through Dashboard, Compliance, Risk Assessment, Findings, Audit Report and Device Data.
- Improved risk gauge semantics by matching the gauge accent to the calculated risk level.
- Added a dedicated risk posture banner with risk level, calculated risk percentage and security score.
- Improved table density, hover states, sticky table headers and evidence readability.
- Refined search/filter controls and target/status/severity badges.
- Improved detail popovers and enterprise card consistency.
- Refined responsive behavior for smaller screens.
- Preserved all existing Compliance Engine v2.1 and Risk Engine v1.0 decision/scoring logic.

### Functional boundary
This pass changes the presentation layer only. It does not alter:
- parser behavior
- compliance rule evaluation
- compliance scoring
- risk weighting
- risk classification
- recommendations generated by the existing engines


### PDF report dependency

The Audit Report PDF generator uses ReportLab. Install all dependencies before running ENCCA:

```bash
python -m pip install -r requirements.txt
```

This installs Flask and ReportLab required by the PDF download feature.

## Authentication & Security

ENCCA protects all audit, history and report routes with a SQLite-backed server-side session service. The Flask cookie contains only a signed random session identifier; identities, permissions, CSRF state and timeout metadata remain in SQLite. Uploaded Cisco configurations and their derived findings are accessible only after sign-in.

### Roles

- **Administrator**: performs audits and manages users, roles, account status and password resets.
- **Security Analyst**: performs audits and can view only audits attributed to their account.

Visitors may register a **Security Analyst** account from the Login page, then sign in. Public registration can never create an administrator; administrator accounts remain controlled by the secure bootstrap process or an existing administrator.

Passwords are never stored in plaintext. ENCCA uses Werkzeug's current secure password hashing implementation. Passwords must have at least 12 characters and include uppercase, lowercase, numeric and special characters. Five consecutive invalid attempts lock an account for 15 minutes; all authentication failures use the same generic response.

### First administrator

ENCCA creates an administrator only on first run, only when no administrator exists, and only when all of these environment variables are configured. No default credentials exist.

```text
FLASK_SECRET_KEY=<long-random-secret>
ENCCA_ADMIN_USERNAME=<initial-admin-username>
ENCCA_ADMIN_EMAIL=<initial-admin-email>
ENCCA_ADMIN_PASSWORD=<strong-password-meeting-policy>
```

For local PowerShell development, set the values before starting the app:

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
$env:ENCCA_ADMIN_USERNAME = "initial-admin"
$env:ENCCA_ADMIN_EMAIL = "admin@example.invalid"
$env:ENCCA_ADMIN_PASSWORD = "ReplaceWithAStrongPassword!1"
python app.py
```

Use `.env.example` only as a placeholder guide; do not commit a real `.env` file. After the initial login, administrators create additional accounts from **Users** in the ENCCA interface.

### Session and request security

### Timezone handling

Audit timestamps are generated as timezone-aware UTC ISO-8601 values and stored unchanged. The UI and PDF convert them for presentation using the configurable `ENCCA_TIMEZONE`, which defaults to `Asia/Colombo`; legacy audit values in the former `%d %b %Y, %H:%M` format are treated as UTC because that was the previous writer's source clock. No server clock or fixed offset arithmetic is used.

### Relational persistence

The application uses SQLite locally and PostgreSQL in production through the shared database adapter. Startup schema creation is idempotent and records the `audit-relational-v1` migration in `schema_migrations`; it never drops tables or deletes data. The relational tables are `users`, `user_sessions`, `configurations`, `audits`, `audit_findings`, `security_events` and `reports`, with foreign keys and query indexes. Audit payloads remain in `audits.payload_json` for compatibility while their configuration metadata and findings are normalized for querying.

To migrate an existing local SQLite account database and JSON audit records into the configured PostgreSQL database, set `ENCCA_DATABASE_URL` and run:

```bash
python -m database.migrate --source-db private/encca_auth.sqlite3 --audit-dir audit_records
```

The migration preserves password hashes, stable user IDs, audit IDs and findings, skips records already present, and reports migrated/skipped counts. Raw configuration files and generated PDFs remain filesystem artifacts until object storage is introduced; their relational storage references are recorded where available.

Sessions use HTTP-only, `SameSite=Lax` cookies, `Path=/`, and secure cookies automatically on Vercel/HTTPS. The default idle timeout is 15 minutes, the absolute timeout is 8 hours, and concurrent sessions are unlimited by default. An optional positive `ENCCA_MAX_CONCURRENT_SESSIONS` value enables oldest-session eviction. These values are configurable with `ENCCA_SESSION_IDLE_TIMEOUT_MINUTES`, `ENCCA_SESSION_ABSOLUTE_TIMEOUT_HOURS`, and `ENCCA_MAX_CONCURRENT_SESSIONS`. Every state-changing form (login, upload and user management) carries a cryptographically random CSRF token whose hash is stored server-side. Login return URLs are restricted to local ENCCA paths. Logout revokes only the current session; user deactivation and password reset revoke all sessions for that account. Session expiry never changes the account or user data.

### Vercel

Set `FLASK_SECRET_KEY`, `ENCCA_DATABASE_URL` and the administrator environment variables in **Vercel Project Settings → Environment Variables** for Production, Preview and Development as appropriate. `ENCCA_DATABASE_URL` must be a durable PostgreSQL connection string from Neon or another managed provider. `DATABASE_URL`, Vercel’s `POSTGRES_URL_NON_POOLING`, `POSTGRES_URL` or `POSTGRES_PRISMA_URL`, and `NEON_DATABASE_URL`/`NEON_DATABASE_URL_UNPOOLED` are accepted as fallbacks. The deployment returns a clear configuration response when no URL is configured rather than creating an ephemeral account database.

Local development continues to use `private/encca_auth.sqlite3` when no database URL is configured. Vercel uses PostgreSQL for the `users` and `user_sessions` tables, so accounts remain available across function instances, restarts, browsers and devices. The JSON audit records and generated PDFs still use temporary Vercel filesystem storage and should be moved to object storage separately if those artifacts must persist in production.

### Tests

Install dependencies and run all parser, compliance, risk, PDF and authentication tests with:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```
