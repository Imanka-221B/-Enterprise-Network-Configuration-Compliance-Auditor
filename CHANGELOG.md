## Audit History — 23 Aug 2026

- Added a dedicated **Audit History** section under Reporting.
- Added persisted audit record discovery from `audit_records/`.
- Added search by hostname, configuration filename, or audit ID.
- Added risk-level filters for All, Critical, High, Medium, and Low.
- Added summary cards for total audits, average compliance, critical posture, and failed controls.
- Added View, Report, and PDF actions for each historical audit.
- Reused the existing ENCCA Cisco-style collapsible sidebar and Poppins UI.
- Audit History is presentation/navigation functionality; compliance and risk engines remain unchanged.

## UI + PDF Alignment Polish — 23 Aug 2026

- Fixed Audit Report delivery card spacing and responsive text/button layout.
- Prevented report statistics rows from clipping long labels/values.
- Aligned the PDF Prioritized Risk Findings table with the UI columns, including Recommendation.
- Corrected PDF table widths to the A4 printable area so Evidence and other columns no longer run outside the page.
- Tightened appendix typography and wrapping for long configuration evidence.
- Added a PDF layout regression test.

## UI v2.2 — Poppins Typography
- Added Google Fonts Poppins (400–800) to the New Audit and Audit Results pages.
- Updated the global UI font stack to Poppins-first for a cleaner Cisco-inspired enterprise dashboard appearance.
- No Compliance Engine, Risk Engine, parser, scoring, or audit workflow logic changed.

## UI v2.1 — Sidebar Rail Stability Fix
- Fixed collapsed sidebar text leaking into the 72px navigation rail.
- Added `.nav-text` wrappers so labels hide cleanly in collapsed mode.
- Kept the ENCCA logo as the primary expand control.
- Restored a compact chevron control in the collapsed rail.
- Applied the same behavior consistently to New Audit and Audit Results pages.
- Removed the decorative non-interactive rail hint that caused the stray chevron.
- Preserved Compliance Engine v2.1 and Risk Engine v1.0 logic unchanged.

# ENCCA Compliance Engine Changelog

## v2.1 – Compliance Engine Stabilization

1. Added context-aware rule applicability and interface roles.
2. Restricted DHCP Snooping trust and DAI trust checks to approved uplinks.
3. Refined SSH-001 to use actual global SSH configuration.
4. Kept SSH version, retry and timeout controls independent.
5. Added `NOT_APPLICABLE` findings and excluded them from compliance scoring.
6. Added a basic deterministic compliance score.
7. Reworked the findings UI with expandable remediation details.
8. Added applicability and role information to the report.
9. Added regression tests for secure, insecure and applicability scenarios.
10. Deferred severity-weighted risk scoring to the Risk Assessment Engine.


## UI Professionalization – v5

- Reworked Flask UI into an ENCCA enterprise application shell.
- Added Cisco-inspired navy/blue visual language without changing backend decision logic.
- Added dashboard-style compliance and risk metrics.
- Added risk gauge, severity distribution and category contribution views.
- Added searchable/filterable compliance and risk findings.
- Added structured audit/device context and completion state.
- Added professional configuration upload workflow.
- Improved responsive behavior and table readability.


## UI v2.0 – Professional Polish Pass

- Tightened dashboard spacing and card proportions for faster security-posture scanning.
- Refined sidebar and topbar hierarchy for a more mature network-security-console appearance.
- Added Local Audit environment context.
- Replaced non-functional decorative topbar controls with clear status context.
- Added active section tracking while scrolling through audit results.
- Added risk-level-aware security score gauge styling.
- Added a dedicated calculated-risk posture banner.
- Improved findings-table density, sticky headers, hover states and evidence presentation.
- Refined badges, target chips, search controls and expandable finding details.
- Updated responsive behavior without changing the deterministic backend engines.

## UI v2.2 — Security Statistics & Charts
- Added a Security Statistics section to Audit Results.
- Added control health, risk exposure, interface inventory, and critical/high summary metrics.
- Added presentation-only compliance outcome, risk severity, and weighted risk-by-category visualizations.
- Statistics are derived from Compliance Engine v2.1 and Risk Assessment Engine v1.0 outputs without changing authoritative decisions.
- Added Security Statistics navigation entry with existing collapsible sidebar support.

## UI v2.2 — Security Statistics & Charts
- Added a dedicated Security Statistics & Charts section to Audit Results.
- Added sidebar navigation entry for direct access to Security Statistics.
- Added compliance outcome, risk severity, risk category contribution, and interface inventory visualizations.
- Statistics are presentation-only and derived from existing Parser v2, Compliance Engine v2.1, and Risk Engine v1.0 outputs.

## Audit Report Statistics Card UI Fix — 23 Aug 2026

- Added consistent horizontal inset to Control Outcome and Severity Distribution rows.
- Prevented statistic labels and values from touching panel edges.
- Preserved responsive behavior with reduced padding on narrower layouts.
