# SentinelQ design

SentinelQ is an independent reporting prototype. Its interface takes inspiration from the task-based navigation of [CPGRAMS](https://www.pgportal.gov.in/Sitemap) and the clear process explanations of the [Parliamentary and Health Service Ombudsman](https://www.ombudsman.org.uk/making-complaint/how-we-deal-complaints). It must never imply government affiliation or promise anonymity.

## Visual language

- Ink: `#203a40`; action green: `#205a4b`; background: `#f8f9f6`.
- White form surfaces, pale sage guidance, muted brass accents. No gradients, ornamental dashboards or animated security badges.
- Georgia for introductory headings and the wordmark; locally bundled Open Sans for body text and controls; IBM Plex Mono for case identifiers.
- Small corner radii, visible field borders, generous line spacing, clear hierarchy and descriptive action labels.
- `frontend/src/styles.css` supplies shared component styles; `frontend/src/portal.css` supplies the public-service layout and responsive presentation.

## Reporter experience

The initial Getting started page explains four steps: describe the concern, optionally attach evidence, save case credentials, and return for updates. Each step has a short explanation and a restrained speech-bubble reminder. Users can select any step, move forward/back, or start reporting immediately.

Main navigation always exposes Getting started, Submit report, Track a case and Authority sign in. Quick exit is available in the header throughout the app. It clears the current workspace and leaves the page; it does not erase browsing history or network records.

The report form retains its original submission and privacy-helper APIs. Section links lead to incident details, optional evidence and submission. Files can be removed before submitting. The applied redaction state is explicit. Submission results receive focus so the recovery key or error is not missed. Draft state survives internal navigation but is not persisted across refreshes.

## Trust and accessibility

Explain actual protections: encryption in storage, restricted case access and additional authorization for originals. Explain limitations in plain language. Never present a decorative shield as live security verification.

Use native buttons and disclosures, visible keyboard focus, a skip link, labeled inputs, announced guide changes and errors, and focus management when changing views. Mobile layouts collapse to one column; all four process steps remain directly accessible. Respect reduced-motion preferences. Maintain the existing backend authorization and evidence-processing boundaries.

## Validation

The September 2026 refresh was built with `node frontend/build.js` and checked against all 52 existing backend tests. Browser checks covered the four-step guide, required fields, draft preservation, successful submission, recovery-key case access, reporter follow-up, and authority sign-in with automatic queue loading. Desktop and 390 px mobile layouts were inspected; report and onboarding pages had no horizontal overflow. Browser workflow checks used isolated temporary case data.
