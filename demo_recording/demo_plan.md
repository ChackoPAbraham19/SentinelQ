# SentinelQ application demonstration

The completed [application_demo.mp4](application_demo.mp4) records SentinelQ running in Google Chrome on October 9, 2026. It demonstrates the report-to-review workflow with the existing application, real API responses, and its actual encrypted storage and evidence-processing worker. The video is 4 minutes 47 seconds, 1920 × 1080, H.264, 30 FPS, with no voiceover.

## Project inspected

SentinelQ is a web application. Its React 18 interface uses Axios and is built with esbuild. The backend is a Node.js HTTP server whose entry point is `backend/index_no_deps.js`. It supports an encrypted local vault and a Supabase database/private evidence bucket. FFmpeg and FFprobe create the masked media review copies. New stored content uses ML-KEM-768, HKDF-SHA512 and AES-256-GCM; new case manifests use ML-DSA-65 signatures.

The normal development commands are `npm --prefix backend start` and `npm --prefix frontend start`. For recording, the built frontend can be served by the backend through `SENTINELQ_SERVE_FRONTEND=1`. This provides one local origin and requires no separate database service when `SENTINELQ_STORAGE_PROVIDER=local` is selected. No external AI service is needed for the rule-based privacy helper.

The recording uses a separate, loopback-only local instance and a new evaluation vault. Existing reports, private `.env` values, and cloud records must remain untouched. Submitted content must visibly identify itself as evaluation material. These are real application records created for the demonstration, not mocked API responses or claims about a real incident.

## Recorded sequence

The automation waited for actual page and API completion. The timings below are rounded chapter starts from the recorded run's timeline; no time compression or temporal speedup was applied to the recording.

| Segment | Approximate time | Real interaction and observed result |
| --- | --- | --- |
| Introduction and cryptography | 0:00–0:32 | Show the clean Getting started page, interact with the reporting guide, and open the encryption FAQ with its stated limitations. Identify the app as a reporting prototype and the data as evaluation material. |
| Privacy-aware intake | 0:32–1:03 | Enter an explicitly fictional title and description. A harmless example email triggers advisory warnings. Generate and review a safer version, then apply it. |
| Evidence and receipt | 1:03–1:21 | Upload the user-provided MP4, submit, and wait for the actual durable receipt. Show the generated Case ID with the recovery key concealed. |
| Reporter follow-up | 1:21–1:51 | Open Track a case using the newly issued details. Show the real status and evidence-processing state, then send an evaluation follow-up. |
| Authority review | 1:51–2:40 | Sign in to the isolated administrator account. Filter the queue, save status and priority, assign the investigator, and add an internal note. |
| Evidence custody and playback | 2:40–3:07 | Confirm actual artifact integrity, download the masked video produced by FFmpeg, and play those downloaded bytes in an explicitly labeled presentation player. |
| Accountable access boundary | 3:07–3:21 | Show that Request original requires a personal key, reference/reason and fresh viewer photo. Cancel without requesting camera permission or granting original access. Show recent audit events. |
| Reply, summary and closure | 3:21–3:43 | Send a reviewer reply, download a summary containing the actual case and reply, and close the evaluation case. |
| Complete the conversation | 3:43–4:13 | Recover the case and show its Closed status and real authority reply. Confirm the reporter view does not disclose internal notes. Refresh and clear the recovery credentials. |
| Role boundaries | 4:13–4:39 | Sign in as the auditor, show read-only case/audit access, and sign out. |
| Clean close | 4:39–4:47 | Display a brief closing card and return to the clean Getting started page. |

## Evidence source

Use exactly the video supplied by the user for video-evidence intake:

`C:\Users\festi\Downloads\gemini_generated_video_84ae97c3.mp4`

The inspected file is 2,085,154 bytes, within the application's eight MiB aggregate evidence limit. The original source file must not be altered or deleted. Its filename indicates generated media; the demonstration must describe it as user-supplied evaluation footage, not authentic proof of an incident.

The recording should show only a masked review copy after the backend reports that processing and integrity verification succeeded. A download alone does not imply an original-preview authorization. If processing fails, record/report that actual state and do not replace it with an invented success screen.

## Presentation and truthfulness

- Record the real Chrome application viewport at 1920 × 1080 where supported, and deliver a landscape H.264 MP4 at 30 FPS.
- Use small opening/section labels and a visible cursor only to explain real actions. Opening and closing cards are demo-only presentation aids. Do not replace application output with designed mock screens.
- Any enlarged playback of a masked video must use the actual downloaded review copy and be explicitly labeled Chrome playback. SentinelQ's current review UI provides a masked-copy download; the presentation must not imply that an extra in-app preview feature exists.
- Use no voiceover or soundtrack. Capture only the Chrome content viewport; browser chrome and the rest of the desktop are intentionally outside the frame.
- Keep account passwords and the recovery key visually concealed. The isolated evaluation credentials are not production credentials.
- Use actual clicks, typing, selections and scrolling, with short pauses after meaningful results and no long idle holds.
- Do not simulate a successful identity check or feed a fake camera image into the original-access gate. The app records a viewer photo; it does not perform biometric identity verification.
- Do not claim network anonymity, end-to-end encryption, post-quantum TLS, FIPS certification, or independent proof of an incident. Similarity candidates are leads, not corroboration.
- Do not use destructive actions or delete existing application records. Case updates in this recording apply only to the fresh evaluation case.

## Completion and verification

The final MP4 exists and passed all 11 technical checks, including full decoding, dimensions, codec, frame rate and duration. No black segments were detected. All 41 automated workflow assertions passed, with no browser JavaScript or console errors. Independent visual review confirmed readable application content and the demonstrated sequence; stationary sections were intentional presentation pauses. Actual MP4 playback and seeking in installed Chrome passed at five positions across the file.

The recording used a fresh local evaluation vault. It did not exercise the production Supabase deployment, actual camera/microphone capture, or successful original-evidence access. The original-access gate was shown and left intact. No existing application records or the user-provided source video were altered.

See [demo_instructions.md](demo_instructions.md) for the exact repeat command, output metadata and verification artifact paths.
