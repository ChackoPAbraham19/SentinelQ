# Record the SentinelQ demonstration

This folder contains the recording workflow, separate from the application source. The demo uses Google Chrome, an isolated local SentinelQ instance, real UI interactions, and the actual user-supplied video upload. It must not modify the existing application vault or cloud database.

## Prerequisites

- Node.js 22.13 or newer and npm.
- Google Chrome installed locally.
- FFmpeg and FFprobe available on PATH, or explicit executable paths provided to the recording workflow.
- The application's locked backend and frontend dependencies installed.
- The user-supplied evidence file at `C:\Users\festi\Downloads\gemini_generated_video_84ae97c3.mp4`.

For a new checkout, install the application dependencies from the repository root:

```powershell
npm --prefix backend ci
npm --prefix frontend ci
```

Do not replace an existing `backend/.env` and do not regenerate keys for an existing vault. The recording workflow must skip application `.env` loading and create independent keys, credentials, and storage for its fresh local evaluation instance.

## Install the recording tools

From the repository root, install the separate demo package. It pins Playwright 1.64.0 and uses your installed Google Chrome; there is no need to download a second Chromium browser.

```powershell
npm --prefix demo_recording ci
$env:PLAYWRIGHT_SKIP_BROWSER_GC = '1'
npx --prefix demo_recording playwright install ffmpeg
```

The last command installs Playwright's capture helper. A system FFmpeg/FFprobe installation is still needed for the application's media processing and final MP4 conversion/inspection.

## Run the demonstration

Run these commands from the repository root. The first checks the complete automation with accelerated reading pauses and saves a rehearsal recording in its own run folder; the second produces the final presentation recording.

```powershell
node demo_recording/demo_script.cjs --rehearsal
node demo_recording/demo_script.cjs --pace 0.85
```

On Windows, `demo_recording\demo_script.cmd` is an executable wrapper for the same Node script and accepts the same options.

To choose another harmless evidence file, pace, or local port:

```powershell
node demo_recording/demo_script.cjs --video "C:\Users\festi\Downloads\gemini_generated_video_84ae97c3.mp4" --pace 1 --port 4178
```

`--video` takes an absolute path. Keep its size within SentinelQ's eight MiB aggregate attachment limit. The delivered video was recorded with `--pace 0.85`; omitting the option uses the script default of `1`. Larger values lengthen reading pauses and typing, while smaller values shorten them. The accepted range is greater than zero and at most three. `--port` chooses the local backend port; use a free port between 1024 and 65535. Chrome opens automatically and the script supplies all clicks, typing, scrolling and selections. No manual mouse or keyboard operation is needed.

Use `node demo_recording/demo_script.cjs --help` to display the options. The normal recording runs the video verifier with a duration window of 180–330 seconds, so extreme pace values can fail the presentation-length check even when the application interactions succeed.

Each run generates independent evaluation credentials and keys and uses a fresh vault under the demo's private `.runtime` area. It skips the application `.env`. Do not distribute `.runtime` files, which contain the run's private secrets and evaluation data.

The workflow is:

1. Verify Chrome, media executables, the evidence file, and application dependencies.
2. Build the existing frontend.
3. Start the backend with a separate evaluation data directory, local storage and a loopback-only port, serving the built frontend from the same origin.
4. Check the health/capabilities routes and load the actual application in Chrome.
5. Record a real report submission, recovery, messaging and authority review sequence.
6. Close the recording context to finalize Playwright's WebM capture, then encode H.264 MP4 with FFmpeg at CRF 18, `yuv420p`, and `+faststart` for broad playback compatibility.
7. Stop only services and browser contexts created by the recording workflow.

The normal application start commands remain `npm --prefix backend start` and `npm --prefix frontend start`. They are not a substitute for the isolated recording configuration: using a normal configured account/vault could expose private records on video.

## Output and privacy

The requested final deliverables are `application_demo.mp4`, executable automation source `demo_script.cjs` and its Windows wrapper `demo_script.cmd`, `demo_plan.md`, and this file. `presentation.css` styles only the recording aids; `verify_video.cjs` checks the completed video.

Each run keeps its WebM source, checkpoints, actual downloaded artifacts, timeline, API readiness snapshots and workflow assertions in `recordings/<timestamp>/`. Successful rehearsals create `rehearsal.mp4` there and do not publish `application_demo.mp4`. A successful full recording writes its MP4 and technical verification under its own run folder, then publishes the top-level `application_demo.mp4` and `latest-run.json`. If a previous final MP4 exists, it is preserved as `application_demo.previous-<timestamp>.mp4` before the new one is copied into place.

The evaluation case is explicitly fictional. Application receipt IDs, processing results, messages, status changes, assignment, notes and downloaded artifacts must come from real application operations. No API response should be mocked. The source evidence file must remain unchanged.

Do not publish runtime secrets, local vault files, debug traces containing response bodies, or session credentials with the portfolio MP4. Keep recovery/password fields concealed on screen. The recording itself may contain the evaluation Case ID and fictional report content.

## Customization and boundaries

Keep text concise enough to remain readable during the intended three-to-five-minute duration. For another project evaluation, change only the demo's narrative and harmless evidence input; leave the application's permission model intact. A slower machine may require longer readiness timeouts, but should not show a fabricated completed state while media processing is still pending.

Original evidence viewing needs a real camera, a fresh viewer-photo challenge, the signed-in account's personal key, a reference and a reason. The unattended demo may show that gate and cancel it. It must not bypass the gate or present a generated camera input as a real viewer. The baseline sequence does not prove physical camera/microphone operation or a live hosted Supabase deployment.

The script launches headed Google Chrome with a 1920 × 1080 content viewport and records that viewport at 30 FPS. Browser-content recording excludes desktop notifications, other windows, and Chrome's address bar. Scrolling is recorded as real page movement; this is not a sequence of stitched screenshots or a recording of the Codex built-in browser.

Short opening/closing cards, section labels and a visible cursor are demo-only presentation aids. They do not alter application functionality or invent successful results. If the recording includes an enlarged playback of a downloaded masked MP4, it is explicitly labeled Chrome playback of the actual downloaded review copy, not an additional SentinelQ preview feature. The video has no voiceover or soundtrack.

The script intercepts only its own `/__demo__/presentation.css` request to load the recording stylesheet. Application API responses are not mocked, and the app's Content Security Policy is not disabled. Recorder selector/pacing changes are separate from the application source.

## Check or troubleshoot a recording

The full run invokes the technical verifier before publishing the top-level MP4. It checks container/codec, 1920 × 1080 dimensions, 30 FPS, duration, complete decoding, black-frame signals and representative frames. It creates a contact sheet and a JSON report. Stationary-frame detections can be intentional reading pauses; inspect them rather than assuming every pause is a failure.

You can run the verifier independently from the repository root:

```powershell
node demo_recording/verify_video.cjs demo_recording/application_demo.mp4
```

It creates a new verification directory without overwriting previous output. For custom durations, pass `--min-duration` and `--max-duration` in seconds. Technical validation does not establish semantic coverage by itself; review the video/contact sheet against the saved `timeline.json` and `workflow-verification.json`.

If automation fails, the run folder retains `failure.png`, `failure-dom.txt` where available, and its verification log. The script exits nonzero and does not replace the top-level final recording. Correct the reported recorder/environment issue, then rerun against a fresh evaluation vault. A port-conflict failure should be handled with a free `--port`, not by terminating an unrelated service.

## Verification record

The final recording completed on **October 9, 2026**, using:

```powershell
node demo_recording/demo_script.cjs --pace 0.85
```

No temporal speedup was used in conversion. The only pacing adjustment was the automation's `0.85` multiplier for reading pauses and typing before/during capture.

| Item | Verified result |
| --- | --- |
| Final deliverable | [application_demo.mp4](application_demo.mp4) |
| Duration | 287.466016 seconds — approximately 4 minutes 47 seconds |
| Resolution and orientation | 1920 × 1080, landscape 16:9 |
| Encoding | H.264, `yuv420p`, 30 FPS, MP4 with fast-start metadata |
| File size | 19,724,481 bytes |
| SHA-256 | `4c582dc36538f5caa912fe89ce3c12bc4ff3eef81857371c9578e5883c46150d` — matches the run-folder MP4 |
| Audio | Silent; no voiceover or soundtrack |
| Application workflow | 41 assertions passed; no browser JavaScript or console errors |
| Technical video checks | All 11 checks passed, including complete decoding; no black segments detected |
| Independent visual review | Passed; demonstrated interactions readable, no major blank, stalled or cut-off section; stationary holds were intentional reading pauses |
| Playback verification | Actual installed-Chrome playback and seeking passed at 5%, 25%, 50%, 75% and 95% of the MP4 |

The successful run is `recordings/2026-10-09T02-15-23-403Z-recording`. Its evidence includes:

- [Workflow assertions](recordings/2026-10-09T02-15-23-403Z-recording/workflow-verification.json), [chapter/checkpoint timeline](recordings/2026-10-09T02-15-23-403Z-recording/timeline.json), and [output metadata](recordings/2026-10-09T02-15-23-403Z-recording/output-metadata.json).
- [Technical video report](recordings/2026-10-09T02-15-23-403Z-recording/quality-check/verification.json) and [contact sheet](recordings/2026-10-09T02-15-23-403Z-recording/quality-check/contact-sheet.jpg).
- [Chrome playback report](recordings/2026-10-09T02-15-23-403Z-recording/quality-check/chrome-playback.json).
- [Visual review](recordings/2026-10-09T02-15-23-403Z-recording/quality-check/visual-review.json), including readable opening and final-home frames sampled from the actual MP4 at 3 and 286 seconds.

The technical report deliberately labels semantic coverage separately: technical checks alone cannot establish that the app workflows succeeded. The independent visual review and recorded application assertions provide that additional evidence.

The demonstrated scope is the actual application with a fresh local evaluation vault, not the production Supabase deployment. The supplied MP4 was really uploaded, processed and downloaded; its source file was preserved. Original access remained blocked without the required personal key and fresh viewer photo; the camera gate was shown and cancelled, never bypassed. Physical camera/microphone capture and successful original viewing are outside this recording's verified scope. Existing application records were not used or changed.
