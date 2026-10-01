import React, { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import OriginalAccess, { ViewerAccount, AuditPhoto } from './ViewerAccess';
import EvidenceCapture from "./EvidenceCapture";
import { evidenceError as validateEvidence, evidenceFileBase64, MAX_EVIDENCE_BYTES } from "./capture.mjs";

const API =
  window.SENTINELQ_CONFIG?.apiBaseUrl ||
  (["localhost", "127.0.0.1"].includes(window.location.hostname)
    ? "http://127.0.0.1:4000"
    : window.location.origin);

function checkPrivacy(text) {
  const warnings = [];
  const t = (text || "").toLowerCase();
  if (/\bname is\b|\bmy name\b/.test(t))
    warnings.push("Mentions a personal name");
  if (/\b(manager|boss|supervisor|hr|team lead|director)\b/.test(t))
    warnings.push("Mentions a workplace role");
  if (/\b(email|phone|mobile|address|location|branch|office)\b/.test(t))
    warnings.push("Contains contact or location detail");
  if (/\b(i work in|i work at|i am in)\b/.test(t))
    warnings.push("Mentions workplace location");
  if (/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i.test(t))
    warnings.push("Contains an email address");
  if (/(?:\+?\d[\d\s().-]{7,}\d)/.test(t))
    warnings.push("Contains a possible phone number");
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(t))
    warnings.push("Contains an IP address");
  if (/\bhttps?:\/\/[^\s]+/i.test(t)) warnings.push("Contains a web address");
  if (
    /\b(?:employee|staff|student|account|case)\s*(?:id|number|no\.?)[\s:#-]*[a-z0-9-]{3,}\b/i.test(
      t,
    )
  )
    warnings.push("Contains a possible organization identifier");
  return warnings;
}

function StatusDot({ tone = "cyan", pulse = false }) {
  return (
    <span
      className={`status-dot ${tone} ${pulse ? "pulse" : ""}`}
      aria-hidden="true"
    />
  );
}

function NavIcon({ name }) {
  const paths = {
    report: "M12 5v14M5 12h14",
    track: "M8 3H5v18h14V3h-3M9 3h6v4H9zM8 12h8M8 16h5",
    dashboard: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    shield: "M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6",
    info: "M12 11v6M12 7v1M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
    upload: "M12 16V3M7 8l5-5 5 5M4 16v5h16v-5",
    home: "M3 11l9-8 9 8M5 10v11h5v-7h4v7h5V10",
    arrow: "M4 12h16M14 6l6 6-6 6",
    lock: "M6 10h12v11H6zM8 10V7a4 4 0 0 1 8 0v3M12 14v3",
  };
  return (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}

const GUIDE_STEPS = [
  { title: "Tell us what happened", short: "Describe your concern", icon: "report", heading: "Start with your own words.", text: "Give your report a short title, then explain what happened. Include the details a reviewer needs, at your own pace.", tip: "You don’t need an account. Leave out names or contact details that aren’t needed to understand the incident.", preview: "A short title and a clear description", note: "The privacy helper can flag some identifying details for you to review." },
  { title: "Add evidence, if you have it", short: "Attach supporting files", icon: "upload", heading: "A little context can help.", text: "You can attach documents, photos, video or audio. Evidence is optional, so you can still send a report without files.", tip: "Check the contents and filenames before uploading. A document or photo can reveal more about you than you intend.", preview: "Supporting files · optional", note: "Original files are encrypted and restricted. Some formats remain quarantined." },
  { title: "Save your case details", short: "Keep your recovery key", icon: "lock", heading: "Keep the way back to your case.", text: "After submission, you’ll receive a Case ID and a recovery key. Save both somewhere only you can access.", tip: "Your recovery key is shown after submission and cannot be reset. Anyone with both details can access your case.", preview: "Case ID + recovery key", note: "These details take the place of a reporter account and password." },
  { title: "Return for updates", short: "Follow your case", icon: "track", heading: "Stay part of the conversation.", text: "Use Track a case to see its status and any messages from the reviewing authority. You can also send a follow-up.", tip: "Keep your case details handy. You’ll need to return here to check for updates and reply to questions.", preview: "Case status and messages", note: "Submitting a report does not guarantee a particular outcome or response time." },
];

function GettingStarted({ onStart, onTrack }) {
  const [step, setStep] = useState(0);
  const guide = GUIDE_STEPS[step];
  return (
    <div className="welcome-page">
      <section className="welcome-intro">
        <div>
          <p className="section-eyebrow">SPEAK UP. STAY INFORMED.</p>
          <h1>A clear path to<br /><em>raising your concern.</em></h1>
          <p className="welcome-description">Taking the first step can feel difficult. Know what to expect, share what matters, and follow your report in one place.</p>
          <div className="welcome-actions">
            <button className="primary-action" onClick={onStart}>Start a report <NavIcon name="arrow" /></button>
            <button className="text-action" onClick={onTrack}>Already reported? Track your case <span aria-hidden="true">↗</span></button>
          </div>
          <p className="welcome-caption"><NavIcon name="shield" /> No reporter account required · Supporting files are optional</p>
        </div>
        <aside className="before-you-begin">
          <span className="note-label">BEFORE YOU BEGIN</span>
          <h2>Your information.<br /> Handled with care.</h2>
          <p>Reports and evidence are encrypted in storage. Access to case records is restricted.</p>
          <div className="honest-note"><NavIcon name="info" /><p>This is a reporting prototype. It does not hide your network activity or guarantee anonymity.</p></div>
          <a href="#privacy-and-help">Understand your privacy <span aria-hidden="true">↓</span></a>
        </aside>
      </section>

      <section className="process-section" aria-labelledby="process-heading">
        <div className="process-heading"><div><p className="section-eyebrow">A FEW SIMPLE STEPS</p><h2 id="process-heading">Here’s how it works</h2></div><span>Explore each step before you start</span></div>
        <div className="process-guide">
          <ol className="process-steps" aria-label="Reporting process">
            {GUIDE_STEPS.map((item, index) => <li key={item.title}><button className={step === index ? "process-step active" : "process-step"} aria-current={step === index ? "step" : undefined} aria-controls="guide-detail" onClick={() => setStep(index)}><span className="step-number">{String(index + 1).padStart(2, "0")}</span><span><strong>{item.title}</strong><small>{item.short}</small></span><span className="step-arrow" aria-hidden="true">→</span></button></li>)}
          </ol>
          <div className="guide-detail" id="guide-detail">
            <div className="guide-copy" aria-live="polite" aria-atomic="true">
              <div className="guide-topline"><span className="guide-icon"><NavIcon name={guide.icon} /></span><span>STEP {step + 1} OF 4</span></div>
              <h3>{guide.heading}</h3><p>{guide.text}</p>
              <div className="guide-preview"><NavIcon name={guide.icon} /><span>{guide.preview}</span></div>
              <div className="guide-tip"><span className="tip-label">A helpful reminder</span><p>{guide.tip}</p></div>
              <p className="guide-note">{guide.note}</p>
            </div>
            <div className="guide-controls"><button className="text-action" disabled={step === 0} onClick={() => setStep(step - 1)}>← Back</button><span className="guide-dots" aria-hidden="true">{GUIDE_STEPS.map((_, index) => <i key={index} className={index === step ? "active" : ""} />)}</span>{step < 3 ? <button className="guide-next" onClick={() => setStep(step + 1)}>Next step <span aria-hidden="true">→</span></button> : <button className="primary-action" onClick={onStart}>Start my report <span aria-hidden="true">→</span></button>}</div>
          </div>
        </div>
      </section>
      <section className="help-section" id="privacy-and-help" aria-labelledby="help-heading">
        <div><p className="section-eyebrow">GOOD TO KNOW</p><h2 id="help-heading">A little clarity<br /> before you share.</h2><p>You decide when you’re ready to begin.</p></div>
        <div className="help-questions">
          <details><summary>Do I need to share my identity?</summary><p>No reporter account is required. Avoid unnecessary identifying details in your title, description and files. The privacy helper is advisory; it cannot guarantee anonymity.</p></details>
          <details><summary>Who can view my report and evidence?</summary><p>Case access is restricted to authorized reviewers. Original evidence requires an authorized court or admin account, that viewer’s personal key, and a recorded camera photo. Sensitive case details use a separate judicial access key. Messages are encrypted in storage, not end to end.</p></details>
          <details><summary>What if I need to leave quickly?</summary><p>Quick exit clears the current workspace and opens a blank page or the configured exit page. It does not erase browser history, downloaded files or network records. An unsent report will be lost.</p></details>
          <details><summary>How do I get back to my report?</summary><p>Choose Track a case and enter your Case ID and recovery key. Save both after submitting; a lost recovery key cannot be reset. You must return to the portal to check for messages.</p></details>
        </div>
      </section>
    </div>
  );
}

function SectionLabel({ eyebrow, title, detail }) {
  return (
    <div className="section-heading">
      <div>
        <p className="section-eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
      </div>
      {detail && <span className="section-detail">{detail}</span>}
    </div>
  );
}

function VerificationMatrix({ verification }) {
  if (!verification)
    return (
      <section className="surface-panel empty-panel">
        <span className="panel-kicker">CASE VERIFICATION MATRIX</span>
        <p>Signals will appear when an authenticated case is selected.</p>
      </section>
    );
  return (
    <section className="surface-panel verification-matrix">
      <div className="panel-kicker">
        <span>CASE VERIFICATION MATRIX</span>
        <span className="mono">{verification.score} / 100</span>
      </div>
      <div className="matrix-level">
        <strong>{verification.level}</strong>
        <StatusDot
          tone={verification.integrity === "VERIFIED" ? "green" : "amber"}
        />
      </div>
      <div className="matrix-signals">
        {verification.signals.map((signal) => (
          <div className="matrix-row" key={signal.name}>
            <div>
              <span>{signal.name}</span>
              <strong>{signal.value}</strong>
            </div>
            <div className="matrix-track">
              <i
                style={{
                  width: `${Math.min(100, Math.max(12, Math.abs(signal.weight) * 4))}%`,
                }}
              />
            </div>
            <small>{signal.detail}</small>
          </div>
        ))}
      </div>
      {verification.warnings?.map((warning) => (
        <p className="inline-warning" key={warning}>
          {warning}
        </p>
      ))}
      <p className="disclaimer">{verification.disclaimer}</p>
    </section>
  );
}

function CorrelationGraph({ verification, selectedCase }) {
  const related = verification?.relatedCases || [];
  return (
    <section className="surface-panel correlation-panel">
      <div className="panel-kicker">
        <span>CORRELATION NETWORK</span>
        <span className="mono">{related.length} LINK(S)</span>
      </div>
      <div className="correlation-graph">
        <svg viewBox="0 0 360 150" aria-label="Logical case correlation graph">
          <path d="M180 75 L80 35 M180 75 L275 35 M180 75 L275 120" />
          {related.slice(0, 3).map((item, index) => (
            <g key={item.id}>
              <circle
                className="graph-node related"
                cx={[80, 275, 275][index]}
                cy={[35, 35, 120][index]}
                r="18"
              />
              <text x={[80, 275, 275][index]} y={[35, 35, 120][index]}>
                {item.id.replace("CASE-", "SQ-").slice(0, 8)}
              </text>
            </g>
          ))}
          <circle className="graph-node main" cx="180" cy="75" r="25" />
          <text x="180" y="75">
            {selectedCase
              ? selectedCase.id.replace("CASE-", "SQ-").slice(0, 8)
              : "CASE"}
          </text>
        </svg>
        {related.length === 0 && (
          <p className="empty-graph">
            No related reports identified. Similarity is reviewed, never treated
            as proof.
          </p>
        )}
      </div>
    </section>
  );
}

function CaseTracker({ onPanicExit }) {
  const [caseId, setCaseId] = useState("");
  const [recoverySecret, setRecoverySecret] = useState("");
  const [trackedCase, setTrackedCase] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);

  const trackCase = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await axios.post(`${API}/track`, {
        caseId: caseId.trim(),
        recoverySecret: recoverySecret.trim(),
      });
      setTrackedCase(response.data.case);
    } catch (requestError) {
      setTrackedCase(null);
      setError(
        requestError.response?.data?.error ||
          "Could not open this case. Check the Case ID and recovery key.",
      );
    } finally {
      setLoading(false);
    }
  };

  const sendReply = async (event) => {
    event.preventDefault();
    if (!message.trim() || !trackedCase) return;
    setSending(true);
    setError("");
    try {
      const response = await axios.post(
        `${API}/cases/${encodeURIComponent(trackedCase.id)}/messages`,
        {
          text: message.trim(),
          sender: "reporter",
          recoverySecret: recoverySecret.trim(),
        },
      );
      setTrackedCase({
        ...trackedCase,
        messages: response.data.messages || [],
      });
      setMessage("");
    } catch (requestError) {
      setError(
        requestError.response?.data?.error || "Message could not be sent.",
      );
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="tracker-layout">
      <div className="workspace-heading">
        <SectionLabel
          eyebrow="REPORTER CASE PORTAL"
          title="Track your case"
          detail="Check progress, read updates and continue the conversation."
        />
        <button className="panic-link" onClick={onPanicExit}>
          Quick exit
        </button>
      </div>
      <section className="surface-panel tracker-panel">
        <div className="panel-kicker">
          <span>CASE ACCESS</span>
          <span className="mono">NO ACCOUNT REQUIRED</span>
        </div>
        <p className="muted">
          Use the Case ID and recovery key shown once after
          submission. SentinelQ cannot reset a lost key.
        </p>
        <form onSubmit={trackCase} className="report-form tracker-form">
          <label>
            Case ID
            <input
              value={caseId}
              onChange={(event) => setCaseId(event.target.value)}
              placeholder="CASE-..."
              required
            />
          </label>
          <label>
            Recovery key
            <input
              value={recoverySecret}
              onChange={(event) => setRecoverySecret(event.target.value)}
              autoComplete="off"
              required
            />
          </label>
          {error && <p className="inline-warning" role="alert">{error}</p>}
          <button className="primary-action" type="submit" disabled={loading}>
            {loading ? "Opening case..." : "Open case"} <span>→</span>
          </button>
        </form>
      </section>
      {trackedCase && (
        <section className="surface-panel tracker-panel case-portal-result">
          <div className="panel-kicker">
            <span>{trackedCase.id}</span>
            <strong>{trackedCase.status}</strong>
          </div>
          <h3>{trackedCase.title || "Untitled case"}</h3>
          <p>{trackedCase.description}</p>
          <div className="tracker-meta">
            <span>
              Category: <strong>{trackedCase.category}</strong>
            </span>
            <span>
              Priority: <strong>{trackedCase.priority}</strong>
            </span>
            <span>
              Evidence:{" "}
              <strong>{trackedCase.files?.length || 0} item(s)</strong>
            </span>
          </div>
          <div className="tracker-timeline">
            {(trackedCase.timeline || []).map((item) => (
              <div className="timeline-row" key={`${item.at}-${item.label}`}>
                <StatusDot tone="cyan" />
                <div>
                  <strong>{item.label}</strong>
                  <small>
                    {item.at ? new Date(item.at).toLocaleString() : ""}
                  </small>
                </div>
              </div>
            ))}
          </div>
          <div className="tracker-messages">
            <div className="panel-kicker">
              <span>CASE MESSAGES</span>
              <span className="mono">ENCRYPTED AT REST</span>
            </div>
            {(trackedCase.messages || []).map((item) => (
              <div
                className={`chat-message ${item.sender === "reporter" ? "reporter" : ""}`}
                key={item.id}
              >
                <small>{item.sender}</small>
                <p>{item.text}</p>
              </div>
            ))}
            {!(trackedCase.messages || []).length && (
              <p className="muted">No messages yet.</p>
            )}
          </div>
          <form onSubmit={sendReply} className="chat-form">
            <input
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              aria-label="Message to the reviewing authority"
              placeholder="Write a follow-up message"
              required
            />
            <button className="primary-action" type="submit" disabled={sending}>
              {sending ? "Sending..." : "Send"}
            </button>
          </form>
        </section>
      )}
    </div>
  );
}

export default function App() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [anonymizedDescription, setAnonymizedDescription] = useState("");
  const [files, setFiles] = useState([]);
  const [captureBusy, setCaptureBusy] = useState(false);
  const [attachmentError, setAttachmentError] = useState("");
  const [result, setResult] = useState(null);
  const [activeView, setActiveView] = useState("welcome");
  const workspaceRef = useRef(null);
  const previousView = useRef("welcome");
  const [cases, setCases] = useState([]);
  const [caseSearch, setCaseSearch] = useState("");
  const [selectedCase, setSelectedCase] = useState(null);
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseError, setCaseError] = useState("");
  const [panicExit, setPanicExit] = useState(false);
  const [privacyWarnings, setPrivacyWarnings] = useState([]);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatSending, setChatSending] = useState(false);
  const [isAnonymizing, setIsAnonymizing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [acceptedAnonymized, setAcceptedAnonymized] = useState(false);
  const [verification, setVerification] = useState(null);
  const [authority, setAuthority] = useState(null);
  const [loginForm, setLoginForm] = useState({
    username: "",
    password: "",
  });
  const [loginError, setLoginError] = useState("");
  const [auditEvents, setAuditEvents] = useState([]);
  const [originalAccessFile, setOriginalAccessFile] = useState(null);
  const [judicialKey, setJudicialKey] = useState("");
  const [accessReason, setAccessReason] = useState("");
  const [evidenceError, setEvidenceError] = useState("");
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [detailsFormOpen, setDetailsFormOpen] = useState(false);
  const [judicialDetails, setJudicialDetails] = useState(null);
  const [detailsError, setDetailsError] = useState("");

  useEffect(() => {
    const titles = { welcome: "Getting started", report: "Submit a report", track: "Track a case", dashboard: "Authority access" };
    document.title = `${titles[activeView]} | SentinelQ`;
    if (previousView.current !== activeView) {
      workspaceRef.current?.focus({ preventScroll: true });
      window.scrollTo({ top: 0, behavior: "instant" });
      previousView.current = activeView;
    }
  }, [activeView]);

  useEffect(() => {
    if (result?.recoverySecret || result?.error) {
      document.getElementById("report-result")?.focus();
    }
  }, [result]);

  useEffect(() => {
    if (authority?.token)
      axios.defaults.headers.common.Authorization = `Bearer ${authority.token}`;
    else delete axios.defaults.headers.common.Authorization;
  }, [authority]);

  useEffect(() => {
    setPrivacyWarnings(checkPrivacy(description));
  }, [description]);

  const anonymize = async () => {
    if (!description.trim()) return;
    setIsAnonymizing(true);
    try {
      const res = await axios.post(`${API}/anonymize`, { text: description });
      setAnonymizedDescription(res.data.anonymizedText || "");
      setAcceptedAnonymized(false);
      setResult({ suggestion: res.data.anonymizedText });
    } catch (err) {
      setResult({ error: err.message });
    } finally {
      setIsAnonymizing(false);
    }
  };

  const addEvidence = incoming => {
    const combined = [...files, ...incoming];
    const error = validateEvidence(combined);
    setAttachmentError(error);
    if (error) return false;
    setFiles(combined);
    return true;
  };

  const submit = async (e) => {
    e.preventDefault();
    if (submitting || captureBusy) return;
    const error = validateEvidence(files);
    if (error) { setAttachmentError(error); return; }
    setSubmitting(true);
    try {
      const toSend = {
        title,
        description: acceptedAnonymized ? anonymizedDescription : description,
        anonymizedDescription: acceptedAnonymized ? anonymizedDescription : "",
        files: [],
      };
      for (const file of files) {
        const b64 = await evidenceFileBase64(file);
        toSend.files.push({ name: file.name, data: b64 });
      }
      const res = await axios.post(`${API}/report-base64`, toSend);
      setResult({ ...res.data, flow: "Report submitted" });
      setAcceptedAnonymized(false);
      setAnonymizedDescription("");
    } catch (err) {
      setResult({ error: err.response?.data?.error || err.message });
    } finally {
      setSubmitting(false);
    }
  };

  const loadCases = async () => {
    if (!authority?.token) return;
    setCaseLoading(true);
    setCaseError("");
    try {
      const res = await axios.get(`${API}/cases`);
      const nextCases = res.data.cases || [];
      setCases(nextCases);
      if (!selectedCase && nextCases.length > 0) {
        setSelectedCase(nextCases[0]);
      }
    } catch (err) {
      setCaseError(err.message);
    } finally {
      setCaseLoading(false);
    }
  };

  const login = async (e) => {
    e.preventDefault();
    setLoginError("");
    try {
      const res = await axios.post(`${API}/auth/login`, loginForm);
      const session = { token: res.data.token, user: res.data.user };
      setAuthority(session);
      setActiveView("dashboard");
    } catch (error) {
      setLoginError(error.response?.data?.error || "Authority login failed");
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${API}/auth/logout`);
    } catch (error) {
      /* local session still clears */
    }
    setAuthority(null);
    setJudicialKey("");
    setAccessReason("");
    setOriginalAccessFile(null);
    setDetailsFormOpen(false);
    setJudicialDetails(null);
    setCases([]);
    setSelectedCase(null);
    setActiveView("report");
  };

  const downloadEvidence = async (file, grant = null) => {
    if (!selectedCase?.id) return;
    const original = Boolean(grant);
    const url = `${API}/cases/${encodeURIComponent(selectedCase.id)}/evidence/${encodeURIComponent(file.name)}${original ? "?original=1" : ""}`;
    const response = await axios.get(url, {
      responseType: "blob",
      headers: original ? { "X-Original-Grant": grant } : {},
    });
    const blobUrl = URL.createObjectURL(response.data);
    const link = document.createElement("a");
    link.href = blobUrl;
    const disposition = response.headers["content-disposition"] || "";
    const serverName = disposition.match(/filename="([^"]+)"/)?.[1];
    const maskedExtension = file.derivativeMime === "video/mp4" ? ".mp4" : file.derivativeMime === "audio/wav" ? ".wav" : file.derivativeMime === "image/png" ? ".png" : file.derivativeMime === "text/plain" ? ".txt" : "";
    link.download = serverName || (original ? `original-${selectedCase.id}-${file.name}` : `masked-${selectedCase.id}-${file.name}${maskedExtension}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  };

  const unlockJudicialDetails = async (event) => {
    event.preventDefault();
    if (!selectedCase?.id) return;
    setDetailsError("");
    setEvidenceBusy(true);
    try {
      const response = await axios.post(`${API}/cases/${encodeURIComponent(selectedCase.id)}/judicial-details`, { key: judicialKey, reason: accessReason });
      setJudicialDetails(response.data.details);
      setDetailsFormOpen(false);
      setAccessReason("");
      loadAudit();
    } catch (error) {
      setDetailsError(error.response?.data?.error || "Judicial details unavailable");
    } finally {
      setJudicialKey("");
      setEvidenceBusy(false);
    }
  };

  const reprocessEvidence = async (file, grant) => {
    if (!selectedCase?.id) return;
    setEvidenceError("");
    setEvidenceBusy(true);
    try {
      const response = await axios.post(`${API}/cases/${encodeURIComponent(selectedCase.id)}/evidence/${encodeURIComponent(file.name)}/reprocess`, {}, { headers: { "X-Original-Grant": grant } });
      setSelectedCase(response.data.case);
      setCases(previous => previous.map(item => item.id === response.data.case.id ? response.data.case : item));
      loadAudit();
    } catch (error) {
      setEvidenceError(error.response?.data?.error || "Media processing failed");
    } finally {
      setEvidenceBusy(false);
    }
  };

  const loadAudit = async () => {
    if (!authority?.token) return;
    try {
      const res = await axios.get(`${API}/audit`);
      setAuditEvents(res.data.events || []);
    } catch (error) {
      setAuditEvents([]);
    }
  };

  const loadMessages = async (caseId) => {
    if (!caseId) return;
    try {
      const res = await axios.get(
        `${API}/cases/${encodeURIComponent(caseId)}/messages`,
      );
      setChatMessages(res.data.messages || []);
    } catch (err) {
      setChatMessages([]);
    }
  };

  useEffect(() => {
    if (activeView === "dashboard" && authority?.token) {
      loadCases();
      loadAudit();
    }
  }, [activeView, authority?.token]);

  useEffect(() => {
    if (activeView === "dashboard" && selectedCase?.id) {
      loadMessages(selectedCase.id);
      axios
        .get(`${API}/cases/${encodeURIComponent(selectedCase.id)}/verification`)
        .then((res) => setVerification(res.data.verification || null))
        .catch(() => setVerification(null));
    }
  }, [activeView, selectedCase?.id]);

  useEffect(() => {
    setOriginalAccessFile(null);
    setJudicialKey("");
    setAccessReason("");
    setEvidenceError("");
    setDetailsFormOpen(false);
    setJudicialDetails(null);
    setDetailsError("");
  }, [selectedCase?.id]);

  useEffect(() => {
    if (!judicialDetails) return;
    const timer = setTimeout(() => setJudicialDetails(null), 60000);
    return () => clearTimeout(timer);
  }, [judicialDetails]);

  const filteredCases = useMemo(() => {
    const q = caseSearch.trim().toLowerCase();
    if (!q) return cases;
    return cases.filter((item) => {
      return [
        item.id,
        item.title,
        item.description,
        item.category,
        item.priority,
        item.status,
      ]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [cases, caseSearch]);

  const updateCase = async (caseId, status, priority) => {
    try {
      const res = await axios.post(
        `${API}/cases/${encodeURIComponent(caseId)}/status`,
        { status, priority },
      );
      const updatedCase = res.data.case;
      setCases((prev) =>
        prev.map((item) => (item.id === updatedCase.id ? updatedCase : item)),
      );
      setSelectedCase(updatedCase);
      setResult({
        updatedCase: updatedCase.id,
        status: updatedCase.status,
        priority: updatedCase.priority,
      });
    } catch (err) {
      setResult({ error: err.message });
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!selectedCase || !chatInput.trim()) return;
    setChatSending(true);
    try {
      const res = await axios.post(
        `${API}/cases/${encodeURIComponent(selectedCase.id)}/messages`,
        { text: chatInput.trim(), sender: "authority" },
      );
      setChatMessages(res.data.messages || []);
      setChatInput("");
    } catch (err) {
      setResult({ error: err.message });
    } finally {
      setChatSending(false);
    }
  };

  const exportSummary = async () => {
    if (!selectedCase?.id) return;
    try {
      const res = await axios.get(
        `${API}/cases/${encodeURIComponent(selectedCase.id)}/summary`,
      );
      setResult({ exportedSummary: res.data.summary });
    } catch (err) {
      setResult({ error: err.message });
    }
  };

  const progressSteps = [
    { title: "Complaint filed", completed: Boolean(title && description) },
    {
      title: "Identity protected",
      completed: Boolean(acceptedAnonymized || anonymizedDescription),
    },
    { title: "Evidence secured", completed: files.length > 0 },
    {
      title: "Authority review",
      completed: Boolean(selectedCase || result?.flow),
    },
  ];

  const caseTimeline = selectedCase
    ? [
        {
          label: "Complaint received",
          detail: `Case ${selectedCase.id} opened and logged.`,
        },
        {
          label: "Privacy review",
          detail: "AI Privacy Guardian evaluated the original report text.",
        },
        {
          label: "Evidence vault",
          detail: `${selectedCase.files?.length || 0} evidence item(s) protected and hashed.`,
        },
        {
          label: selectedCase.status,
          detail: `Authority status set to ${selectedCase.status}.`,
        },
      ]
    : [];

  const liveFeed = [
    {
      label: "New complaint received",
      detail: "An incident was safely submitted and anonymized.",
    },
    {
      label: "Evidence secured",
      detail: "Metadata stripped and encrypted evidence stored in the vault.",
    },
    {
      label: "Case updated",
      detail: "Authority review status advanced to In Review.",
    },
  ];

  const triggerPanicExit = () => {
    const token = authority?.token;
    if (token)
      fetch(`${API}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        keepalive: true,
      }).catch(() => {});
    setTitle("");
    setDescription("");
    setAnonymizedDescription("");
    setFiles([]);
    setResult(null);
    setCaseSearch("");
    setSelectedCase(null);
    setCases([]);
    setChatMessages([]);
    setChatInput("");
    setAuthority(null);
    setJudicialKey("");
    setAccessReason("");
    setOriginalAccessFile(null);
    setDetailsFormOpen(false);
    setJudicialDetails(null);
    setAcceptedAnonymized(false);
    setPanicExit(true);
    sessionStorage.clear();
    window.history.replaceState(null, "", "/");
    window.location.replace(
      window.SENTINELQ_CONFIG?.safeExitUrl || "about:blank",
    );
  };

  if (panicExit) {
    return (
      <div className="app panic-screen">
        <div className="panel panic-card">
          <p className="eyebrow">SentinelQ</p>
          <h1>Safe exit activated</h1>
          <p>
            Session contents were cleared from the UI. You can safely close this
            window.
          </p>
        </div>
      </div>
    );
  }

  const metrics = [
    {
      label: "Active cases",
      value: cases.filter((item) => item.status !== "Closed").length,
      tone: "cyan",
    },
    {
      label: "Integrity alerts",
      value: cases.filter((item) =>
        item.files?.some((file) => file.processingStatus === "FAILED" || file.processingStatus === "NEEDS_MASKING"),
      ).length,
      tone: "amber",
    },
    {
      label: "Review queue",
      value: cases.filter(
        (item) => item.status === "Open" || item.status === "In Review",
      ).length,
      tone: "green",
    },
  ];

  return (
    <div className="app-shell">
      <a className="skip-link" href="#workspace">Skip to workspace</a>
      <div className="service-strip"><div><span>Independent incident reporting</span><span className="prototype-label">Prototype · Not a government service</span></div></div>
      <header className="system-bar">
        <button className="brand-mark" onClick={() => setActiveView("welcome")} aria-label="SentinelQ home">
          <span className="brand-symbol"><NavIcon name="shield" /></span>
          <span>
            <strong>SentinelQ</strong>
            <small>Every concern deserves to be heard</small>
          </span>
        </button>
        <div className="header-spacer" />
        <div className="system-user">
          {authority ? (
            <>
              <span>{authority.user.role}</span>
              <b>{authority.user.username}</b>
            </>
          ) : (
            <><span className="session-avatar"><NavIcon name="lock" /></span><span>No account required<small>Access your case with a recovery key</small></span></>
          )}
        </div>
        <button className="panic-link" onClick={triggerPanicExit} title="Clears this workspace and leaves the page. Browser history is not erased.">Quick exit <span aria-hidden="true">↗</span></button>
      </header>
      <div className="workspace-shell">
        <nav className="sidebar" aria-label="Main navigation">
          <div className="sidebar-section">
            <button className={activeView === "welcome" ? "nav-item selected" : "nav-item"} onClick={() => setActiveView("welcome")} aria-current={activeView === "welcome" ? "page" : undefined}><NavIcon name="home" /><span>Getting started</span></button>
            <button
              className={
                activeView === "report" ? "nav-item selected" : "nav-item"
              }
              onClick={() => setActiveView("report")}
              aria-current={activeView === "report" ? "page" : undefined}
            >
              <NavIcon name="report" />
              <span>Submit report</span>
            </button>
            <button
              className={
                activeView === "track" ? "nav-item selected" : "nav-item"
              }
              onClick={() => setActiveView("track")}
              aria-current={activeView === "track" ? "page" : undefined}
            >
              <NavIcon name="track" />
              <span>Track a case</span>
            </button>
          </div>
          <div className="sidebar-section authority-nav">
            <button
              className={
                activeView === "dashboard" ? "nav-item selected" : "nav-item"
              }
              onClick={() => {
                setActiveView("dashboard");
              }}
              aria-current={activeView === "dashboard" ? "page" : undefined}
            >
              <NavIcon name="dashboard" />
              <span>{authority ? "Case operations" : "Authority sign in"}</span>
            </button>
          </div>
          {authority && <div className="sidebar-footer">
              <button className="logout-link" onClick={logout}>
                Sign out
              </button>
          </div>}
        </nav>
        <main ref={workspaceRef} className="main-workspace" id="workspace" tabIndex={-1}>
          {activeView === "welcome" && <GettingStarted onStart={() => setActiveView("report")} onTrack={() => setActiveView("track")} />}
          {activeView === "track" && (
            <CaseTracker onPanicExit={triggerPanicExit} />
          )}
          {activeView === "report" && (
            <>
              <div className="workspace-heading">
                <SectionLabel
                  eyebrow="REPORT A CONCERN"
                  title="Tell us what happened."
                  detail="Take your time. Give the reviewer the details they need, and share only what is necessary."
                />
                <button className="text-action" onClick={() => setActiveView("welcome")}><NavIcon name="info" /> How it works</button>
              </div>
              <div className="report-layout"><div className="report-main">
              <nav className="intake-steps" aria-label="Report sections"><a href="#report-details"><b>1</b> Incident details</a><a href="#report-evidence"><b>2</b> Evidence <small>Optional</small></a><a href="#report-submit"><b>3</b> Submit report</a></nav>
              <div className="intake-grid">
                <section id="report-details" tabIndex={-1} className="intake-panel surface-panel">
                  <div className="panel-kicker">
                    <span>01 / INCIDENT DETAILS</span>
                    <span className="mono">REQUIRED</span>
                  </div>
                  <h2 className="panel-title">Describe your concern</h2>
                  <p className="panel-description">Share enough detail to help a reviewer understand the incident.</p>
                  <form id="incident-report" onSubmit={submit} className="report-form">
                    <label>
                      Case title <span className="required-label">Required</span>
                      <input
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        placeholder="A short summary of the concern"
                        required
                      />
                    </label>
                    <label>
                        Incident description <span className="required-label">Required</span>
                      <textarea
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        placeholder="Describe what happened, when, and where. Avoid details that identify you unless investigators need them."
                        required
                      />
                    </label>
                    <div className="field-hint"><span>Include what, when, and where. Avoid unnecessary personal details.</span><span>{description.length.toLocaleString()} characters</span></div>
                    {privacyWarnings.length > 0 && (
                      <div className="privacy-analysis">
                        <div className="analysis-head">
                          <span>ADVISORY PRIVACY CHECK</span>
                          <strong>REVIEW NEEDED</strong>
                        </div>
                        <p>
                          Pattern matching found possible identifying details.
                          It cannot guarantee anonymity.
                        </p>
                        <div className="analysis-signals">
                          {privacyWarnings.map((item) => (
                            <span key={item}>
                              <StatusDot tone="amber" />
                              {item}
                            </span>
                          ))}
                        </div>
                        <div className="actions-row">
                          <button
                            type="button"
                            onClick={anonymize}
                            disabled={isAnonymizing}
                          >
                            {isAnonymizing
                              ? "Scanning..."
                              : "Generate safer version"}
                          </button>
                          <button
                            type="button"
                            onClick={() => setPrivacyWarnings([])}
                          >
                            Keep original
                          </button>
                        </div>
                      </div>
                    )}
                    {anonymizedDescription && (
                      <div className="anonymized-box">
                        <div className="panel-kicker">
                          <span>SUGGESTED SAFER VERSION</span>
                          <span className="mono">MANUAL REVIEW REQUIRED</span>
                        </div>
                        <textarea
                          aria-label="Suggested safer version"
                          value={anonymizedDescription}
                          onChange={(e) =>
                            setAnonymizedDescription(e.target.value)
                          }
                        />
                        <p className="redaction-state" role="status">{acceptedAnonymized ? "The edited version will be submitted." : "Your original description will be submitted until you apply this version."}</p>
                        <div className="actions-row">
                          <button
                            type="button"
                            onClick={() => setAcceptedAnonymized(true)}
                          >
                            Apply redaction
                          </button>
                          <button
                            type="button"
                            onClick={() => setAcceptedAnonymized(false)}
                          >
                            Keep original
                          </button>
                        </div>
                      </div>
                    )}
                    <div className="form-actions">
                      <a className="next-step-link" href="#report-evidence">Continue to evidence <span aria-hidden="true">↓</span></a>
                    </div>
                  </form>
                </section>
                <section id="report-evidence" tabIndex={-1} className="evidence-upload surface-panel">
                  <div className="panel-kicker">
                    <span>02 / SUPPORTING EVIDENCE</span>
                    <span className="mono">OPTIONAL</span>
                  </div>
                  <h2 className="panel-title">Add supporting evidence.</h2>
                  <EvidenceCapture onAdd={addEvidence} onBusy={setCaptureBusy} disabled={submitting || files.length >= 5} remainingBytes={MAX_EVIDENCE_BYTES - files.reduce((sum, file) => sum + file.size, 0)} />
                  <label className="drop-zone">
                    <span className="drop-icon"><NavIcon name="upload" /></span>
                    <strong>Browse evidence files <span aria-hidden="true">↗</span></strong>
                    <small>
                      JPEG / PNG / TXT / VIDEO / AUDIO · PDF QUARANTINED · FIVE FILES / 8 MiB TOTAL
                    </small>
                    <input
                      type="file"
                      accept="image/jpeg,image/png,video/mp4,video/webm,audio/webm,audio/wav,audio/mpeg,audio/mp4,audio/ogg,.weba,.pdf,.txt"
                      multiple
                      disabled={submitting || captureBusy}
                      onChange={(e) => { addEvidence(Array.from(e.target.files)); e.target.value = ""; }}
                    />
                  </label>
                  {attachmentError && <p className="inline-warning" role="alert">{attachmentError}</p>}
                  {files.length > 0 && (
                    <div className="file-pipeline">
                      {Array.from(files).map((file, index) => (
                        <div className="upload-file" key={`${file.name}-${index}`}>
                          <div>
                            <strong>{file.name}</strong>
                            <small>
                              {file.type || "application/octet-stream"} ·{" "}
                              {Math.round(file.size / 1024)} KB
                            </small>
                          </div>
                          <button type="button" className="text-action" disabled={submitting} aria-label={`Remove ${file.name}`} onClick={() => { setFiles(current => Array.from(current).filter((_, fileIndex) => fileIndex !== index)); setAttachmentError(""); }}>Remove</button>
                        </div>
                      ))}
                      {Array.from(files)
                        .filter(
                          (file) =>
                            file.type.startsWith("image/") ||
                            file.type.startsWith("video/") ||
                            file.type.startsWith("audio/") ||
                            file.type === "application/pdf",
                        )
                        .map((file) => (
                          <p className="video-note" key={`${file.name}-note`}>
                            {file.type === "application/pdf"
                              ? "PDF evidence stays quarantined with no review copy. Its encrypted original requires judicial access."
                              : "Images and video are blurred across the whole frame, including faces. Audio uses an altered voice. Spoken names and identifying details remain audible; avoid including them. Originals are encrypted in storage. Authorized court or admin viewers must enter their personal key and record a photo before access."}
                          </p>
                        ))}
                    </div>
                  )}
                  <div id="report-submit" tabIndex={-1} className="submission-actions"><p>Ready to send your report?<small>{captureBusy ? "Use or discard your capture before submitting." : "Review your details above before submitting."}</small></p><button className="primary-action" type="submit" form="incident-report" disabled={submitting || captureBusy}>{submitting ? "Submitting..." : "Submit report"}<span aria-hidden="true">→</span></button></div>
                  <p className="form-footnote"><NavIcon name="shield" />Save the recovery key shown after submission. You will need it to return to your case; it cannot be reset.</p>
                </section>
                {result && (
                  <div id="report-result" tabIndex={-1} className="submission-result surface-panel" role="status" aria-live="polite">
                    <>
                      <div className="panel-kicker">
                        <span>REPORT UPDATE</span>
                        <StatusDot tone={result.error ? "amber" : "green"} />
                      </div>
                      <strong className={`result-title ${result.error ? "inline-warning" : ""}`}>
                        {result.error ? "Request could not be completed" : result.flow || "Response received"}
                      </strong>
                      {result.error ? <p className="response-error">{result.error}</p> : result.recoverySecret ? <div className="report-receipt"><p>Your report has been received. Keep both details below in a safe place.</p><dl><dt>Case ID</dt><dd>{result.id}</dd><dt>Recovery key</dt><dd>{result.recoverySecret}</dd></dl><p className="disclaimer">{result.warning || "This key cannot be recovered if lost."}</p></div> : result.suggestion ? <p>Review the suggested version in the incident details before applying it.</p> : <p>Your request was completed.</p>}
                    </>
                  </div>
                )}
              </div>
              </div><aside className="report-guidance"><div className="guidance-heading"><NavIcon name="shield" /><h2>Before you share</h2></div><p>You don’t need to include your name or contact information to submit a report.</p><div className="guide-tip"><span className="tip-label">A helpful reminder</span><p>Focus on what happened. Avoid details that identify you unless they are needed to understand the concern.</p></div><h3>What happens next?</h3><ol><li>Submit your report.</li><li>Save your Case ID and recovery key.</li><li>Return to check for updates and messages.</li></ol><div className="guidance-note"><NavIcon name="lock" /><p>Your report is encrypted in storage. This service does not hide your network activity.</p></div><p className="draft-note">Your unsent report stays in this tab. Refreshing or using Quick exit will clear it.</p></aside></div>
            </>
          )}
          {activeView === "dashboard" && (
            <>
              {!authority ? (
                <form className="login-panel surface-panel" onSubmit={login}>
                  <SectionLabel
                    eyebrow="ADMIN / AUTHORITY ACCESS"
                    title="Sign in to review cases."
                  />
                  <p>
                    Case records and masked evidence require an authenticated
                    session. Original viewing requires a court or admin account, a personal access key, and a camera photo.
                  </p>
                  <label>
                    Username
                    <input
                      autoComplete="username"
                      value={loginForm.username}
                      onChange={(e) =>
                        setLoginForm({ ...loginForm, username: e.target.value })
                      }
                      required
                    />
                  </label>
                  <label>
                    Password
                    <input
                      type="password"
                      autoComplete="current-password"
                      value={loginForm.password}
                      onChange={(e) =>
                        setLoginForm({ ...loginForm, password: e.target.value })
                      }
                      required
                    />
                  </label>
                  {loginError && (
                    <div className="inline-warning" role="alert">{loginError}</div>
                  )}
                  <button className="primary-action" type="submit">
                    Sign in <span>→</span>
                  </button>
                </form>
              ) : (
                <>
                  <div className="workspace-heading">
                    <SectionLabel
                      eyebrow="AUTHORITY COMMAND CENTER"
                      title="Case operations"
                      detail={`ROLE / ${authority.user.role}`}
                    />
                    <button
                      className="quiet-button"
                      onClick={() => {
                        loadCases();
                        loadAudit();
                      }}
                    >
                      Refresh data
                    </button>
                  </div>
                  {['ADMIN', 'COURT'].includes(authority.user.role) && <ViewerAccount api={API} authority={authority} />}
                  <div className="metric-strip">
                    {metrics.map((metric) => (
                      <div className="metric" key={metric.label}>
                        <StatusDot tone={metric.tone} />
                        <small>{metric.label}</small>
                        <strong>{metric.value}</strong>
                      </div>
                    ))}
                  </div>
                  <div className="command-grid">
                    <div className="case-queue surface-panel">
                      <div className="panel-kicker">
                        <span>ACTIVE CASE QUEUE</span>
                        <label className="compact-search">
                          <input
                            aria-label="Filter cases"
                            value={caseSearch}
                            onChange={(e) => setCaseSearch(e.target.value)}
                            placeholder="Filter cases"
                          />
                        </label>
                      </div>
                      {caseLoading && (
                        <p className="muted">Loading secure queue...</p>
                      )}
                      {filteredCases.map((item) => (
                        <button
                          className={`queue-row ${selectedCase?.id === item.id ? "active" : ""}`}
                          key={item.id}
                          onClick={() => setSelectedCase(item)}
                        >
                          <div>
                            <strong>{item.id.replace("CASE-", "SQ-")}</strong>
                            <span>
                              {item.category} / {item.priority}
                            </span>
                          </div>
                          <div>
                            <b>{item.title || "Untitled case"}</b>
                            <small>
                              {item.files?.length || 0} evidence · {item.status}
                            </small>
                          </div>
                          <span className="queue-arrow">→</span>
                        </button>
                      ))}
                      {!caseLoading && filteredCases.length === 0 && (
                        <p className="empty-state">
                          No cases match the current queue filter.
                        </p>
                      )}
                    </div>
                    <div className="command-side">
                      <VerificationMatrix verification={verification} />
                      <CorrelationGraph
                        verification={verification}
                        selectedCase={selectedCase}
                      />
                    </div>
                  </div>
                  {selectedCase && (
                    <div className="case-workspace">
                      <div className="case-header">
                        <div>
                          <span className="mono">
                            {selectedCase.id.replace("CASE-", "SQ-")}
                          </span>
                          <h3>{selectedCase.title || "Untitled case"}</h3>
                        </div>
                        <div className="case-state">
                          <StatusDot
                            tone={
                              selectedCase.status === "Closed"
                                ? "muted"
                                : "amber"
                            }
                          />
                          <span>
                            {selectedCase.priority} / {selectedCase.status}
                          </span>
                        </div>
                      </div>
                      <div className="case-content">
                        <div className="case-overview">
                          <p className="case-description">
                            {selectedCase.description || "No description."}
                          </p>
                          {authority?.user?.role === "ADMIN" && (
                            <div className="judicial-panel">
                              <div className="panel-kicker"><span>RESTRICTED CASE DETAILS</span><span>JUDICIAL KEY REQUIRED</span></div>
                              <p className="muted">Reporter identifiers, source text, and original filenames stay masked during routine review.</p>
                              <div className="evidence-actions"><button type="button" onClick={() => { setDetailsFormOpen(judicialDetails ? false : !detailsFormOpen); setJudicialDetails(null); setOriginalAccessFile(null); setJudicialKey(""); setAccessReason(""); setDetailsError(""); }}>{judicialDetails ? "Hide details" : detailsFormOpen ? "Cancel" : "Unlock sensitive details"}</button></div>
                              {detailsError && <p className="inline-warning" role="alert">{detailsError}</p>}
                              {detailsFormOpen && (
                                <form className="original-access-form" onSubmit={unlockJudicialDetails}>
                                  <label>Reason for access<textarea value={accessReason} onChange={event => setAccessReason(event.target.value)} minLength={20} maxLength={500} required placeholder="Describe the specific judicial need" /></label>
                                  <label>Judicial access key<input type="password" autoComplete="off" value={judicialKey} onChange={event => setJudicialKey(event.target.value)} required /></label>
                                  <div className="evidence-actions"><button type="submit" disabled={evidenceBusy}>{evidenceBusy ? "Checking…" : "Reveal for 60 seconds"}</button></div>
                                </form>
                              )}
                              {judicialDetails && (
                                <div className="judicial-details" role="region" aria-label="Unlocked judicial details">
                                  <p>Access audited. These details clear from this screen after 60 seconds.</p>
                                  <dl><dt>Reporter reference</dt><dd>{judicialDetails.reporterId || "Not recorded"}</dd><dt>Original title</dt><dd>{judicialDetails.title || "Not recorded"}</dd><dt>Original report</dt><dd>{judicialDetails.description || "Not recorded"}</dd><dt>Involved</dt><dd>{judicialDetails.involved || "Not recorded"}</dd><dt>Incident date</dt><dd>{judicialDetails.incidentDate || "Not recorded"}</dd></dl>
                                  <strong>Original evidence metadata</strong>
                                  {judicialDetails.files?.map(file => <p key={file.id}>{file.originalName} · SHA3-256 {file.originalHash}</p>)}
                                </div>
                              )}
                            </div>
                          )}
                          <div className="status-actions">
                            <button
                              onClick={() =>
                                updateCase(
                                  selectedCase.id,
                                  "Open",
                                  selectedCase.priority,
                                )
                              }
                            >
                              Open
                            </button>
                            <button
                              onClick={() =>
                                updateCase(selectedCase.id, "In Review", "High")
                              }
                            >
                              Mark in review
                            </button>
                            <button
                              onClick={() =>
                                updateCase(
                                  selectedCase.id,
                                  "Closed",
                                  selectedCase.priority,
                                )
                              }
                            >
                              Close
                            </button>
                            <button onClick={exportSummary}>
                              Export summary
                            </button>
                          </div>
                          <div className="evidence-list">
                            <div className="panel-kicker">
                              <span>EVIDENCE CUSTODY</span>
                              <span className="mono">
                                {selectedCase.files?.length || 0} ITEM(S)
                              </span>
                            </div>
                            <p className="muted">Review copies blur faces and the surrounding scene and alter voices. Spoken identities may still be audible. Originals are encrypted in storage. Each original view requires the viewer’s personal key and a camera photo linked to the audit trail.</p>
                            {evidenceError && <p className="inline-warning" role="alert">{evidenceError}</p>}
                            {selectedCase.files?.map((file) => (
                              <div className="evidence-row" key={file.name}>
                                <div>
                                  <strong>{file.original || file.name}</strong>
                                  <span>
                                    {file.mime || "evidence"} · {file.size || 0}{" "}
                                    bytes
                                  </span>
                                </div>
                                <small>{file.maskedCopyAvailable ? "Masked copy ready" : file.processingStatus === "QUARANTINED" ? "Quarantined" : "Masking required"}</small>
                                <small>{file.originalProtection === "COURT_SEALED" ? "Legacy sealed original: recovery required" : "Original restricted: personal key + viewer photo"}</small>
                                {(file.mime?.startsWith("image/") || file.mime?.startsWith("video/") || file.mime?.startsWith("audio/")) && (
                                  <b
                                    className={
                                      file.processingStatus === "COMPLETE"
                                        ? "video-ready"
                                        : "video-failed"
                                    }
                                  >
                                    MEDIA PRIVACY /{" "}
                                    {file.processingStatus || "UNKNOWN"}
                                    <br />
                                    Original restricted · Masked copy{" "}
                                    {file.maskedCopyAvailable
                                      ? "available"
                                      : "not available"}
                                  </b>
                                )}
                                <div className="evidence-actions">
                                  {file.maskedCopyAvailable && <button type="button" onClick={() => downloadEvidence(file).catch(error => setEvidenceError(error.response?.data?.error || "Masked copy unavailable"))}>Download masked copy</button>}
                                  {["ADMIN", "COURT"].includes(authority?.user?.role) && <button type="button" onClick={() => { setOriginalAccessFile(file.name); setDetailsFormOpen(false); setJudicialDetails(null); setJudicialKey(""); setAccessReason(""); setEvidenceError(""); }}>Request original</button>}
                                </div>
                                {["ADMIN", "COURT"].includes(authority?.user?.role) && originalAccessFile === file.name && <OriginalAccess key={`${selectedCase.id}:${file.name}`} api={API} caseId={selectedCase.id} file={file} authority={authority} onClose={() => setOriginalAccessFile(null)} onAudit={loadAudit} onReprocess={reprocessEvidence} />}
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="chat-panel surface-panel">
                          <div className="panel-kicker">
                            <span>SECURE CASE CHANNEL</span>
                            <span>IDENTITY SHIELDED</span>
                          </div>
                          <div className="chat-list">
                            {chatMessages.length === 0 ? (
                              <p className="muted">No messages yet.</p>
                            ) : (
                              chatMessages.map((message) => (
                                <div
                                  key={message.id}
                                  className={`chat-bubble ${message.sender === "authority" ? "authority" : "reporter"}`}
                                >
                                  <div className="chat-meta">
                                    {message.sender === "authority"
                                      ? "Authority"
                                      : "Reporter"}{" "}
                                    ·{" "}
                                    {new Date(
                                      message.createdAt,
                                    ).toLocaleString()}
                                  </div>
                                  <div>{message.text}</div>
                                </div>
                              ))
                            )}
                          </div>
                          <form onSubmit={sendMessage} className="chat-form">
                            <textarea
                              aria-label="Message to the reporter"
                              value={chatInput}
                              onChange={(e) => setChatInput(e.target.value)}
                              placeholder="Send a case-scoped follow-up"
                            />
                            <button type="submit" disabled={chatSending}>
                              {chatSending ? "Sending..." : "Send message"}
                            </button>
                          </form>
                          <small className="chat-footnote">
                            Encrypted at rest · Case-scoped communication · Not
                            end-to-end encrypted
                          </small>
                        </div>
                      </div>
                    </div>
                  )}
                  <div className="audit-stream surface-panel">
                    <div className="panel-kicker">
                      <span>RECENT AUDIT ACTIVITY</span>
                      <span className="mono">REDACTED EVENTS</span>
                    </div>
                    {auditEvents
                      .slice(-6)
                      .reverse()
                      .map((event, index) => (
                        <div
                          className="audit-row"
                          key={`${event.timestamp}-${index}`}
                        >
                          <span>
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                          <strong>{event.event}</strong>
                          <small>
                            {event.caseId || event.actor || "system"}
                          </small>
                          {event.event === 'ORIGINAL_ACCESS_GRANTED' && event.accessId && <AuditPhoto api={API} event={event} token={authority.token} />}
                        </div>
                      ))}
                    {auditEvents.length === 0 && (
                      <p className="empty-state">
                        No audit events available for this session.
                      </p>
                    )}
                  </div>
                </>
              )}
            </>
          )}
        </main>
      </div>
      <footer className="system-footer">
        <div><strong>SentinelQ</strong><span>A considered space for raising concerns.</span></div>
        <p>Independent reporting prototype · Not a government service<br />Encrypted storage does not provide network anonymity.</p>
      </footer>
    </div>
  );
}
