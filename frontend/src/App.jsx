import React, { useEffect, useMemo, useRef, useState } from "react";
import axios, { API, setToken } from './api';
import { isCancel } from 'axios';
import { EvidenceStatus, RecoveryReceipt, evidenceLabel, processingPending } from './SecurityStatus';
import OriginalAccess, { ViewerAccount, AuditPhoto } from './ViewerAccess';
import EvidenceCapture from "./EvidenceCapture";
import CaseActions, { reviewerPermissions } from './CaseActions';
import ReporterSafety from './ReporterSafety';
import { evidenceError as validateEvidence, evidenceFileBase64, MAX_EVIDENCE_BYTES } from "./capture.mjs";

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
  { title: "Add supporting evidence", short: "Attach supporting files", icon: "upload", heading: "A little context can help.", text: "You can attach documents, photos, video or audio. At least one supporting file is required before you can submit.", tip: "Check the contents and filenames before uploading. A document or photo can reveal more about you than you intend.", preview: "Supporting files · required", note: "Original files are encrypted and restricted. Some formats remain quarantined." },
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
          <p className="welcome-caption"><NavIcon name="shield" /> No reporter account required · Supporting evidence is required</p>
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
          <details><summary>How is my information encrypted?</summary><p>New reports use lattice-based post-quantum cryptography: ML-KEM-768 protects encryption keys, AES-256-GCM encrypts stored data, and ML-DSA-65 signs case records. Earlier records retain their original protection until updated. The platform manages these keys; this does not provide end-to-end encryption or hide your network activity.</p></details>
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
          {related.slice(0, 3).map((item, index) => (
            <g key={item.id}>
              <title>{item.id}</title>
              <path d={`M180 75 L${[80, 275, 275][index]} ${[35, 35, 120][index]}`} />
              <circle
                className="graph-node related"
                cx={[80, 275, 275][index]}
                cy={[35, 35, 120][index]}
                r="18"
              />
              <text x={[80, 275, 275][index]} y={[35, 35, 120][index]}>
                {item.id.slice(-6)}
              </text>
            </g>
          ))}
          <circle className="graph-node main" cx="180" cy="75" r="25" />
          <text x="180" y="75">
            {selectedCase
              ? selectedCase.id.slice(-6)
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
  const [securityBusy, setSecurityBusy] = useState(false), [securityNotice, setSecurityNotice] = useState('');
  const trackGeneration = useRef(0);
  const closeCase = () => { trackGeneration.current++; setTrackedCase(null); setRecoverySecret(''); setCaseId(''); setMessage(''); setError(''); setLoading(false); setSending(false); setSecurityBusy(false); };
  useEffect(() => {
    let lastActive = Date.now();
    const activity = () => { lastActive = Date.now(); };
    const timer = setInterval(() => { if (Date.now() - lastActive > 15 * 60 * 1000) closeCase(); }, 10000);
    window.addEventListener('pointerdown', activity);
    window.addEventListener('keydown', activity);
    return () => { clearInterval(timer); trackGeneration.current++; window.removeEventListener('pointerdown', activity); window.removeEventListener('keydown', activity); };
  }, []);
  useEffect(() => {
    if (!trackedCase || loading || sending || securityBusy) return;
    let cancelled = false, busy = false;
    const timer = setInterval(async () => {
      if (document.hidden || busy) return;
      busy = true;
      try {
        const response = await axios.post(`${API}/track`, { caseId: trackedCase.id, recoverySecret: recoverySecret.trim() });
        if (!cancelled) setTrackedCase(response.data.case);
      } catch (err) { if (!cancelled) setError(err.response?.data?.error || 'Progress could not refresh. Your submitted report is still saved.'); }
      finally { busy = false; }
    }, 10000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [trackedCase?.id, recoverySecret, loading, sending, securityBusy]);

  const trackCase = async (event) => {
    event.preventDefault();
    if (loading || sending || securityBusy) return;
    setError("");
    setLoading(true);
    const generation = ++trackGeneration.current;
    try {
      const response = await axios.post(`${API}/track`, {
        caseId: caseId.trim(),
        recoverySecret: recoverySecret.trim(),
      });
      if (generation === trackGeneration.current) setTrackedCase(response.data.case);
    } catch (requestError) {
      if (generation !== trackGeneration.current) return;
      setTrackedCase(null);
      setError(
        requestError.response?.data?.error ||
          "Could not open this case. Check the Case ID and recovery key.",
      );
    } finally {
      if (generation === trackGeneration.current) setLoading(false);
    }
  };

  const sendReply = async (event) => {
    event.preventDefault();
    if (!message.trim() || !trackedCase || sending || loading || securityBusy) return;
    setSending(true);
    setError("");
    const generation = trackGeneration.current;
    try {
      const response = await axios.post(
        `${API}/cases/${encodeURIComponent(trackedCase.id)}/messages`,
        {
          text: message.trim(),
          sender: "reporter",
          recoverySecret: recoverySecret.trim(),
        },
        { headers: { Authorization: null } },
      );
      if (generation !== trackGeneration.current) return;
      setTrackedCase(current => current ? { ...current, messages: response.data.messages || [] } : current);
      setMessage("");
    } catch (requestError) {
      if (generation !== trackGeneration.current) return;
      setError(
        requestError.response?.data?.error || "Message could not be sent.",
      );
    } finally {
      if (generation === trackGeneration.current) setSending(false);
    }
  };

  const rotated = async newKey => {
    const generation = ++trackGeneration.current;
    setRecoverySecret(newKey);
    setTrackedCase(current => current ? { ...current, reviewLocked: true } : current);
    try {
      const { data } = await axios.post(`${API}/track`, { caseId: trackedCase.id, recoverySecret: newKey });
      if (generation === trackGeneration.current) setTrackedCase(data.case);
    } catch { if (generation === trackGeneration.current) setError('Key replacement succeeded. Keep your saved new key and refresh when storage is available.'); }
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
        {securityNotice && <p role="status">{securityNotice}</p>}
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
              maxLength={101}
              autoComplete="off"
              spellCheck={false}
              readOnly={!!trackedCase}
              onChange={(event) => setCaseId(event.target.value)}
              placeholder="CASE-..."
              required
            />
          </label>
          <label>
            Recovery key
            <input
              type="password"
              value={recoverySecret}
              readOnly={!!trackedCase}
              onChange={(event) => setRecoverySecret(event.target.value)}
              autoComplete="off"
              required
            />
          </label>
          {error && <p className="inline-warning" role="alert">{error}</p>}
          <button className="primary-action" type="submit" disabled={loading || sending || securityBusy}>
            {loading ? "Refreshing…" : trackedCase ? "Refresh case and messages" : "Open case"} <span>→</span>
          </button>
          {trackedCase && <button className="text-action" type="button" onClick={closeCase}>Close case and clear key</button>}
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
          <ReporterSafety key={trackedCase.id} record={trackedCase} recoverySecret={recoverySecret.trim()} onUpdated={setTrackedCase} onRotated={rotated} onBusy={setSecurityBusy} onDeleted={pending => { closeCase(); setSecurityBusy(false); setSecurityNotice(pending ? 'Complaint access is revoked. Removal of retired encrypted objects is pending and will retry automatically.' : 'Your live complaint, messages and evidence were deleted. Minimal audit and deletion records remain.'); }} />
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
            <EvidenceStatus files={trackedCase.files} />
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
                <small>{item.sender} · {item.createdAt ? new Date(item.createdAt).toLocaleString() : ''}</small>
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
              maxLength={4000}
              disabled={sending}
              onChange={(event) => setMessage(event.target.value)}
              aria-label="Message to the reviewing authority"
              placeholder="Write a follow-up message"
              required
            />
            <button className="primary-action" type="submit" disabled={loading || sending || securityBusy || !message.trim()}>
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
  const [location, setLocation] = useState(''), [incidentDate, setIncidentDate] = useState('');
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
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedCase, setSelectedCase] = useState(null);
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseError, setCaseError] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailRefresh, setDetailRefresh] = useState(0);
  const [messageError, setMessageError] = useState('');
  const [verificationError, setVerificationError] = useState('');
  const [auditError, setAuditError] = useState('');
  const [panicExit, setPanicExit] = useState(false);
  const [privacyWarnings, setPrivacyWarnings] = useState([]);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatSending, setChatSending] = useState(false);
  const [isAnonymizing, setIsAnonymizing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const pendingSubmission = useRef(null);
  const descriptionRevision = useRef(0);
  const detailsGeneration = useRef(0);
  const [acceptedAnonymized, setAcceptedAnonymized] = useState(false);
  const [verification, setVerification] = useState(null);
  const [authority, setAuthority] = useState(null);
  const [loginForm, setLoginForm] = useState({
    username: "",
    password: "",
  });
  const [loginError, setLoginError] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const authorityGeneration = useRef(0);
  const selectedCaseRef = useRef(null);
  selectedCaseRef.current = selectedCase?.id;
  const permissions = reviewerPermissions(authority?.user?.role);
  const [auditEvents, setAuditEvents] = useState([]);
  const [originalAccessFile, setOriginalAccessFile] = useState(null);
  const [judicialKey, setJudicialKey] = useState("");
  const [accessReason, setAccessReason] = useState("");
  const [evidenceError, setEvidenceError] = useState("");
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [detailsFormOpen, setDetailsFormOpen] = useState(false);
  const [judicialDetails, setJudicialDetails] = useState(null);
  const [detailsError, setDetailsError] = useState("");
  const clearAuthority = () => {
    detailsGeneration.current++;
    authorityGeneration.current++; setLoginBusy(false); setCaseError(''); setMessageError(''); setVerificationError(''); setAuditError(''); setCaseSearch(''); setStatusFilter('All');
    setToken(null); setAuthority(null); setCases([]); setSelectedCase(null); setChatMessages([]); setChatInput(''); setAuditEvents([]); setVerification(null);
    setOriginalAccessFile(null); setJudicialKey(''); setAccessReason(''); setJudicialDetails(null); setDetailsFormOpen(false); setLoginForm({ username: '', password: '' });
  };
  useEffect(() => {
    const expire = () => { clearAuthority(); setLoginError('Your session ended. Sign in again to continue.'); };
    window.addEventListener('sentinelq-session-expired', expire);
    return () => window.removeEventListener('sentinelq-session-expired', expire);
  }, []);
  useEffect(() => {
    const restored = event => { if (event.persisted) window.location.reload(); };
    const leaving = () => { clearAuthority(); setResult(null); setTitle(''); setDescription(''); setFiles([]); setLocation(''); setIncidentDate(''); pendingSubmission.current = null; };
    window.addEventListener('pagehide', leaving);
    window.addEventListener('pageshow', restored);
    return () => { window.removeEventListener('pagehide', leaving); window.removeEventListener('pageshow', restored); };
  }, []);
  useEffect(() => {
    if (!authority) return;
    let lastActive = Date.now();
    const activity = () => { lastActive = Date.now(); };
    const timer = setInterval(() => {
      if (Date.now() - lastActive >= 15 * 60 * 1000 || Date.now() >= Date.parse(authority.expiresAt)) {
        logout(); setLoginError('Locked after inactivity or session expiry. Sign in again to continue.');
      }
    }, 10000);
    window.addEventListener('pointerdown', activity); window.addEventListener('keydown', activity);
    return () => { clearInterval(timer); window.removeEventListener('pointerdown', activity); window.removeEventListener('keydown', activity); };
  }, [authority]);

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
    setToken(authority?.token);
  }, [authority]);

  useEffect(() => {
    setPrivacyWarnings(checkPrivacy(description));
  }, [description]);

  const anonymize = async () => {
    if (!description.trim() || isAnonymizing || submitting) return;
    const revision = descriptionRevision.current;
    setIsAnonymizing(true);
    try {
      const res = await axios.post(`${API}/anonymize`, { text: description });
      if (revision !== descriptionRevision.current) return;
      setAnonymizedDescription(res.data.anonymizedText || "");
      setAcceptedAnonymized(false);
      if (!result?.recoverySecret) setResult({ suggestion: res.data.anonymizedText });
    } catch (err) {
      if (revision !== descriptionRevision.current) return;
      if (!result?.recoverySecret) setResult({ error: err.message });
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
    if (submitting || captureBusy || isAnonymizing || result?.recoverySecret) return;
    const error = files.length ? validateEvidence(files) : 'Attach at least one supporting evidence file before submitting.';
    if (error) { setAttachmentError(error); return; }
    setSubmitting(true);
    setUploadProgress(0);
    try {
      const toSend = {
        title,
        location, incidentDate,
        description: acceptedAnonymized ? anonymizedDescription : description,
        anonymizedDescription: acceptedAnonymized ? anonymizedDescription : "",
        files: [],
      };
      for (const file of files) {
        const b64 = await evidenceFileBase64(file);
        toSend.files.push({ name: file.name, data: b64 });
      }
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(toSend)))), byte => byte.toString(16).padStart(2, '0')).join('');
      if (pendingSubmission.current?.digest !== digest) pendingSubmission.current = { digest, token: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
      const res = await axios.post(`${API}/report-base64`, toSend, { headers: { 'X-Submission-Token': pendingSubmission.current.token }, onUploadProgress: progress => setUploadProgress(progress.total ? Math.min(100, Math.round(progress.loaded / progress.total * 100)) : 0) });
      pendingSubmission.current = null;
      setResult({ ...res.data, flow: "Report submitted" });
      descriptionRevision.current++;
      setTitle(''); setDescription(''); setFiles([]); setLocation(''); setIncidentDate('');
      setAcceptedAnonymized(false);
      setAnonymizedDescription("");
    } catch (err) {
      setResult({ error: err.response?.data?.error || 'Submission could not be confirmed. Keep this tab open and retry with the same details; a saved report will not be duplicated.' });
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
      setSelectedCase(current => nextCases.find(item => item.id === current?.id) || nextCases[0] || null);
      setDetailRefresh(current => current + 1);
    } catch (err) {
      if (!isCancel(err)) setCaseError(err.response?.data?.error || 'Could not refresh cases. Try again.');
    } finally {
      setCaseLoading(false);
    }
  };

  const login = async (e) => {
    e.preventDefault();
    if (loginBusy) return;
    setLoginBusy(true);
    const generation = ++authorityGeneration.current;
    setLoginError("");
    try {
      const res = await axios.post(`${API}/auth/login`, loginForm);
      if (generation !== authorityGeneration.current) return;
      const session = { token: res.data.token, user: res.data.user, expiresAt: res.data.expiresAt };
      setToken(session.token);
      setAuthority(session);
      setLoginForm({ username: '', password: '' });
      setActiveView("dashboard");
    } catch (error) {
      if (generation === authorityGeneration.current) setLoginError(error.response?.data?.error || "Authority login failed");
    } finally { if (generation === authorityGeneration.current) setLoginBusy(false); }
  };

  const logout = async () => {
    const token = authority?.token;
    clearAuthority();
    pendingSubmission.current = null;
    setActiveView("dashboard");
    try {
      if (token) await fetch(`${API}/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, keepalive: true });
    } catch (error) {
      /* local session still clears */
    }
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
    if (!selectedCase?.id || evidenceBusy) return;
    const id = selectedCase.id;
    const generation = ++detailsGeneration.current;
    setDetailsError("");
    setEvidenceBusy(true);
    try {
      const response = await axios.post(`${API}/cases/${encodeURIComponent(selectedCase.id)}/judicial-details`, { key: judicialKey, reason: accessReason });
      if (generation !== detailsGeneration.current || selectedCaseRef.current !== id || document.hidden) return;
      setJudicialDetails(response.data.details);
      setDetailsFormOpen(false);
      setAccessReason("");
      loadAudit();
    } catch (error) {
      if (generation === detailsGeneration.current && !isCancel(error)) setDetailsError(error.response?.data?.error || "Judicial details unavailable");
    } finally {
      setJudicialKey("");
      setEvidenceBusy(false);
    }
  };

  const reprocessEvidence = async (file, grant) => {
    if (!selectedCase?.id) return;
    const id = selectedCase.id;
    setEvidenceError("");
    setEvidenceBusy(true);
    try {
      const response = await axios.post(`${API}/cases/${encodeURIComponent(selectedCase.id)}/evidence/${encodeURIComponent(file.name)}/reprocess`, {}, { headers: { "X-Original-Grant": grant } });
      if (selectedCaseRef.current !== id) return;
      setSelectedCase(response.data.case);
      setCases(previous => previous.map(item => item.id === response.data.case.id ? response.data.case : item));
      loadAudit();
    } catch (error) {
      if (selectedCaseRef.current === id && !isCancel(error)) setEvidenceError(error.response?.data?.error || "Media processing failed");
    } finally {
      setEvidenceBusy(false);
    }
  };

  const loadAudit = async () => {
    if (!authority?.token || !permissions.audit) return;
    setAuditError('');
    try {
      const res = await axios.get(`${API}/audit`);
      setAuditEvents(res.data.events || []);
    } catch (error) {
      if (!isCancel(error)) setAuditError(error.response?.data?.error || 'Audit activity could not refresh.');
    }
  };

  useEffect(() => {
    detailsGeneration.current++;
    if (activeView !== 'dashboard') { setJudicialDetails(null); setDetailsFormOpen(false); setOriginalAccessFile(null); setJudicialKey(''); setAccessReason(''); }
    if (activeView === "dashboard" && authority?.token) {
      loadCases();
      loadAudit();
    }
  }, [activeView, authority?.token]);

  useEffect(() => {
    if (activeView !== 'dashboard' || !authority || !selectedCase?.id) return;
    let cancelled = false;
    const id = selectedCase.id;
    setChatMessages([]); setChatInput(''); setMessageError(''); setVerification(null); setVerificationError(''); setDetailLoading(true);
    axios.get(`${API}/cases/${encodeURIComponent(id)}`).then(({ data }) => {
      if (cancelled) return;
      setSelectedCase(data.case); setChatMessages(data.case.messages || []);
    }).catch(error => { if (!cancelled && !isCancel(error)) setCaseError(error.response?.data?.error || 'Case details could not load. Refresh data to retry.'); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });
    axios.get(`${API}/cases/${encodeURIComponent(id)}/verification`).then(({ data }) => { if (!cancelled) setVerification(data.verification || null); })
      .catch(error => { if (!cancelled && !isCancel(error)) setVerificationError(error.response?.data?.error || 'Integrity checks could not load. Refresh data to retry.'); });
    return () => { cancelled = true; };
  }, [activeView, authority?.token, selectedCase?.id, detailRefresh]);

  useEffect(() => {
    if (!authority || activeView !== 'dashboard' || !processingPending(selectedCase?.files)) return;
    let cancelled = false, busy = false;
    const timer = setInterval(async () => {
      if (document.hidden || busy) return;
      busy = true;
      try {
        const { data } = await axios.get(`${API}/cases/${encodeURIComponent(selectedCase.id)}`);
        if (cancelled) return;
        setSelectedCase(data.case);
        setCases(current => current.map(item => item.id === data.case.id ? data.case : item));
        const checked = await axios.get(`${API}/cases/${encodeURIComponent(selectedCase.id)}/verification`);
        if (!cancelled) setVerification(checked.data.verification);
      } catch (error) { if (!cancelled) setEvidenceError(error.response?.data?.error || 'Could not refresh evidence status.'); }
      finally { busy = false; }
    }, 5000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [activeView, authority?.token, selectedCase?.id, processingPending(selectedCase?.files)]);

  useEffect(() => {
    if (!result?.recoverySecret || !processingPending(result.files)) return;
    let cancelled = false, busy = false;
    const timer = setInterval(async () => {
      if (document.hidden || busy) return;
      busy = true;
      try {
        const { data } = await axios.post(`${API}/track`, { caseId: result.id, recoverySecret: result.recoverySecret });
        if (!cancelled) setResult(current => current?.id === result.id ? { ...current, files: data.case.files } : current);
      } catch { /* Receipt remains valid during a temporary refresh failure. */ }
      finally { busy = false; }
    }, 15000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [result?.id, processingPending(result?.files)]);

  useEffect(() => {
    detailsGeneration.current++;
    setOriginalAccessFile(null);
    setJudicialKey("");
    setAccessReason("");
    setEvidenceError("");
    setDetailsFormOpen(false);
    setJudicialDetails(null);
    setDetailsError("");
  }, [selectedCase?.id]);

  useEffect(() => {
    if (!judicialDetails && !detailsFormOpen) return;
    const timer = setTimeout(() => setJudicialDetails(null), 60000);
    const hide = () => { if (document.hidden) { detailsGeneration.current++; setJudicialDetails(null); setDetailsFormOpen(false); setJudicialKey(''); setAccessReason(''); } };
    document.addEventListener('visibilitychange', hide);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', hide); };
  }, [judicialDetails, detailsFormOpen]);

  const filteredCases = useMemo(() => {
    const q = caseSearch.trim().toLowerCase();
    return cases.filter((item) => {
      return (statusFilter === 'All' || item.status === statusFilter) && [
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
  }, [cases, caseSearch, statusFilter]);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!selectedCase || !chatInput.trim() || chatSending || !permissions.writeChat) return;
    const id = selectedCase.id;
    setMessageError('');
    setChatSending(true);
    try {
      const res = await axios.post(
        `${API}/cases/${encodeURIComponent(selectedCase.id)}/messages`,
        { text: chatInput.trim(), sender: "authority" },
      );
      if (selectedCaseRef.current !== id) return;
      setChatMessages(res.data.messages || []);
      setChatInput("");
    } catch (err) {
      if (selectedCaseRef.current === id && !isCancel(err)) setMessageError(err.response?.data?.error || 'Message could not be sent. Please retry.');
    } finally {
      setChatSending(false);
    }
  };

  const triggerPanicExit = () => {
    const token = authority?.token;
    clearAuthority();
    pendingSubmission.current = null;
    if (token)
      fetch(`${API}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        keepalive: true,
      }).catch(() => {});
    setTitle("");
    setDescription("");
    setLocation(''); setIncidentDate('');
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
      label: "Masking alerts",
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
      <div className="service-strip"><div><span>Independent incident reporting · Version 2</span><span className="prototype-label">Prototype · Not a government service</span></div></div>
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
        {authority && <button className="text-action header-signout" onClick={logout}>Sign out</button>}
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
              <nav className="intake-steps" aria-label="Report sections"><a href="#report-details"><b>1</b> Incident details</a><a href="#report-evidence"><b>2</b> Evidence <small>Required</small></a><a href="#report-submit"><b>3</b> Submit report</a></nav>
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
                        maxLength={200}
                        disabled={submitting}
                        onChange={(e) => setTitle(e.target.value)}
                        placeholder="A short summary of the concern"
                        required
                      />
                    </label>
                    <label>
                        Incident description <span className="required-label">Required</span>
                      <textarea
                        value={description}
                        maxLength={10000}
                        disabled={submitting}
                        onChange={(e) => { descriptionRevision.current++; setDescription(e.target.value); setAnonymizedDescription(''); setAcceptedAnonymized(false); }}
                        placeholder="Describe what happened. Use the encrypted location field below for an exact address or coordinates."
                        required
                      />
                    </label>
                    <div className="field-hint"><span>Keep exact location out of the title and narrative; use the protected field below.</span><span>{description.length.toLocaleString()} characters</span></div>
                    <label>Incident date (optional)<input type="date" value={incidentDate} disabled={submitting} onChange={event => setIncidentDate(event.target.value)} /></label>
                    <label>Exact location (optional, encrypted)<textarea value={location} disabled={submitting} onChange={event => setLocation(event.target.value)} maxLength={500} placeholder="Incident address, landmark or coordinates" /></label>
                    <p className="field-hint">Ordinary views never receive this location. An authorized admin or court viewer needs the separate judicial key and an access reason to decrypt it. Your device location is not collected automatically.</p>
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
                            disabled={isAnonymizing || submitting}
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
                          maxLength={10000}
                          disabled={submitting}
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
                            disabled={submitting || !anonymizedDescription.trim()}
                          >
                            Apply redaction
                          </button>
                          <button
                            type="button"
                            onClick={() => setAcceptedAnonymized(false)}
                            disabled={submitting}
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
                    <span className="mono">REQUIRED</span>
                  </div>
                  <h2 className="panel-title">Add supporting evidence.</h2>
                  <p>At least one nonempty supporting file is required. Its integrity can be checked cryptographically; investigators must still assess whether the allegation is true.</p>
                  <p className="security-notice">Submit without waiting for video masking. Once upload and encrypted storage finish, you receive your case details. Masking continues in the background; originals remain restricted.</p>
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
                  <div id="report-submit" tabIndex={-1} className="submission-actions"><p>Ready to send your report?<small>{result?.recoverySecret ? 'Save and clear the receipt below before submitting another report.' : captureBusy ? "Use or discard your capture before submitting." : "Review your details above before submitting."}</small></p><button className="primary-action" type="submit" form="incident-report" disabled={submitting || captureBusy || isAnonymizing || !files.length || Boolean(result?.recoverySecret)}>{submitting ? uploadProgress < 100 ? `Uploading ${uploadProgress}%` : "Saving securely…" : "Submit report"}<span aria-hidden="true">→</span></button></div>
                  {submitting && <p role="status">{uploadProgress < 100 ? 'Uploading your report and attachments. Keep this page open until you receive your receipt.' : 'Upload complete. Waiting for confirmation that your encrypted report is saved.'} Masking will run afterward.</p>}
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
                      {result.error ? <p className="response-error">{result.error}</p> : result.recoverySecret ? <RecoveryReceipt key={result.id} result={result} onClose={() => setResult(null)} /> : result.suggestion ? <p>Review the suggested version in the incident details before applying it.</p> : <p>Your request was completed.</p>}
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
                  <p className="security-notice">This workspace locks after 15 minutes without keyboard or pointer activity. Sign out when finished on a shared device.</p>
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
                  <button className="primary-action" type="submit" disabled={loginBusy}>
                    {loginBusy ? 'Signing in…' : 'Sign in'} <span>→</span>
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
                      disabled={caseLoading || detailLoading}
                      onClick={() => {
                        loadCases();
                        loadAudit();
                      }}
                    >
                      {caseLoading || detailLoading ? 'Refreshing…' : 'Refresh data'}
                    </button>
                  </div>
                  {caseError && <p className="inline-warning" role="alert">{caseError}</p>}
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
                        <span>CASE QUEUE · {filteredCases.length} OF {cases.length}</span>
                        <label className="compact-search">
                          <input
                            aria-label="Filter cases"
                            value={caseSearch}
                            onChange={(e) => setCaseSearch(e.target.value)}
                            placeholder="Filter cases"
                          />
                        </label>
                      </div>
                      <label className="queue-filter">Filter by status<select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>{['All', 'Open', 'In Review', 'Closed'].map(value => <option key={value}>{value}</option>)}</select></label>
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
                            <strong>{item.id}</strong>
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
                          {cases.length ? 'No cases match your filters.' : authority.user.role === 'INVESTIGATOR' ? 'No cases are assigned to you yet.' : 'No reports have been submitted yet.'}
                        </p>
                      )}
                    </div>
                    <div className="command-side">
                      {verificationError && <p className="inline-warning" role="alert">{verificationError}</p>}
                      <VerificationMatrix verification={verification} />
                      <CorrelationGraph
                        verification={verification}
                        selectedCase={selectedCase}
                      />
                    </div>
                  </div>
                  {detailLoading && <p role="status">Loading case details…</p>}
                  {selectedCase && !detailLoading && (
                    <div className="case-workspace">
                      <div className="case-header">
                        <div>
                          <span className="mono">
                            {selectedCase.id}
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
                        <p className="muted">Location: {selectedCase.location || 'Not provided'}</p>
                        <div className="case-overview">
                          <p className="case-description">
                            {selectedCase.description || "No description."}
                          </p>
                          {authority?.user?.role === "ADMIN" && (
                            <div className="judicial-panel">
                              <div className="panel-kicker"><span>RESTRICTED CASE DETAILS</span><span>JUDICIAL KEY REQUIRED</span></div>
                              <p className="muted">Reporter identifiers, source text, and original filenames stay masked during routine review.</p>
                              <div className="evidence-actions"><button type="button" onClick={() => { detailsGeneration.current++; setDetailsFormOpen(judicialDetails ? false : !detailsFormOpen); setJudicialDetails(null); setOriginalAccessFile(null); setJudicialKey(""); setAccessReason(""); setDetailsError(""); }}>{judicialDetails ? "Hide details" : detailsFormOpen ? "Cancel" : "Unlock sensitive details"}</button></div>
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
                                  <dl><dt>Exact location (decrypted)</dt><dd>{judicialDetails.location || "Not provided"}</dd><dt>Reporter reference</dt><dd>{judicialDetails.reporterId || "Not recorded"}</dd><dt>Original title</dt><dd>{judicialDetails.title || "Not recorded"}</dd><dt>Original report</dt><dd>{judicialDetails.description || "Not recorded"}</dd><dt>Involved</dt><dd>{judicialDetails.involved || "Not recorded"}</dd><dt>Incident date</dt><dd>{judicialDetails.incidentDate || "Not recorded"}</dd></dl>
                                  <strong>Original evidence metadata</strong>
                                  {judicialDetails.files?.map(file => <p key={file.id}>{file.originalName} · SHA3-256 {file.originalHash}</p>)}
                                </div>
                              )}
                            </div>
                          )}
                          <CaseActions key={selectedCase.id} record={selectedCase} role={authority.user.role} onUpdated={updated => {
                            setCases(current => current.map(item => item.id === updated.id ? { ...item, ...updated } : item));
                            setSelectedCase(current => current?.id === updated.id ? { ...current, ...updated } : current);
                            loadAudit();
                          }} />
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
                                <small aria-live="polite">{evidenceLabel(file)}</small>
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
                                  {["ADMIN", "COURT"].includes(authority?.user?.role) && <button type="button" onClick={() => { detailsGeneration.current++; setOriginalAccessFile(file.name); setDetailsFormOpen(false); setJudicialDetails(null); setJudicialKey(""); setAccessReason(""); setEvidenceError(""); }}>Request original</button>}
                                </div>
                                {["ADMIN", "COURT"].includes(authority?.user?.role) && originalAccessFile === file.name && <OriginalAccess key={`${selectedCase.id}:${file.name}`} api={API} caseId={selectedCase.id} file={file} authority={authority} onClose={() => setOriginalAccessFile(null)} onAudit={loadAudit} onReprocess={reprocessEvidence} />}
                              </div>
                            ))}
                          </div>
                        </div>
                        {permissions.readChat && <div className="chat-panel surface-panel">
                          <div className="panel-kicker">
                            <span>SECURE CASE CHANNEL</span>
                            <span>ENCRYPTED AT REST</span>
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
                          {messageError && <p className="inline-warning" role="alert">{messageError}</p>}
                          {permissions.writeChat && <form onSubmit={sendMessage} className="chat-form">
                            <textarea
                              aria-label="Message to the reporter"
                              maxLength={4000}
                              disabled={chatSending}
                              value={chatInput}
                              onChange={(e) => setChatInput(e.target.value)}
                              placeholder="Send a case-scoped follow-up"
                            />
                            <button type="submit" disabled={chatSending || !chatInput.trim()}>
                              {chatSending ? "Sending..." : "Send message"}
                            </button>
                          </form>}
                          <small className="chat-footnote">
                            Encrypted at rest · Case-scoped communication · Not
                            end-to-end encrypted
                          </small>
                        </div>}
                      </div>
                    </div>
                  )}
                  {permissions.audit && <div className="audit-stream surface-panel">
                    <div className="panel-kicker">
                      <span>RECENT AUDIT ACTIVITY</span>
                      <span className="mono">REDACTED EVENTS</span>
                    </div>
                    {auditError && <p className="inline-warning" role="alert">{auditError}</p>}
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
                    {!auditError && auditEvents.length === 0 && (
                      <p className="empty-state">
                        No audit events available for this session.
                      </p>
                    )}
                  </div>}
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
