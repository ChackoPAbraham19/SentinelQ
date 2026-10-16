import React, { useEffect, useRef, useState } from 'react';
import axios from './api';

export function AuditPhoto({ api, event, token }) {
  const [url, setUrl] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const request = useRef(null);
  useEffect(() => () => { if (url) URL.revokeObjectURL(url); }, [url]);
  useEffect(() => {
    const hide = () => { if (document.hidden) { request.current?.abort(); setUrl(''); setBusy(false); } };
    document.addEventListener('visibilitychange', hide);
    return () => { request.current?.abort(); document.removeEventListener('visibilitychange', hide); };
  }, []);
  const show = async () => {
    if (url) { setUrl(''); return; }
    if (request.current && !request.current.signal.aborted) return;
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError('');
    try {
      const response = await axios.get(`${api}/access-audits/${encodeURIComponent(event.accessId)}/photo`, { responseType: 'blob', headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
      if (!controller.signal.aborted && !document.hidden) setUrl(URL.createObjectURL(response.data));
    }
    catch { if (!controller.signal.aborted) setError('Viewer photo unavailable. Try again.'); }
    finally { if (request.current === controller) { request.current = null; if (!controller.signal.aborted) setBusy(false); } }
  };
  return <div><small>Viewer: {event.actor} ({event.role}) · {event.orderReference} · {event.reason}</small><button type="button" disabled={busy} onClick={show}>{busy ? 'Loading viewer photo…' : url ? 'Hide viewer photo' : 'Review viewer photo'}</button>{url && <img className="viewer-photo-preview" src={url} alt={`Recorded photo for ${event.actor}, access ${event.accessId}`} />}{error && <p role="alert">{error}</p>}</div>;
}

export function ViewerAccount({ api, authority }) {
  const [configured, setConfigured] = useState(null);
  const [password, setPassword] = useState('');
  const [key, setKey] = useState('');
  const [revealKey, setRevealKey] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [court, setCourt] = useState({ username: '', password: '' });
  const [created, setCreated] = useState('');
  const [statusAttempt, setStatusAttempt] = useState(0);
  const [statusError, setStatusError] = useState('');
  const [copied, setCopied] = useState('');
  const config = { headers: { Authorization: `Bearer ${authority.token}` } };
  useEffect(() => {
    const controller = new AbortController();
    setConfigured(null); setStatusError('');
    axios.get(`${api}/viewer-key`, { ...config, signal: controller.signal })
      .then(res => { if (!controller.signal.aborted) setConfigured(res.data.configured); })
      .catch(() => { if (!controller.signal.aborted) setStatusError('Could not load personal key status.'); });
    return () => controller.abort();
  }, [api, authority.token, statusAttempt]);
  useEffect(() => {
    const hide = () => { if (document.hidden) setRevealKey(false); };
    const timer = revealKey ? setTimeout(() => setRevealKey(false), 30000) : null;
    document.addEventListener('visibilitychange', hide);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', hide); };
  }, [revealKey]);
  const createKey = async e => {
    e.preventDefault(); setBusy(true); setError('');
    try { const { data } = await axios.post(`${api}/viewer-key`, { password }, config); setKey(data.key); setConfigured(true); }
    catch (err) { setError(err.response?.data?.error || 'Could not create key.'); }
    finally { setPassword(''); setBusy(false); }
  };
  const createCourt = async e => {
    e.preventDefault(); setBusy(true); setError(''); setCreated('');
    try { const { data } = await axios.post(`${api}/courts`, court, config); setCreated(`Court login ${data.username} created. The court user can sign in and create their own personal access key.`); setCourt({ username: '', password: '' }); }
    catch (err) { setError(err.response?.data?.error || 'Could not create court login.'); }
    finally { setBusy(false); }
  };
  const copyKey = async () => {
    try { await navigator.clipboard.writeText(key); setCopied('Key copied. Store it privately; your clipboard may be shared with other apps.'); }
    catch { setCopied('Clipboard unavailable. Reveal your key, select it, and copy it manually.'); }
  };
  return <section className="surface-panel custody-panel">
    <h2>Your original-access key</h2>
    <p>Reporters submit evidence without a key. To view an original, you must enter your own key and take a camera photo. Each access is recorded against your account.</p>
    {configured === null && !statusError && <p role="status">Checking your personal key status…</p>}
    {statusError && <div><p role="alert">{statusError}</p><button type="button" onClick={() => setStatusAttempt(value => value + 1)}>Retry key status</button></div>}
    {configured === false && <form onSubmit={createKey}><label>Confirm your account password<input type="password" autoComplete="current-password" required disabled={busy} value={password} onChange={e => setPassword(e.target.value)} /></label><button disabled={busy}>{busy ? 'Creating personal key…' : 'Create my personal key'}</button></form>}
    {configured && !key && <p>Your key is configured. Use your saved key when requesting an original.</p>}
    {key && <div><strong>Save this key securely. It is shown only once and cannot be recovered.</strong><label>Your personal access key<input type={revealKey ? 'text' : 'password'} autoComplete="off" spellCheck={false} readOnly value={key} onFocus={e => e.target.select()} /></label><button type="button" onClick={() => setRevealKey(value => !value)} aria-pressed={revealKey}>{revealKey ? 'Hide key' : 'Reveal key for 30 seconds'}</button><button type="button" onClick={copyKey}>Copy personal key</button><button type="button" onClick={() => { setKey(''); setRevealKey(false); setCopied(''); }}>I have saved my key</button>{copied && <p role="status">{copied}</p>}</div>}
    {authority.user.role === 'ADMIN' && <details><summary>Create a court login</summary><p>Create a separate account for each court viewer so access is attributable to a person. Deliver login credentials through your approved secure channel.</p><form onSubmit={createCourt}><label>Court viewer username<input pattern="[a-z][a-z0-9_-]{2,63}" required value={court.username} onChange={e => setCourt({ ...court, username: e.target.value })} /></label><label>Initial password (at least 16 characters)<input type="password" autoComplete="new-password" minLength={16} maxLength={256} required value={court.password} onChange={e => setCourt({ ...court, password: e.target.value })} /></label><button disabled={busy}>Create court login</button></form></details>}
    {created && <p role="status">{created}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}

export function ViewerPhoto({ startChallenge, onPhoto, disabled = false }) {
  const video = useRef(null), stream = useRef(null), generation = useRef(0), request = useRef(null);
  const [active, setActive] = useState(false), [ready, setReady] = useState(false), [busy, setBusy] = useState(false), [preview, setPreview] = useState(''), [error, setError] = useState('');
  const stop = () => { generation.current++; request.current?.abort(); stream.current?.getTracks().forEach(track => track.stop()); stream.current = null; setActive(false); setReady(false); setBusy(false); };
  useEffect(() => {
    const background = () => { if (document.hidden) { stop(); onPhoto(null); setPreview(''); } };
    const exit = () => { stop(); onPhoto(null); setPreview(''); };
    document.addEventListener('visibilitychange', background);
    window.addEventListener('pagehide', exit);
    return () => { generation.current++; request.current?.abort(); stream.current?.getTracks().forEach(track => track.stop()); document.removeEventListener('visibilitychange', background); window.removeEventListener('pagehide', exit); };
  }, []);
  const start = async () => {
    stop(); onPhoto(null); setPreview(''); setError(''); setBusy(true);
    const run = generation.current;
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('Camera access requires HTTPS and a supported browser. Open this page in a supported browser to continue.');
      const controller = new AbortController(); request.current = controller;
      await startChallenge(controller.signal);
      if (run !== generation.current) return;
      const media = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
      if (run !== generation.current) { media.getTracks().forEach(track => track.stop()); return; }
      stream.current = media;
      media.getTracks().forEach(track => track.addEventListener('ended', () => { if (run === generation.current) { stop(); onPhoto(null); setError('Your camera was disconnected. Reconnect it and try again.'); } }, { once: true }));
      setActive(true); setBusy(false);
    } catch (err) { if (run === generation.current) { stop(); setError(err.response?.data?.error || (!navigator.mediaDevices?.getUserMedia ? err.message : 'Camera access is required to view an original. Check camera permission and try again.')); } }
  };
  useEffect(() => { if (active && video.current) { video.current.srcObject = stream.current; video.current.play().catch(() => {}); } }, [active]);
  const capture = () => {
    const source = video.current;
    if (!source?.videoWidth || !source.videoHeight) return;
    try {
      const canvas = document.createElement('canvas'), scale = Math.min(1, 640 / Math.max(source.videoWidth, source.videoHeight));
      canvas.width = Math.round(source.videoWidth * scale); canvas.height = Math.round(source.videoHeight * scale);
      if (Math.min(canvas.width, canvas.height) < 120) throw new Error('The camera image is too small. Choose a camera with a higher resolution.');
      canvas.getContext('2d').drawImage(source, 0, 0, canvas.width, canvas.height);
      const data = canvas.toDataURL('image/jpeg', 0.85); stop(); setPreview(data); onPhoto(data.split(',')[1]);
    } catch (err) { stop(); onPhoto(null); setError(err.message || 'Could not capture your photo. Please try again.'); }
  };
  return <div className="viewer-photo"><p>Your photo will be encrypted and kept with the access audit. It records who presented themselves; it is not automatic identity verification.</p><button type="button" disabled={disabled || busy || active} onClick={start}>{preview ? 'Retake viewer photo' : 'Start viewer camera'}</button>{busy && <><p role="status">Preparing secure camera access…</p><button type="button" onClick={stop}>Cancel camera request</button></>}{active && <><video className="capture-preview" ref={video} autoPlay muted playsInline onLoadedData={() => setReady(true)} /><button type="button" disabled={disabled || !ready} onClick={capture}>Capture my photo</button><button type="button" onClick={stop}>Cancel camera</button></>}{preview && <img className="viewer-photo-preview" src={preview} alt="Your photo for this access audit" />}{error && <p role="alert">{error}</p>}</div>;
}

export default function OriginalAccess({ api, caseId, file, authority, onClose, onAudit, onReprocess }) {
  const [key, setKey] = useState(''), [reason, setReason] = useState(''), [reference, setReference] = useState(''), [challenge, setChallenge] = useState(''), [photo, setPhoto] = useState(null), [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState(''), [view, setView] = useState(null);
  const [challengeExpiresAt, setChallengeExpiresAt] = useState(0), [notice, setNotice] = useState('');
  const generation = useRef(0), request = useRef(null);
  useEffect(() => {
    const clear = () => { generation.current++; request.current?.abort(); setView(null); setKey(''); setPhoto(null); setChallenge(''); setChallengeExpiresAt(0); setAttempt(value => value + 1); setBusy(false); };
    const hide = () => { if (document.hidden) clear(); };
    document.addEventListener('visibilitychange', hide);
    window.addEventListener('pagehide', clear);
    return () => { generation.current++; request.current?.abort(); document.removeEventListener('visibilitychange', hide); window.removeEventListener('pagehide', clear); };
  }, []);
  const route = `${api}/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(file.name)}`;
  const config = { headers: { Authorization: `Bearer ${authority.token}` } };
  useEffect(() => {
    if (!view) return;
    const close = () => { setView(null); setNotice('The restricted preview has closed. Request access again to reopen it.'); };
    const hide = () => { if (document.hidden) close(); };
    const timer = setTimeout(close, 5 * 60 * 1000);
    document.addEventListener('visibilitychange', hide);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', hide); URL.revokeObjectURL(view.url); };
  }, [view]);
  useEffect(() => {
    if (!challengeExpiresAt) return;
    const timer = setTimeout(() => {
      setChallenge(''); setPhoto(null); setChallengeExpiresAt(0); setAttempt(value => value + 1);
      setNotice('The camera access window expired. Start the viewer camera again to take a fresh photo.');
    }, Math.max(0, challengeExpiresAt - Date.now()));
    return () => clearTimeout(timer);
  }, [challengeExpiresAt]);
  const startChallenge = async signal => {
    const run = generation.current;
    const startedAt = Date.now();
    setChallenge(''); setChallengeExpiresAt(0); setNotice(''); setError('');
    const { data } = await axios.post(route + '/viewer-challenge', {}, { ...config, signal });
    if (signal.aborted || run !== generation.current || document.hidden) return;
    setChallenge(data.challenge);
    setChallengeExpiresAt(startedAt + Math.min(120, Number(data.expiresInSeconds) || 120) * 1000);
  };
  const open = async e => {
    e.preventDefault(); if (busy || !photo || !challenge) return;
    if (!key.trim() || reason.trim().length < 20 || reference.trim().length < 3) { setError('Enter your personal key, a reference of at least 3 characters, and a reason of at least 20 characters.'); return; }
    const retryMasking = e.nativeEvent.submitter?.value === 'reprocess';
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(''); setNotice(''); setChallengeExpiresAt(0);
    const run = generation.current;
    try {
      const { data } = await axios.post(route + '/original-access', { key: key.trim(), challenge, photo, reason: reason.trim(), orderReference: reference.trim() }, { ...config, signal: controller.signal });
      if (run !== generation.current || document.hidden) return;
      if (retryMasking) { await onReprocess(file, data.grant); if (run !== generation.current) return; onClose(); }
      else {
        const response = await axios.get(route + '?original=1', { responseType: 'blob', headers: { ...config.headers, 'X-Original-Grant': data.grant }, signal: controller.signal });
        if (run !== generation.current || document.hidden) return;
        const blob = new Blob([response.data], { type: file.mime });
        const text = file.mime === 'text/plain' ? await blob.text() : null;
        if (run !== generation.current || document.hidden) return;
        setView({ url: URL.createObjectURL(blob), accessId: data.accessId, text, time: new Date().toLocaleString() });
      }
      onAudit();
    } catch (err) { if (run === generation.current && !controller.signal.aborted) setError(err.response?.data?.error || 'Original access failed. Retake your photo and try again.'); }
    finally { if (run === generation.current) { setKey(''); setPhoto(null); setChallenge(''); setAttempt(value => value + 1); setBusy(false); } }
  };
  return <div className="original-access-form">
    {view ? <>
      <div className="original-viewer" onContextMenu={event => event.preventDefault()}>
        {file.mime.startsWith('video/') ? <video src={view.url} controls playsInline controlsList="nodownload" disablePictureInPicture /> : file.mime.startsWith('audio/') ? <audio src={view.url} controls controlsList="nodownload" /> : file.mime.startsWith('image/') ? <img src={view.url} alt="Restricted original evidence" /> : file.mime === 'text/plain' ? <pre>{view.text}</pre> : <iframe src={view.url} title="Restricted original evidence" sandbox="" />}
        <div className="viewer-watermark">RESTRICTED · {authority.user.username}<br />{view.time}<br />Access {view.accessId}</div>
      </div>
      <p>Access recorded. This preview closes after five minutes or when you leave the tab. Copying or sharing evidence remains your responsibility.</p>
      <button type="button" onClick={onClose}>Close original</button>
    </> : <form onSubmit={open} aria-busy={busy}>
      <h4>View original — recorded access</h4>
      <label>Your personal access key<input type="password" autoComplete="off" value={key} maxLength={256} required disabled={busy} onChange={e => setKey(e.target.value)} /></label>
      <label>Court order / case reference<input value={reference} minLength={3} maxLength={160} required disabled={busy} onChange={e => setReference(e.target.value)} /></label>
      <label>Reason for access (20–500 characters)<textarea value={reason} minLength={20} maxLength={500} required disabled={busy} onChange={e => setReason(e.target.value)} /></label>
      <ViewerPhoto key={attempt} startChallenge={startChallenge} onPhoto={setPhoto} disabled={busy} />
      {photo && !busy && <p>Submit within two minutes of starting the camera. If it expires, take a fresh photo.</p>}
      <div className="evidence-actions">
        <button disabled={busy || !photo || !challenge}>{busy ? 'Checking access…' : 'Record access and view original'}</button>
        {!file.maskedCopyAvailable && !['QUEUED', 'PROCESSING', 'RETRY_WAIT'].includes(file.processingStatus) && file.mime !== 'application/pdf' && <button value="reprocess" disabled={busy || !photo || !challenge}>Record access and retry masking</button>}
        <button type="button" disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
