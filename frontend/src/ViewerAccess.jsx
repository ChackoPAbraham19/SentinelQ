import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';

export function AuditPhoto({ api, event, token }) {
  const [url, setUrl] = useState(''), [error, setError] = useState('');
  useEffect(() => () => { if (url) URL.revokeObjectURL(url); }, [url]);
  const show = async () => {
    if (url) { setUrl(''); return; }
    try { const response = await axios.get(`${api}/access-audits/${event.accessId}/photo`, { responseType: 'blob', headers: { Authorization: `Bearer ${token}` } }); setUrl(URL.createObjectURL(response.data)); }
    catch { setError('Viewer photo unavailable.'); }
  };
  return <div><small>Viewer: {event.actor} ({event.role}) · {event.orderReference} · {event.reason}</small><button type="button" onClick={show}>{url ? 'Hide viewer photo' : 'Review viewer photo'}</button>{url && <img className="viewer-photo-preview" src={url} alt={`Recorded photo for ${event.actor}, access ${event.accessId}`} />}{error && <p role="alert">{error}</p>}</div>;
}

export function ViewerAccount({ api, authority }) {
  const [configured, setConfigured] = useState(null);
  const [password, setPassword] = useState('');
  const [key, setKey] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [court, setCourt] = useState({ username: '', password: '' });
  const [created, setCreated] = useState('');
  const config = { headers: { Authorization: `Bearer ${authority.token}` } };
  useEffect(() => { axios.get(`${api}/viewer-key`, config).then(res => setConfigured(res.data.configured)).catch(() => setError('Could not load personal key status.')); }, [authority.token]);
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
  return <section className="surface-panel custody-panel">
    <h2>Your original-access key</h2>
    <p>Reporters submit evidence without a key. To view an original, you must enter your own key and take a camera photo. Each access is recorded against your account.</p>
    {configured === false && <form onSubmit={createKey}><label>Confirm your account password<input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label><button disabled={busy}>Create my personal key</button></form>}
    {configured && !key && <p>Your key is configured. Use your saved key when requesting an original.</p>}
    {key && <div role="status"><strong>Save this key securely. It is shown only once and cannot be recovered.</strong><label>Your personal access key<input readOnly value={key} onFocus={e => e.target.select()} /></label><button type="button" onClick={() => setKey('')}>I have saved my key</button></div>}
    {authority.user.role === 'ADMIN' && <details><summary>Create a court login</summary><p>Create a separate account for each court viewer so access is attributable to a person. Deliver login credentials through your approved secure channel.</p><form onSubmit={createCourt}><label>Court viewer username<input pattern="[a-z][a-z0-9_-]{2,63}" required value={court.username} onChange={e => setCourt({ ...court, username: e.target.value })} /></label><label>Initial password (at least 16 characters)<input type="password" autoComplete="new-password" minLength={16} maxLength={256} required value={court.password} onChange={e => setCourt({ ...court, password: e.target.value })} /></label><button disabled={busy}>Create court login</button></form></details>}
    {created && <p role="status">{created}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}

export function ViewerPhoto({ startChallenge, onPhoto }) {
  const video = useRef(null), stream = useRef(null), generation = useRef(0);
  const [active, setActive] = useState(false), [ready, setReady] = useState(false), [busy, setBusy] = useState(false), [preview, setPreview] = useState(''), [error, setError] = useState('');
  const stop = () => { generation.current++; stream.current?.getTracks().forEach(track => track.stop()); stream.current = null; setActive(false); setReady(false); setBusy(false); };
  useEffect(() => {
    const background = () => { if (document.hidden) { stop(); onPhoto(null); setPreview(''); } };
    document.addEventListener('visibilitychange', background);
    window.addEventListener('pagehide', background);
    return () => { generation.current++; stream.current?.getTracks().forEach(track => track.stop()); document.removeEventListener('visibilitychange', background); window.removeEventListener('pagehide', background); };
  }, []);
  const start = async () => {
    stop(); onPhoto(null); setPreview(''); setError(''); setBusy(true);
    const run = generation.current;
    try {
      await startChallenge();
      if (run !== generation.current) return;
      const media = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
      if (run !== generation.current) { media.getTracks().forEach(track => track.stop()); return; }
      stream.current = media; setActive(true); setBusy(false);
    } catch (err) { if (run === generation.current) { stop(); setError(err.response?.data?.error || 'Camera access is required to view an original. Check camera permission and try again.'); } }
  };
  useEffect(() => { if (active && video.current) { video.current.srcObject = stream.current; video.current.play().catch(() => {}); } }, [active]);
  const capture = () => {
    const source = video.current;
    if (!source?.videoWidth || !source.videoHeight) return;
    const canvas = document.createElement('canvas'), scale = Math.min(1, 640 / Math.max(source.videoWidth, source.videoHeight));
    canvas.width = Math.round(source.videoWidth * scale); canvas.height = Math.round(source.videoHeight * scale);
    canvas.getContext('2d').drawImage(source, 0, 0, canvas.width, canvas.height);
    const data = canvas.toDataURL('image/jpeg', 0.85); stop(); setPreview(data); onPhoto(data.split(',')[1]);
  };
  return <div className="viewer-photo"><p>Your photo will be encrypted and kept with the access audit. It records who presented themselves; it is not automatic identity verification.</p><button type="button" disabled={busy || active} onClick={start}>{preview ? 'Retake viewer photo' : 'Start viewer camera'}</button>{busy && <button type="button" onClick={stop}>Cancel camera request</button>}{active && <><video className="capture-preview" ref={video} autoPlay muted playsInline onLoadedData={() => setReady(true)} /><button type="button" disabled={!ready} onClick={capture}>Capture my photo</button><button type="button" onClick={stop}>Cancel camera</button></>}{preview && <img className="viewer-photo-preview" src={preview} alt="Your photo for this access audit" />}{error && <p role="alert">{error}</p>}</div>;
}

export default function OriginalAccess({ api, caseId, file, authority, onClose, onAudit, onReprocess }) {
  const [key, setKey] = useState(''), [reason, setReason] = useState(''), [reference, setReference] = useState(''), [challenge, setChallenge] = useState(''), [photo, setPhoto] = useState(null), [attempt, setAttempt] = useState(0), [busy, setBusy] = useState(false), [error, setError] = useState(''), [view, setView] = useState(null);
  const route = `${api}/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(file.name)}`;
  const config = { headers: { Authorization: `Bearer ${authority.token}` } };
  useEffect(() => {
    if (!view) return;
    const close = () => setView(null);
    const hide = () => { if (document.hidden) close(); };
    const timer = setTimeout(close, 5 * 60 * 1000);
    document.addEventListener('visibilitychange', hide);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', hide); URL.revokeObjectURL(view.url); };
  }, [view]);
  const startChallenge = async () => { const { data } = await axios.post(route + '/viewer-challenge', {}, config); setChallenge(data.challenge); };
  const open = async e => {
    e.preventDefault(); if (!photo || !challenge) return;
    setBusy(true); setError('');
    try {
      const { data } = await axios.post(route + '/original-access', { key, challenge, photo, reason, orderReference: reference }, config);
      if (e.nativeEvent.submitter?.value === 'reprocess') { await onReprocess(file, data.grant); onClose(); }
      else {
        const response = await axios.get(route + '?original=1', { responseType: 'blob', headers: { ...config.headers, 'X-Original-Grant': data.grant } });
        const blob = new Blob([response.data], { type: file.mime });
        setView({ url: URL.createObjectURL(blob), accessId: data.accessId, text: file.mime === 'text/plain' ? await blob.text() : null, time: new Date().toLocaleString() });
      }
      onAudit();
    } catch (err) { setError(err.response?.data?.error || 'Original access failed. Retake your photo and try again.'); }
    finally { setKey(''); setPhoto(null); setChallenge(''); setAttempt(value => value + 1); setBusy(false); }
  };
  return <div className="original-access-form">
    {view ? <><div className="original-viewer" onContextMenu={event => event.preventDefault()}>{file.mime.startsWith('video/') ? <video src={view.url} controls playsInline controlsList="nodownload" disablePictureInPicture /> : file.mime.startsWith('audio/') ? <audio src={view.url} controls controlsList="nodownload" /> : file.mime.startsWith('image/') ? <img src={view.url} alt="Restricted original evidence" /> : file.mime === 'text/plain' ? <pre>{view.text}</pre> : <iframe src={view.url} title="Restricted original evidence" sandbox="" />}<div className="viewer-watermark">RESTRICTED · {authority.user.username}<br />{view.time}<br />Access {view.accessId}</div></div><p>Access recorded. This preview closes after five minutes or when you leave the tab. Copying or sharing evidence remains your responsibility.</p><button type="button" onClick={onClose}>Close original</button></> : <form onSubmit={open}><h4>View original — recorded access</h4><label>Your personal access key<input type="password" autoComplete="off" value={key} maxLength={256} required onChange={e => setKey(e.target.value)} /></label><label>Court order / case reference<input value={reference} minLength={3} maxLength={160} required onChange={e => setReference(e.target.value)} /></label><label>Reason for access<textarea value={reason} minLength={20} maxLength={500} required onChange={e => setReason(e.target.value)} /></label><ViewerPhoto key={attempt} startChallenge={startChallenge} onPhoto={setPhoto} /><div className="evidence-actions"><button disabled={busy || !photo || !challenge}>{busy ? 'Checking access…' : 'Record access and view original'}</button>{!file.maskedCopyAvailable && file.mime !== 'application/pdf' && <button value="reprocess" disabled={busy || !photo || !challenge}>Record access and retry masking</button>}<button type="button" disabled={busy} onClick={onClose}>Cancel</button></div></form>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
