import React, { useEffect, useRef, useState } from 'react';
import axios, { API } from './api';

const randomKey = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export default function ReporterSafety({ record, recoverySecret, onUpdated, onRotated, onDeleted, onBusy }) {
  const [mode, setMode] = useState(''), [confirmation, setConfirmation] = useState('');
  const [replacementKey, setReplacementKey] = useState(''), [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [older, setOlder] = useState([]), [olderBefore, setOlderBefore] = useState(undefined);
  const attempt = useRef(null), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const credentials = { caseId: record.id, recoverySecret };
  const alerts = record.accessAlerts;
  const activity = async (route, extra = {}) => {
    setBusy(true); onBusy(true); setError('');
    try {
      const { data } = await axios.post(`${API}/track/${route}`, { ...credentials, ...extra });
      if (!mounted.current) return;
      if (route === 'alerts') { setOlder(current => [...current, ...data.case.accessAlerts.events]); setOlderBefore(data.case.accessAlerts.olderBefore); }
      else onUpdated(data.case);
    } catch (err) { if (mounted.current) setError(err.response?.data?.error || 'The request could not complete. Please retry.'); }
    finally { if (mounted.current) { setBusy(false); onBusy(false); } }
  };
  const choose = value => {
    if (attempt.current) return;
    setMode(value); setConfirmation(''); setSaved(false); setError(''); setNotice('');
    setReplacementKey(value === 'rotate' ? randomKey() : '');
  };
  const emergency = async event => {
    event.preventDefault();
    if (busy || confirmation !== record.id || (mode === 'rotate' && !saved)) return;
    if (!attempt.current) attempt.current = { ...credentials, mode, confirmation, operationToken: randomKey(), ...(mode === 'rotate' ? { replacementKey } : {}) };
    setBusy(true); onBusy(true); setError('');
    try {
      const { data } = await axios.post(`${API}/track/emergency`, attempt.current);
      if (!mounted.current) return;
      const completed = attempt.current;
      attempt.current = null;
      if (data.mode === 'delete') onDeleted(data.cleanupPending);
      else {
        await onRotated(completed.replacementKey);
        setMode(''); setReplacementKey(''); setConfirmation(''); setSaved(false);
        setNotice(`Case contents and evidence now use a new encryption key. Your old recovery key is invalid. Authority review is paused.${data.cleanupPending ? ' Removal of retired encrypted objects is pending and will retry automatically.' : ''}`);
      }
    } catch (err) {
      if (mounted.current) {
        const rejected = [400, 401, 403, 409, 422].includes(err.response?.status);
        if (rejected) attempt.current = null;
        setError(rejected ? (err.response?.data?.error || 'The action was rejected.') : `${err.response?.data?.error || 'The outcome could not be confirmed.'} Retry this same action. For key replacement, keep the new key you saved; it may already be active.`);
      }
    } finally { if (mounted.current) { setBusy(false); onBusy(false); } }
  };
  const olderCursor = olderBefore === undefined ? alerts?.olderBefore : olderBefore;
  const events = [...(alerts?.events || []), ...older].filter((event, index, all) => all.findIndex(item => item.id === event.id) === index);
  return <section className="reporter-safety" aria-label="Reporter security controls">
    <h3>Access alerts</h3>
    <p className="access-alert-count" role="status" aria-live="polite">{alerts?.unread ? `${alerts.unread} unreviewed access alert${alerts.unread === 1 ? '' : 's'}` : 'No unreviewed access alerts'} · {alerts?.total || 0} recorded</p>
    <p>While this case is open, alerts refresh every 10 seconds. Access while you are away is saved for your next visit. Closed-browser push and email are not enabled.</p>
    {events.length > 0 && <ol className="access-alert-list">{events.map(event => <li key={event.id}>
      <strong>{event.action.replaceAll('_', ' ').toLowerCase()}</strong><span>{event.actor} · {event.role}</span><time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
    </li>)}</ol>}
    <div className="evidence-actions">
      {!!alerts?.unread && <button type="button" disabled={busy} onClick={() => activity('alerts/ack', { through: alerts.total })}>Mark these alerts reviewed</button>}
      {olderCursor && <button type="button" disabled={busy} onClick={() => activity('alerts', { before: olderCursor })}>Load older access alerts</button>}
    </div>
    {record.reviewLocked && <div className="review-paused" role="status"><strong>Authority review is paused.</strong><p>You can read your case with your replacement recovery key. Resume only when you want authorized reviewers to access it again.</p><button disabled={busy} type="button" onClick={() => activity('resume')}>Resume authority review</button></div>}
    <details className="emergency-controls">
      <summary>Emergency controls (death switch)</summary>
      <p>If access looks suspicious, choose one of the actions below. Anyone holding your Case ID and recovery key can use these controls.</p>
      <div className="evidence-actions"><button type="button" disabled={busy || !!attempt.current} onClick={() => choose('rotate')}>Replace keys and pause access</button><button type="button" disabled={busy || !!attempt.current} onClick={() => choose('delete')}>Delete complaint</button></div>
      {mode && <form onSubmit={emergency}>
        <h4>{mode === 'delete' ? 'Delete complaint and evidence' : 'Replace the case keys'}</h4>
        <p>{mode === 'delete' ? 'Removes the live complaint, messages and evidence, and revokes download grants. This cannot be undone in the app. A minimal deletion record and signed audit history remain.' : 'Re-encrypts the complaint, messages and evidence, invalidates the old recovery key, revokes download grants and pauses authority review. Save the new key before continuing.'}</p>
        <p>Previously downloaded copies and provider backups cannot be recalled by this action.</p>
        {mode === 'rotate' && <>
          <label>New recovery key<input type="text" readOnly spellCheck={false} autoComplete="off" value={replacementKey} /></label>
          <label className="saved-key-check"><input type="checkbox" checked={saved} disabled={busy || !!attempt.current} onChange={event => setSaved(event.target.checked)} />I have saved this new key privately.</label>
        </>}
        <label>Type your Case ID to confirm<input autoComplete="off" spellCheck={false} value={confirmation} disabled={busy || !!attempt.current} onChange={event => setConfirmation(event.target.value)} placeholder={record.id} required /></label>
        <button type="submit" disabled={busy || confirmation !== record.id || (mode === 'rotate' && !saved)}>{busy ? 'Applying secure action…' : attempt.current ? 'Retry the same secure action' : mode === 'delete' ? 'Permanently delete live complaint' : 'Re-encrypt and replace keys'}</button>
        <button type="button" disabled={busy || !!attempt.current} onClick={() => choose('')}>Cancel emergency action</button>
      </form>}
    </details>
    {notice && <p role="status">{notice}</p>}{error && <p role="alert" className="inline-warning">{error}</p>}
  </section>;
}
