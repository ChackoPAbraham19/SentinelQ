import React, { useEffect, useRef, useState } from 'react';
import axios, { API } from './api';

export function reviewerPermissions(role) {
  return {
    edit: ['ADMIN', 'CASE_MANAGER'].includes(role),
    notes: ['ADMIN', 'CASE_MANAGER', 'INVESTIGATOR'].includes(role),
    readChat: ['ADMIN', 'CASE_MANAGER', 'INVESTIGATOR', 'COURT'].includes(role),
    writeChat: ['ADMIN', 'CASE_MANAGER', 'INVESTIGATOR'].includes(role),
    audit: ['ADMIN', 'AUDITOR'].includes(role),
  };
}

export default function CaseActions({ record, role, onUpdated }) {
  const permissions = reviewerPermissions(role);
  const [status, setStatus] = useState(record.status), [priority, setPriority] = useState(record.priority);
  const [investigators, setInvestigators] = useState([]), [assigned, setAssigned] = useState(record.assignedTo?.[0] || '');
  const [directoryError, setDirectoryError] = useState(''), [directoryLoading, setDirectoryLoading] = useState(false);
  const [note, setNote] = useState(''), [busy, setBusy] = useState(''), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setStatus(record.status); setPriority(record.priority); setAssigned(record.assignedTo?.[0] || ''); }, [record.status, record.priority, record.assignedTo?.[0]]);
  const directory = async () => {
    setDirectoryLoading(true); setDirectoryError('');
    try { const { data } = await axios.get(`${API}/authorities/investigators`); if (mounted.current) setInvestigators(data.investigators || []); }
    catch (err) { if (mounted.current) setDirectoryError(err.response?.data?.error || 'Investigator list could not load.'); }
    finally { if (mounted.current) setDirectoryLoading(false); }
  };
  useEffect(() => { if (permissions.edit) directory(); }, [permissions.edit]);
  const save = async (kind, body) => {
    if (busy) return;
    setBusy(kind); setError(''); setNotice('');
    try {
      const { data } = await axios.post(`${API}/cases/${encodeURIComponent(record.id)}/${kind}`, body);
      if (!mounted.current) return;
      onUpdated(data.case || { id: record.id, notes: data.notes });
      if (kind === 'notes') setNote('');
      setNotice({ status: 'Status and priority saved.', assign: 'Investigator assignment saved.', notes: 'Internal note saved.' }[kind]);
    } catch (err) { if (mounted.current) setError(err.response?.data?.error || 'Changes could not be saved. Your input is still here; refresh and try again.'); }
    finally { if (mounted.current) setBusy(''); }
  };
  const exportSummary = async () => {
    setBusy('summary'); setError(''); setNotice('');
    try {
      const { data } = await axios.get(`${API}/cases/${encodeURIComponent(record.id)}/summary`);
      if (!mounted.current) return;
      const url = URL.createObjectURL(new Blob([data.summary], { type: 'text/plain;charset=utf-8' }));
      const link = document.createElement('a'); link.href = url; link.download = `${record.id}-summary.txt`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice('Summary downloaded. Store the file securely.');
    } catch (err) { if (mounted.current) setError(err.response?.data?.error || 'Summary could not be downloaded.'); }
    finally { if (mounted.current) setBusy(''); }
  };
  return <section className="case-actions-panel" aria-label="Case management">
    <h3>Case management</h3>
    {permissions.edit ? <>
      <form className="case-action-form" onSubmit={e => { e.preventDefault(); save('status', { status, priority }); }}>
        <label>Case status<select value={status} disabled={!!busy} onChange={e => setStatus(e.target.value)}>{['Open', 'In Review', 'Closed'].map(value => <option key={value}>{value}</option>)}</select></label>
        <label>Priority<select value={priority} disabled={!!busy} onChange={e => setPriority(e.target.value)}>{['Low', 'Medium', 'High'].map(value => <option key={value}>{value}</option>)}</select></label>
        <button disabled={!!busy || (status === record.status && priority === record.priority)}>{busy === 'status' ? 'Saving…' : 'Save status and priority'}</button>
      </form>
      <form className="case-action-form" onSubmit={e => { e.preventDefault(); save('assign', { username: assigned || null }); }}>
        <label>Assigned investigator<select value={assigned} disabled={!!busy || directoryLoading || !!directoryError} onChange={e => setAssigned(e.target.value)}>
          <option value="">Unassigned</option>{investigators.map(item => <option key={item.username} value={item.username}>{item.username}</option>)}
        </select></label>
        <button disabled={!!busy || directoryLoading || !!directoryError || assigned === (record.assignedTo?.[0] || '')}>{busy === 'assign' ? 'Saving…' : 'Save assignment'}</button>
      </form>
      {directoryLoading && <p role="status">Loading investigators…</p>}
      {directoryError && <p role="alert">{directoryError} <button type="button" onClick={directory}>Retry investigator list</button></p>}
    </> : <p className="muted">Status and assignments are managed by an administrator or case manager.</p>}
    <button className="quiet-button" type="button" disabled={!!busy} onClick={exportSummary}>{busy === 'summary' ? 'Preparing summary…' : 'Download case summary'}</button>
    {permissions.notes && <div className="internal-notes">
      <h3>Internal notes</h3><p className="muted">Visible to the review team. These notes are not sent to the reporter or court viewers.</p>
      {(record.notes || []).length ? <ul>{record.notes.map(item => <li key={item.id}><small>{item.author} · {new Date(item.createdAt).toLocaleString()}</small><p>{item.text}</p></li>)}</ul> : <p className="muted">No internal notes yet.</p>}
      <form onSubmit={e => { e.preventDefault(); if (note.trim()) save('notes', { text: note.trim() }); }}>
        <label>New internal note<textarea value={note} maxLength={4000} required disabled={!!busy} onChange={e => setNote(e.target.value)} /></label>
        <button disabled={!!busy || !note.trim()}>{busy === 'notes' ? 'Saving…' : 'Save internal note'}</button>
      </form>
    </div>}
    {notice && <p className="action-notice" role="status">{notice}</p>}
    {error && <p className="inline-warning" role="alert">{error}</p>}
  </section>;
}
