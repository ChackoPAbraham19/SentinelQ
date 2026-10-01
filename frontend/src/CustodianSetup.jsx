import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { generateRecoveryFile, enrollmentProof } from './custodian-crypto.mjs';

export function CustodyAdmin({ api, token }) {
  const [status, setStatus] = useState(null);
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    try { setStatus((await axios.get(`${api}/custody/status`, { headers: { Authorization: `Bearer ${token}` } })).data); setError(''); }
    catch { setError('Could not load evidence protection status.'); }
  };
  useEffect(() => { refresh(); }, [token]);
  const create = async () => {
    setBusy(true);
    try { setInvite((await axios.post(`${api}/custody/invite`, {}, { headers: { Authorization: `Bearer ${token}` } })).data); setError(''); }
    catch (err) { setError(err.response?.data?.error || 'Could not create invitation.'); }
    finally { setBusy(false); }
  };
  return <section className="surface-panel custody-panel">
    <h2>Evidence protection setup</h2>
    {status?.ready ? <><p>Ready. Reporters can attach evidence without providing any key. Original access requires a signed court release.</p><small className="custody-fingerprint">Custodian fingerprint: {status.keyId}</small></> : <>
      <p>Complete this once before accepting evidence. Send a setup invitation to the independent custodian. Their device creates and retains the private recovery key; the platform receives only the public encryption key.</p>
      <button type="button" onClick={create} disabled={busy || !status}>{busy ? 'Creating…' : 'Create custodian invitation'}</button>
      {invite && <div><p>This invitation expires in 30 minutes and replaces any earlier invitation. Share it privately with the designated custodian. Do not complete real custody setup on the admin’s device.</p><label>Custodian setup link<input readOnly value={`${window.location.origin}/#custodian-setup=${invite.token}`} onFocus={e => e.target.select()} /></label></div>}
    </>}
    <button type="button" onClick={refresh}>Refresh setup status</button>
    {error && <p role="alert">{error}</p>}
  </section>;
}

export default function CustodianSetup({ token, api }) {
  const [invitation, setInvitation] = useState(null);
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [backup, setBackup] = useState(null);
  const [recoveryFile, setRecoveryFile] = useState(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [complete, setComplete] = useState(null);
  useEffect(() => {
    document.title = 'Custodian setup | SentinelQ';
    axios.post(`${api}/custody/check`, { token }).then(res => setInvitation(res.data)).catch(() => setError('This invitation is invalid or expired. Ask the administrator for a new invitation.'));
  }, [token]);
  const generate = async e => {
    e.preventDefault(); setError('');
    if (passphrase !== confirmation) { setError('Passphrases do not match.'); return; }
    setBusy(true);
    try { setBackup(await generateRecoveryFile(passphrase)); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'sentinelq-custodian-recovery.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const register = async () => {
    if (!saved || !recoveryFile) return;
    setBusy(true); setError('');
    try {
      if (recoveryFile.size > 16384) throw new Error('Invalid recovery file.');
      const restored = JSON.parse(await recoveryFile.text());
      const proof = await enrollmentProof(restored, passphrase, invitation.challenge);
      const { data } = await axios.post(`${api}/custody/register`, { token, ...proof });
      setComplete(data.keyId); setPassphrase(''); setConfirmation(''); setBackup(null); setRecoveryFile(null);
      window.history.replaceState(null, '', '/');
    } catch (err) { setError(err.response?.data?.error || err.message); }
    finally { setBusy(false); }
  };
  return <main className="custody-setup surface-panel">
    <h1>Custodian setup</h1>
    {complete ? <><p>Setup complete. Evidence submissions are now enabled. Keep the recovery file and passphrase securely backed up, separately from the platform administrator.</p><p className="custody-fingerprint">Public key fingerprint: {complete}</p><p>Compare this fingerprint with the administrator through your agreed independent channel. Use the offline custodian tool to issue releases after reviewing court orders.</p></> : <>
      <p>This is a one-time step for the designated custodian, not for reporters. Your private key and passphrase stay on this device and are never sent to the platform. Only the public encryption key is registered.</p>
      <p>Use your own secured device. Losing the recovery file or passphrase means originals cannot be recovered. Save protected backups before activating uploads.</p>
      {invitation && <>
        <form onSubmit={generate}>
          <label>Recovery passphrase (at least 20 characters)<input type="password" autoComplete="new-password" minLength={20} required value={passphrase} disabled={busy || !!backup} onChange={e => setPassphrase(e.target.value)} /></label>
          {!backup && <label>Confirm recovery passphrase<input type="password" autoComplete="new-password" minLength={20} required value={confirmation} disabled={busy} onChange={e => setConfirmation(e.target.value)} /></label>}
          {!backup && <button type="submit" disabled={busy}>{busy ? 'Creating protected recovery file…' : 'Create recovery file on this device'}</button>}
        </form>
        {backup && <>
          <button type="button" onClick={download}>Save encrypted recovery file</button>
          <label>Select the saved file to verify the backup (read locally only)<input type="file" accept=".json" disabled={busy} onChange={e => setRecoveryFile(e.target.files[0] || null)} /></label>
          <label><input type="checkbox" checked={saved} disabled={busy} onChange={e => setSaved(e.target.checked)} /> I have saved the recovery file and passphrase with protected backups, outside the platform administrator’s control.</label>
          <button type="button" disabled={busy || !saved || !recoveryFile} onClick={register}>{busy ? 'Verifying and activating…' : 'Verify backup and activate evidence submissions'}</button>
        </>}
      </>}
    </>}
    {error && <p className="inline-warning" role="alert">{error}</p>}
  </main>;
}
