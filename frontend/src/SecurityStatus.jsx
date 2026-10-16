import React, { useEffect, useState } from 'react';

export const processingPending = files => files?.some(file => ['QUEUED', 'PROCESSING', 'RETRY_WAIT'].includes(file.processingStatus));
export const evidenceLabel = file => ({
  QUEUED: 'Waiting for secure masking', PROCESSING: 'Masking in progress', RETRY_WAIT: 'Masking will retry automatically',
  COMPLETE: 'Masked review copy ready', FAILED: 'Masking needs reviewer attention', QUARANTINED: 'Quarantined for review',
  NEEDS_MASKING: 'Masking required',
}[file.processingStatus] || 'Review copy unavailable');

export function EvidenceStatus({ files = [] }) {
  if (!files.length) return null;
  return <div className="evidence-status" role="status" aria-live="polite">
    <strong>{processingPending(files) ? 'Your report is received. Evidence masking continues in the background.' : 'Evidence privacy status'}</strong>
    {processingPending(files) && <p>You can leave after saving your Case ID and recovery key. Track your case to check progress.</p>}
    <ul>{files.map((file, index) => <li key={file.id || file.name || index}><span>Evidence {index + 1}</span><strong>{evidenceLabel(file)}</strong></li>)}</ul>
    <p>Originals stay encrypted and restricted. Review copies are available only after masking and integrity checks succeed.</p>
  </div>;
}

export function RecoveryReceipt({ result, onClose }) {
  const [revealed, setRevealed] = useState(false), [copied, setCopied] = useState('');
  useEffect(() => {
    const hide = () => { if (document.hidden) setRevealed(false); };
    const timer = revealed ? setTimeout(() => setRevealed(false), 30000) : null;
    document.addEventListener('visibilitychange', hide);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', hide); };
  }, [revealed]);
  const copy = async () => {
    try { await navigator.clipboard.writeText(`SentinelQ Case ID: ${result.id}\nRecovery key: ${result.recoverySecret}`); setCopied('Copied. Store these details privately; your clipboard may be shared with other apps.'); }
    catch { setCopied('Clipboard unavailable. Reveal the key and save both details manually.'); }
  };
  const downloadReceipt = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.signedReceipt, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = `${result.id}-signed-receipt.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <div className="report-receipt">
    <p>{result.message || 'Your report has been received. Save both details below privately.'}</p>
    <dl><dt>Case ID</dt><dd>{result.id}</dd></dl>
    <label>Recovery key<input className="recovery-key" type={revealed ? 'text' : 'password'} readOnly autoComplete="off" spellCheck={false} value={result.recoverySecret} onFocus={event => event.target.select()} /></label>
    <div className="evidence-actions"><button type="button" onClick={() => setRevealed(value => !value)} aria-pressed={revealed}>{revealed ? 'Hide key' : 'Reveal key for 30 seconds'}</button><button type="button" onClick={copy}>Copy case details</button></div>
    {copied && <p role="status">{copied}</p>}
    {result.signedReceipt && <p><button type="button" onClick={downloadReceipt}>Download signed evidence receipt</button><small> Contains the case reference and evidence hashes, without your recovery key. Keep it privately to verify the original submission later.</small></p>}
    <p className="disclaimer">Anyone with both details can access your case. This key cannot be reset. Save it before closing this receipt.</p>
    <EvidenceStatus files={result.files} />
    <button className="text-action" type="button" onClick={onClose}>I saved my case details — clear this receipt</button>
  </div>;
}
