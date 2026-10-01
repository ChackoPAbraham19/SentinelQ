import React, { useEffect, useRef, useState } from 'react';
import { CaptureSession, MAX_EVIDENCE_BYTES } from './capture.mjs';

export default function EvidenceCapture({ onAdd, onBusy, disabled, remainingBytes }) {
  const [state, setState] = useState('idle');
  const [kind, setKind] = useState('photo');
  const [facing, setFacing] = useState('environment');
  const [stream, setStream] = useState(null);
  const [file, setFile] = useState(null);
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [seconds, setSeconds] = useState(0);
  const [cameraReady, setCameraReady] = useState(false);
  const video = useRef(null);
  const session = useRef(null);
  const photoGeneration = useRef(0);

  useEffect(() => {
    const active = new CaptureSession({ mediaDevices: navigator.mediaDevices, Recorder: window.MediaRecorder, onState: setState, onStream: setStream, onCapture: setFile, onError: setError });
    session.current = active;
    const stopForBackground = () => {
      if (document.hidden) { photoGeneration.current++; active.cancel(); }
    };
    const stopForExit = () => { photoGeneration.current++; active.cancel(); };
    document.addEventListener('visibilitychange', stopForBackground);
    window.addEventListener('pagehide', stopForExit);
    return () => {
      photoGeneration.current++;
      active.cancel();
      onBusy(false);
      document.removeEventListener('visibilitychange', stopForBackground);
      window.removeEventListener('pagehide', stopForExit);
    };
  }, []);
  useEffect(() => { onBusy(state !== 'idle' || Boolean(file)); }, [state, file, onBusy]);
  useEffect(() => {
    setCameraReady(false);
    if (video.current) {
      video.current.srcObject = stream;
      if (stream) video.current.play().catch(() => { setError('Tap the camera preview to start it.'); });
    }
  }, [stream]);
  useEffect(() => {
    if (!file) { setUrl(''); return; }
    const next = URL.createObjectURL(file);
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [file]);
  useEffect(() => {
    if (state !== 'recording') return;
    const start = Date.now();
    setSeconds(0);
    const timer = setInterval(() => setSeconds(Math.floor((Date.now() - start) / 1000)), 250);
    return () => clearInterval(timer);
  }, [state]);

  const discard = () => { photoGeneration.current++; session.current?.cancel(); setFile(null); setError(''); };
  const start = nextKind => {
    discard(); setKind(nextKind);
    session.current.maxBytes = Math.min(remainingBytes, MAX_EVIDENCE_BYTES);
    session.current.start(nextKind, facing);
  };
  const takePhoto = () => {
    const source = video.current;
    if (!source?.videoWidth || !source.videoHeight) return;
    const generation = ++photoGeneration.current;
    setState('finishing');
    try {
      const canvas = document.createElement('canvas');
      const scale = Math.min(1, 1600 / Math.max(source.videoWidth, source.videoHeight));
      canvas.width = Math.round(source.videoWidth * scale);
      canvas.height = Math.round(source.videoHeight * scale);
      canvas.getContext('2d').drawImage(source, 0, 0, canvas.width, canvas.height);
      session.current.cancel();
      setState('finishing');
      canvas.toBlob(blob => {
        if (generation !== photoGeneration.current) return;
        if (!blob || blob.size > remainingBytes) { setState('idle'); setError('Photo could not fit within the evidence size limit. Remove another attachment and try again.'); return; }
        setFile(new File([blob], `capture-photo-${Date.now()}.jpg`, { type: 'image/jpeg' }));
        setState('review');
      }, 'image/jpeg', 0.9);
    } catch {
      session.current.cancel();
      setError('The photo could not be captured. Try again or attach a photo instead.');
    }
  };
  const canStart = state === 'idle' && !file && !disabled && remainingBytes > 0;
  return <div className="evidence-capture">
    <h3>Capture evidence on this device</h3>
    <p>Take a photo or record a short clip. Permission is requested only when you start. Nothing is sent until you submit your report.</p>
    <div className="capture-actions">
      <button type="button" disabled={!canStart} onClick={() => start('photo')}>Take photo</button>
      <button type="button" disabled={!canStart} onClick={() => start('video')}>Record video</button>
      <button type="button" disabled={!canStart} onClick={() => start('audio')}>Record audio</button>
    </div>
    {state === 'idle' && !file && <label className="capture-camera-choice">Camera preference<select value={facing} disabled={disabled} onChange={event => setFacing(event.target.value)}><option value="environment">Back camera</option><option value="user">Front camera</option></select></label>}
    <small>Video: up to 45 seconds · Audio: up to 2 minutes · Five files / 8 MiB combined</small>
    {error && <p className="inline-warning" role="alert">{error}</p>}
    {state === 'requesting' && <p role="status">Waiting for camera or microphone permission…</p>}
    {stream && kind !== 'audio' && <video className="capture-preview" ref={video} autoPlay muted playsInline onLoadedData={() => setCameraReady(true)} onClick={() => video.current?.play().catch(() => {})} aria-label="Live camera preview" />}
    {state === 'recording' && <p className="capture-recording" role="status">Recording {kind} · {seconds}s — microphone on{kind === 'video' ? ', camera on' : ''}</p>}
    {state === 'camera' && <button type="button" disabled={!cameraReady} onClick={takePhoto}>Capture photo</button>}
    {state === 'recording' && <button type="button" onClick={() => session.current.stop()}>Stop recording</button>}
    {state === 'finishing' && <p role="status">Preparing preview…</p>}
    {state !== 'idle' && !file && <button type="button" className="text-action" onClick={discard}>Cancel capture</button>}
    {file && <div className="capture-review">
      <strong>Review your capture — original, not yet masked</strong>
      {url && (file.type.startsWith('image/') ? <img className="capture-preview" src={url} alt="Captured evidence preview" /> : file.type.startsWith('video/') ? <video className="capture-preview" src={url} controls playsInline /> : <audio src={url} controls />)}
      <p>After submission, photos and video are blurred, and voices are altered. Spoken names remain audible. The original is encrypted in storage and restricted to authorized viewers with a personal key and recorded photo.</p>
      <div className="capture-actions"><button type="button" disabled={disabled} onClick={() => { if (onAdd([file])) discard(); }}>Use this evidence</button><button type="button" onClick={discard}>Discard</button></div>
    </div>}
  </div>;
}
