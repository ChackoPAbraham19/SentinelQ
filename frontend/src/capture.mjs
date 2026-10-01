export const MAX_EVIDENCE_BYTES = 8 * 1024 * 1024;
// Encode file bytes directly: recorded MIME types can contain commas (vp8,opus).
export async function evidenceFileBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32768)));
  }
  return btoa(chunks.join(''));
}

export function evidenceError(files) {
  if (files.length > 5) return 'You can attach up to five evidence files.';
  if (files.some(file => !file.size || file.size > MAX_EVIDENCE_BYTES)) return 'Each evidence file must contain data and be no larger than 8 MiB.';
  if (files.reduce((sum, file) => sum + file.size, 0) > MAX_EVIDENCE_BYTES) return 'Keep the combined evidence size within 8 MiB. Remove a file or make a shorter recording.';
  if (files.some(file => !/\.(jpe?g|png|mp4|webm|weba|wav|mp3|m4a|ogg|pdf|txt)$/i.test(file.name))) return 'Use JPEG, PNG, MP4, WebM, WAV, MP3, M4A, OGG, PDF or TXT evidence.';
  return '';
}
export function recordingFormat(kind, Recorder) {
  const choices = kind === 'audio'
    ? [['audio/webm;codecs=opus', 'weba'], ['audio/mp4', 'm4a'], ['audio/ogg;codecs=opus', 'ogg']]
    : [['video/webm;codecs=vp8,opus', 'webm'], ['video/mp4', 'mp4'], ['video/webm', 'webm']];
  return choices.find(([mime]) => Recorder?.isTypeSupported?.(mime));
}
export function captureError(error) {
  if (['NotAllowedError', 'SecurityError'].includes(error?.name)) return 'Camera or microphone permission was not granted. Allow access in your browser’s site settings, or attach a file instead.';
  if (error?.name === 'NotFoundError') return 'No suitable camera or microphone was found. Attach a file instead.';
  if (['NotReadableError', 'AbortError'].includes(error?.name)) return 'The camera or microphone is unavailable or in use by another app. Close that app and try again.';
  return error?.message || 'Capture failed. Try again or attach a file instead.';
}

// Owns device tracks and recorder callbacks, including permission requests that finish after cancellation.
export class CaptureSession {
  constructor({ mediaDevices, Recorder, onState, onStream, onCapture, onError, maxBytes = MAX_EVIDENCE_BYTES }) {
    Object.assign(this, { mediaDevices, Recorder, onState, onStream, onCapture, onError, maxBytes });
    this.generation = 0;
  }
  releaseDevices() {
    clearTimeout(this.timer);
    this.stream?.getTracks().forEach(track => track.stop());
    this.stream = null;
    this.onStream(null);
  }
  cancel() {
    this.generation++;
    if (this.recorder) {
      this.recorder.ondataavailable = this.recorder.onstop = this.recorder.onerror = null;
      if (this.recorder.state !== 'inactive') this.recorder.stop();
      this.recorder = null;
    }
    this.releaseDevices();
    this.onState('idle');
  }
  fail(error, generation) {
    if (generation !== this.generation) return;
    this.cancel();
    this.onError(captureError(error));
  }
  async start(kind, facingMode = 'environment') {
    this.cancel();
    const generation = this.generation;
    this.onState('requesting');
    try {
      if (!this.mediaDevices?.getUserMedia) throw new Error('Camera capture needs HTTPS and a supported browser. Open this site in Safari or Chrome, or attach a file instead.');
      const format = kind === 'photo' ? null : recordingFormat(kind, this.Recorder);
      if (kind !== 'photo' && !format) throw new Error('This browser cannot record a supported format. Record with your phone’s camera or recorder app, then attach the file.');
      const stream = await this.mediaDevices.getUserMedia({
        video: kind === 'audio' ? false : { facingMode: { ideal: facingMode }, width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: kind !== 'photo'
      });
      if (generation !== this.generation) { stream.getTracks().forEach(track => track.stop()); return; }
      this.stream = stream;
      this.onStream(stream);
      for (const track of stream.getTracks()) track.addEventListener('ended', () => this.fail(new Error('Capture was interrupted. Please try again.'), generation), { once: true });
      if (kind === 'photo') { this.onState('camera'); return; }
      const recorder = new this.Recorder(stream, { mimeType: format[0], audioBitsPerSecond: 64000, ...(kind === 'video' ? { videoBitsPerSecond: 900000 } : {}) });
      this.recorder = recorder;
      const chunks = [];
      let size = 0;
      recorder.ondataavailable = event => {
        if (generation !== this.generation || !event.data.size) return;
        size += event.data.size;
        if (size > this.maxBytes) { chunks.length = 0; this.fail(new Error('Recording exceeded the available evidence size. Make a shorter recording.'), generation); return; }
        chunks.push(event.data);
      };
      recorder.onerror = () => this.fail(new Error('Recording failed. Please try again or attach a file.'), generation);
      recorder.onstop = () => {
        if (generation !== this.generation) return;
        this.recorder = null;
        this.releaseDevices();
        if (!size) { this.fail(new Error('The recording was empty. Please try again.'), generation); return; }
        const file = new File(chunks, `capture-${kind}-${Date.now()}.${format[1]}`, { type: recorder.mimeType || format[0] });
        chunks.length = 0;
        this.onCapture(file);
        this.onState('review');
      };
      recorder.start(250);
      this.onState('recording');
      this.timer = setTimeout(() => this.stop(), kind === 'video' ? 45000 : 120000);
    } catch (error) { this.fail(error, generation); }
  }
  stop() {
    if (this.recorder?.state === 'recording') {
      this.onState('finishing');
      this.recorder.stop();
      this.releaseDevices();
    }
  }
}
