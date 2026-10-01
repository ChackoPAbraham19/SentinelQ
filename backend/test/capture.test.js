const test = require('node:test');
const assert = require('node:assert/strict');
const capture = import('../../frontend/src/capture.mjs');

function fixture(options = {}) {
  const state = { tracksStopped: 0, states: [], captures: [], errors: [], streams: [] };
  const track = { stop: () => state.tracksStopped++, addEventListener: (event, callback) => { state.interrupted = callback; } };
  const stream = { getTracks: () => [track] };
  class Recorder {
    static isTypeSupported(mime) { return mime.includes('webm'); }
    constructor(source, settings) { state.recorder = this; this.state = 'inactive'; this.mimeType = settings.mimeType; }
    start() { this.state = 'recording'; }
    stop() { this.state = 'inactive'; queueMicrotask(() => this.onstop?.()); }
    emit(bytes = 'recorded-media') { this.ondataavailable?.({ data: new Blob([bytes], { type: this.mimeType }) }); }
  }
  return { state, stream, settings: { mediaDevices: { getUserMedia: async constraints => { state.constraints = constraints; return stream; } }, Recorder, onState: value => state.states.push(value), onStream: value => state.streams.push(value), onCapture: value => state.captures.push(value), onError: value => state.errors.push(value), ...options } };
}

test('microphone capture produces a correctly named WebM audio file and stops device tracks', async () => {
  const { CaptureSession } = await capture;
  const { state, settings } = fixture();
  const session = new CaptureSession(settings);
  await session.start('audio');
  assert.deepEqual(state.constraints, { video: false, audio: true });
  state.recorder.emit();
  session.stop();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(state.tracksStopped, 1);
  assert.equal(state.captures.length, 1);
  assert.match(state.captures[0].name, /\.weba$/);
  assert.equal(await state.captures[0].text(), 'recorded-media');
  assert.equal(state.states.at(-1), 'review');
  session.cancel();
});

test('late camera permission after cancellation closes tracks without recording', async () => {
  const { CaptureSession } = await capture;
  let resolvePermission;
  const { state, stream, settings } = fixture({ mediaDevices: { getUserMedia: () => new Promise(resolve => { resolvePermission = resolve; }) } });
  const session = new CaptureSession(settings);
  const pending = session.start('video');
  session.cancel();
  resolvePermission(stream);
  await pending;
  assert.equal(state.tracksStopped, 1);
  assert.equal(state.recorder, undefined);
  assert.equal(state.captures.length, 0);
  assert.equal(state.states.at(-1), 'idle');
});

test('photo requests no microphone and closing capture stops the camera', async () => {
  const { CaptureSession } = await capture;
  const { state, settings } = fixture();
  const session = new CaptureSession(settings);
  await session.start('photo', 'user');
  assert.equal(state.constraints.audio, false);
  assert.equal(state.constraints.video.facingMode.ideal, 'user');
  assert.equal(state.states.at(-1), 'camera');
  assert.equal(state.recorder, undefined);
  session.cancel();
  assert.equal(state.tracksStopped, 1);
});

test('oversized, interrupted and empty recordings fail closed and release devices', async () => {
  const { CaptureSession } = await capture;
  for (const problem of ['size', 'interrupted', 'empty']) {
    const { state, settings } = fixture({ maxBytes: 4 });
    const session = new CaptureSession(settings);
    await session.start('video');
    if (problem === 'size') state.recorder.emit('12345');
    else if (problem === 'interrupted') state.interrupted();
    else session.stop();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(state.captures.length, 0, problem);
    assert.equal(state.tracksStopped, 1, problem);
    assert.equal(state.errors.length, 1, problem);
    assert.equal(state.states.at(-1), 'idle', problem);
    session.cancel();
  }
});

test('permission refusal and unsupported browsers offer a file upload fallback', async () => {
  const { CaptureSession, recordingFormat } = await capture;
  for (const settingsOverride of [{ mediaDevices: undefined }, { Recorder: undefined }, { mediaDevices: { getUserMedia: async () => { throw { name: 'NotAllowedError' }; } } }]) {
    const { state, settings } = fixture(settingsOverride);
    const session = new CaptureSession(settings);
    await session.start('audio');
    assert.equal(state.states.at(-1), 'idle');
    assert.match(state.errors[0], /file|attach/i);
  }
  const safari = { isTypeSupported: mime => mime.endsWith('/mp4') };
  assert.deepEqual(recordingFormat('audio', safari), ['audio/mp4', 'm4a']);
  assert.deepEqual(recordingFormat('video', safari), ['video/mp4', 'mp4']);
});

test('uploaded and captured evidence share count, format and total-size limits', async () => {
  const { evidenceError, MAX_EVIDENCE_BYTES } = await capture;
  const sample = { name: 'capture.weba', size: 1024 };
  assert.equal(evidenceError([sample, { name: 'photo.jpg', size: 1024 }]), '');
  assert.match(evidenceError(Array(6).fill(sample)), /five/);
  assert.match(evidenceError([{ ...sample, size: MAX_EVIDENCE_BYTES }, sample]), /combined/);
  assert.match(evidenceError([{ ...sample, size: 0 }]), /contain data/);
  assert.match(evidenceError([{ name: 'capture.heic', size: 1024 }]), /JPEG/);
});
