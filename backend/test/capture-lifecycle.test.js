'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const capture = import('../../frontend/src/capture.mjs');

function fixture({ stopFails = false } = {}) {
  const state = { stopped: 0, states: [], errors: [], files: [] };
  const track = new EventTarget();
  track.stop = () => { state.stopped++; };
  const stream = { getTracks: () => [track] };
  class Recorder {
    static isTypeSupported(mime) { return mime.includes('webm'); }
    constructor(_, options) { state.recorder = this; this.state = 'inactive'; this.mimeType = options.mimeType; }
    start() { this.state = 'recording'; }
    stop() {
      if (stopFails) throw new Error('The recording device disconnected.');
      this.state = 'inactive';
      queueMicrotask(() => this.onstop?.());
    }
    emit() { this.ondataavailable?.({ data: new Blob(['test recording']) }); }
  }
  return { state, stream, track, settings: {
    mediaDevices: { getUserMedia: async () => stream }, Recorder,
    onState: value => state.states.push(value), onStream: () => {},
    onCapture: value => state.files.push(value), onError: value => state.errors.push(value)
  } };
}

test('recording completion removes device listeners so late device events preserve the review', async () => {
  const { CaptureSession } = await capture;
  const { state, track, settings } = fixture();
  const session = new CaptureSession(settings);
  await session.start('audio');
  state.recorder.emit();
  session.stop();
  await new Promise(resolve => setImmediate(resolve));
  track.dispatchEvent(new Event('ended'));
  assert.equal(state.states.at(-1), 'review');
  assert.equal(state.files.length, 1);
  assert.deepEqual(state.errors, []);
  assert.equal(state.stopped, 1);
  session.cancel();
});

test('recorder stop errors release the microphone and leave capture ready for retry', async () => {
  const { CaptureSession } = await capture;
  const { state, settings } = fixture({ stopFails: true });
  const session = new CaptureSession(settings);
  await session.start('audio');
  assert.doesNotThrow(() => session.stop());
  assert.equal(state.stopped, 1);
  assert.equal(state.states.at(-1), 'idle');
  assert.equal(state.errors.length, 1);
  assert.equal(state.files.length, 0);
});

test('cancelling a faulty recorder still releases device tracks without creating a capture', async () => {
  const { CaptureSession } = await capture;
  const { state, track, settings } = fixture({ stopFails: true });
  const session = new CaptureSession(settings);
  await session.start('video');
  assert.doesNotThrow(() => session.cancel());
  track.dispatchEvent(new Event('ended'));
  assert.equal(state.stopped, 1);
  assert.equal(state.states.at(-1), 'idle');
  assert.deepEqual(state.errors, []);
  assert.deepEqual(state.files, []);
});

test('a newer camera request wins when older permissions resolve after restarting capture', async () => {
  const { CaptureSession } = await capture;
  const old = fixture(), current = fixture();
  let resolveOld;
  let calls = 0;
  const session = new CaptureSession({ ...current.settings, mediaDevices: { getUserMedia: () => ++calls === 1 ? new Promise(resolve => { resolveOld = resolve; }) : Promise.resolve(current.stream) } });
  const oldRequest = session.start('photo');
  await session.start('photo');
  resolveOld(old.stream);
  await oldRequest;
  assert.equal(old.state.stopped, 1);
  assert.equal(current.state.stopped, 0);
  assert.equal(session.stream, current.stream);
  assert.equal(current.state.states.at(-1), 'camera');
  session.cancel();
  assert.equal(current.state.stopped, 1);
});
