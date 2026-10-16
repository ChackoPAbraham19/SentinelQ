'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('browser client scopes tokens, rejects other origins, clears expired sessions and ignores responses after logout', async () => {
  global.window = Object.assign(new EventTarget(), { SENTINELQ_CONFIG: { apiBaseUrl: 'https://sentinelq.example' }, location: { hostname: 'sentinelq.example', origin: 'https://sentinelq.example' } });
  try {
    const { default: client, setToken } = await import('../../frontend/src/api.js');
    const received = [];
    client.defaults.adapter = async config => { received.push(config); return { status: 200, data: {}, config }; };
    setToken('synthetic-session');
    await client.post('https://sentinelq.example/report-base64', {});
    await client.post('https://sentinelq.example/track', {});
    await client.get('https://sentinelq.example/cases');
    await client.post('https://sentinelq.example/cases/CASE-TEST/messages', {}, { headers: { Authorization: null } });
    assert.equal(received[0].headers.get('Authorization'), undefined);
    assert.equal(received[1].headers.get('Authorization'), undefined);
    assert.equal(received[2].headers.get('Authorization'), 'Bearer synthetic-session');
    assert.equal(received[3].headers.get('Authorization'), null);
    await assert.rejects(client.get('https://attacker.example/cases'), /secure API connection/);
    let finish;
    client.defaults.adapter = config => new Promise(resolve => { finish = () => resolve({ status: 200, data: { private: 'case data' }, config }); });
    const outstanding = client.get('https://sentinelq.example/cases');
    await new Promise(resolve => setImmediate(resolve));
    setToken(null); finish();
    await assert.rejects(outstanding, /Session ended/);
    let expired = 0;
    window.addEventListener('sentinelq-session-expired', () => expired++);
    setToken('new-synthetic-session');
    client.defaults.adapter = async config => { const error = new Error('Unauthorized'); error.config = config; error.response = { status: 401, data: { code: 'SESSION_EXPIRED' } }; throw error; };
    await assert.rejects(client.get('https://sentinelq.example/cases'));
    assert.equal(expired, 1);
    client.defaults.adapter = async config => { const error = new Error('Forbidden'); error.config = config; error.response = { status: 403, data: {} }; throw error; };
    await assert.rejects(client.get('https://sentinelq.example/audit'));
    assert.equal(expired, 1);
    setToken(null);
  } finally { delete global.window; }
});
