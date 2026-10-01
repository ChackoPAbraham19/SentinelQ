const crypto = require('node:crypto');
const { issueRelease } = require('../court-vault');
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
const environment = { SENTINELQ_COURT_PUBLIC_KEY: keys.publicKey.export({ type: 'spki', format: 'pem' }), SENTINELQ_COURT_PUBLIC_KEY_PATH: '' };
async function releaseBody(request, evidenceRoute, token, reason = 'Court-authorized review of submitted original evidence') {
  const response = await request('POST', `${evidenceRoute}/court-request`, {}, token);
  if (!response.body.request) throw new Error(JSON.stringify(response.body));
  return { requestId: response.body.request.requestId, release: issueRelease(response.body.request, keys.privateKey, 'ORDER-TEST-2026'), reason };
}
module.exports = { environment, releaseBody, keys };
