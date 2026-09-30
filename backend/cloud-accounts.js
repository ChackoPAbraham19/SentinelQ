'use strict';

// Explicit account password rotation; never logs password values or hashes.
const { loadAuthorityUsers } = require('./index_no_deps');
const { SupabaseStorage } = require('./storage');

async function main() {
  const username = process.argv[2];
  if (!['admin', 'investigator', 'auditor', 'manager'].includes(username)) throw Error('Usage: node cloud-accounts.js <admin|investigator|auditor|manager>');
  if (process.env.SENTINELQ_ADMIN_PASSWORD === 'admin') throw Error('Cloud accounts cannot use demo credentials');
  const user = loadAuthorityUsers().find(item => item.username === username);
  const cloud = new SupabaseStorage(process.env);
  await cloud.init();
  const rows = await cloud.request(`/rest/v1/sentinelq_authorities?username=eq.${username}`, {
    method: 'PATCH', headers: { Prefer: 'return=representation' }, body: { password_hash: user.passwordHash },
  });
  if (rows?.length !== 1) throw Error('Account does not exist; no account was created');
  console.log('Password verifier updated. Restart the backend to apply it and invalidate existing sessions.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
