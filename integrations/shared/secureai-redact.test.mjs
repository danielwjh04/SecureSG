import assert from 'node:assert/strict'
import { test } from 'node:test'
import { redactString, redactSecrets, computeContentHash, applyPrivacyMode, REDACTED } from './secureai-redact.mjs'

test('redacts a hyphenated Slack bot token', () => {
  assert.doesNotMatch(redactString('use xoxb-12345678901-abcdefABCDEF as token'), /xoxb-12345678901-abcdefABCDEF/)
})
test('redacts an AWS access key id with no separator', () => {
  assert.doesNotMatch(redactString('AKIAIOSFODNN7EXAMPLE in config'), /AKIAIOSFODNN7EXAMPLE/)
})
test('redacts a PEM private key block', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END RSA PRIVATE KEY-----'
  const out = redactString(pem)
  assert.doesNotMatch(out, /MIIBVAIBADANBgkq/)
})
test('redacts the password in a connection string but keeps scheme and host shape', () => {
  const out = redactString('DATABASE_URL=postgres://user:p4ssw0rd@db.example.com:5432/app')
  assert.doesNotMatch(out, /p4ssw0rd/)
})
test('redacts a JWT', () => {
  assert.doesNotMatch(redactString('auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123'), /eyJzdWIiOiIxIn0/)
})
test('does not over-redact ordinary prose', () => {
  assert.equal(redactString('the quick brown fox jumps over the lazy dog'), 'the quick brown fox jumps over the lazy dog')
})
test('redactSecrets redacts an object value whose key looks secret', () => {
  assert.equal(redactSecrets({ api_key: 'live123', note: 'ok' }).api_key, REDACTED)
})
test('computeContentHash is deterministic and key-order independent', () => {
  const a = computeContentHash({ tool_name: 'Bash', tool_input: { command: 'ls', cwd: '/p' } })
  const b = computeContentHash({ tool_name: 'Bash', tool_input: { cwd: '/p', command: 'ls' } })
  assert.equal(a, b)
  assert.match(a, /^[0-9a-f]{64}$/)
})
test('maximum mode drops content but keeps tool_name and content_hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'ls' }, content_hash: 'h', session_id: 's', cwd: '/p' }, 'maximum')
  assert.equal(out.tool_input, undefined)
  assert.equal(out.session_id, undefined)
  assert.equal(out.cwd, undefined)
  assert.equal(out.tool_name, 'Bash')
  assert.equal(out.content_hash, 'h')
})
test('balanced mode keeps redacted content and hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'GITHUB_TOKEN=ghp_abcdefghijklmno ls' }, content_hash: 'h' }, 'balanced')
  assert.doesNotMatch(JSON.stringify(out), /ghp_abcdefghijklmno/)
  assert.equal(out.content_hash, 'h')
})
