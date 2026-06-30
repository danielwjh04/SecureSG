import { describe, expect, it } from 'vitest'
import type { PreToolUsePayload } from '../schemas/validate'
import { loadConfig } from '../config/env'
import { evaluateGuardActionPolicy, normalizeGuardAction } from './actionPolicy'

const config = loadConfig({})

function payload(toolName: string, toolInput: Record<string, unknown>): PreToolUsePayload {
  // Mirror real Claude Code hook shape: cwd is a top-level field, not part of
  // tool_input. Hoist it here so tests can pass it naturally in the input dict.
  const { cwd, ...restInput } = toolInput
  return {
    hook_event_name: 'PreToolUse',
    tool_name: toolName,
    tool_input: restInput,
    ...(typeof cwd === 'string' ? { cwd } : {}),
  }
}

describe('guard action policy', () => {
  it('normalizes a read tool call into a low-risk file read action', () => {
    const action = normalizeGuardAction(payload('Read', { file_path: 'README.md' }), config)

    expect(action.operation).toBe('read_file')
    expect(action.targetPaths).toEqual(['README.md'])
    expect(action.requestedCapabilities).toEqual(['filesystem.read'])

    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('ALLOW')
    expect(policy.findings).toEqual([])
  })

  it('requires review for a sensitive file read with no URL', () => {
    const action = normalizeGuardAction(
      payload('Read', { file_path: '.dev.vars' }),
      config,
    )

    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.sensitive_path_access' }),
    )
  })

  it('requires review for package installation commands with no URL', () => {
    const action = normalizeGuardAction(
      payload('Bash', { command: 'npm install left-pad' }),
      config,
    )

    expect(action.commandStructure?.class).toBe('package_install')
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.package_install' }),
    )
  })

  it('requires review for destructive file commands with no URL', () => {
    const action = normalizeGuardAction(
      payload('Shell', { command: 'rm -rf dist' }),
      config,
    )

    expect(action.commandStructure?.class).toBe('destructive_file_change')
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.destructive_file_change' }),
    )
  })

  it('requires review for unknown shell commands with no URL', () => {
    const action = normalizeGuardAction(
      payload('Bash', { command: 'node scripts/release.js' }),
      config,
    )

    expect(action.commandStructure?.class).toBe('unknown_shell')
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.unknown_shell_command' }),
    )
  })

  it('requires review for a secret file read via a safe shell reader (no URL)', () => {
    const action = normalizeGuardAction(
      payload('Bash', { command: 'cat ~/.ssh/id_rsa' }),
      config,
    )
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.sensitive_path_access' }),
    )
  })

  it('keeps a benign safe shell read as ALLOW', () => {
    const action = normalizeGuardAction(payload('Bash', { command: 'cat README.md' }), config)
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('ALLOW')
    expect(policy.findings).toEqual([])
  })

  it('does not allow a destructive command hidden behind substitution', () => {
    const action = normalizeGuardAction(payload('Bash', { command: 'echo $(chmod -R 777 /etc)' }), config)
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('catches a destructive command chained without spaces', () => {
    const action = normalizeGuardAction(payload('Bash', { command: 'echo ok&&rm -rf /' }), config)
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('requires review for a read of a system secret file', () => {
    const action = normalizeGuardAction(payload('Read', { file_path: '/etc/shadow' }), config)
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('requires review for an absolute read outside the workspace root', () => {
    const action = normalizeGuardAction(
      payload('Read', { file_path: '/var/secrets/key', cwd: '/home/me/project' }),
      config,
    )
    const policy = evaluateGuardActionPolicy(action, config)
    expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(policy.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'guard.path_outside_workspace' }),
    )
  })
})
