/**
 * Capability-aware guard action normalization and deterministic policy.
 *
 * This module turns native agent hook payloads into one common action shape
 * before the scanner looks for URLs or download-execute strings. That closes the
 * gap where a high-impact tool call with no visible link could otherwise be
 * treated as safe just because there was no content indicator to scan.
 */

import type { RuleFinding, Verdict } from '../schemas/contract'
import type { PreToolUsePayload } from '../schemas/validate'
import { escalate } from '../verdict'
import { commandTouchesSensitivePath, hasShellMetacharacters } from './commandRisk'

export type GuardActionOperation =
  | 'read_file'
  | 'write_file'
  | 'execute_shell'
  | 'network_request'
  | 'mcp_tool_call'
  | 'unknown'

export type GuardActionCapability =
  | 'filesystem.read'
  | 'filesystem.write'
  | 'shell.execute'
  | 'network.egress'
  | 'mcp.invoke'
  | 'unknown'

export type GuardCommandClass =
  | 'safe_shell'
  | 'package_install'
  | 'package_script_execution'
  | 'destructive_file_change'
  | 'permission_change'
  | 'unknown_shell'

export interface GuardCommandStructure {
  readonly command: string
  readonly words: readonly string[]
  readonly class: GuardCommandClass
}

export interface NormalizedGuardAction {
  readonly provider: string
  readonly agent: string
  readonly sessionId: string | null
  readonly toolName: string
  readonly operation: GuardActionOperation
  readonly targetPaths: readonly string[]
  readonly commandStructure: GuardCommandStructure | null
  readonly networkDestinations: readonly string[]
  readonly mcpServerIdentity: string | null
  readonly requestedCapabilities: readonly GuardActionCapability[]
  readonly workspaceRoot: string | null
  readonly sourceProvenance: string | null
  readonly contentHash: string | null
}

export interface GuardPolicyConfig {
  readonly guardReadTools: ReadonlySet<string>
  readonly guardWriteTools: ReadonlySet<string>
  readonly guardShellTools: ReadonlySet<string>
  readonly guardNetworkTools: ReadonlySet<string>
  readonly guardMcpToolPrefixes: ReadonlySet<string>
  readonly guardSensitivePathMarkers: ReadonlySet<string>
  readonly guardConfigPathMarkers: ReadonlySet<string>
  readonly guardSafeShellCommands: ReadonlySet<string>
  readonly guardDestructiveCommands: ReadonlySet<string>
  readonly guardPermissionCommands: ReadonlySet<string>
  readonly guardPackageManagers: ReadonlySet<string>
  readonly guardPackageInstallWords: ReadonlySet<string>
  readonly guardPackageScriptWords: ReadonlySet<string>
}

export interface GuardActionPolicyResult {
  readonly verdict: Verdict
  readonly findings: readonly RuleFinding[]
}

const POLICY_FLOOR: Verdict = 'ALLOW'
const REVIEW: Verdict = 'HUMAN_APPROVAL_REQUIRED'

const TOOL_INPUT_PATH_FIELDS = [
  'file_path',
  'path',
  'target_path',
  'notebook_path',
  'old_path',
  'new_path',
  'cwd',
]

const TOOL_INPUT_PATH_LIST_FIELDS = ['file_paths', 'paths', 'target_paths']

const TOOL_INPUT_NETWORK_FIELDS = [
  'url',
  'uri',
  'href',
  'target_url',
  'sourceUrl',
  'endpoint',
  'network_destination',
  'mcp_server_url',
]

/**
 * Normalize one validated guard payload into a provider-independent action.
 *
 * Time complexity: O(p + w) where p is the number of configured path fields and
 * w is the command word count. Space complexity: O(p + w).
 */
export function normalizeGuardAction(
  payload: PreToolUsePayload,
  config: GuardPolicyConfig,
): NormalizedGuardAction {
  const payloadRecord = payload as unknown as Record<string, unknown>
  const toolInput = payload.tool_input
  const toolName = payload.tool_name
  const toolKey = toolName.toLowerCase()
  const command = firstStringField(toolInput, ['command', 'cmd', 'script', 'shell'])
  const commandStructure =
    command === null ? null : buildCommandStructure(command, config)
  const targetPaths = collectTargetPaths(toolInput)
  const networkDestinations = collectNetworkDestinations(toolInput)
  const mcpServerIdentity = firstStringField(toolInput, [
    'mcp_server_url',
    'mcp_server_command',
    'server',
    'server_name',
  ])

  const operation = classifyOperation({
    toolKey,
    commandStructure,
    networkDestinations,
    mcpServerIdentity,
    config,
  })
  const requestedCapabilities = capabilitiesFor(operation)

  return {
    provider: stringOrDefault(payloadRecord.provider, 'unknown'),
    agent: stringOrDefault(payloadRecord.agent, 'unknown'),
    sessionId: stringOrNull(payload.session_id),
    toolName,
    operation,
    targetPaths,
    commandStructure,
    networkDestinations,
    mcpServerIdentity,
    requestedCapabilities,
    workspaceRoot: stringOrNull(payload.cwd),
    sourceProvenance: firstStringField(payloadRecord, [
      'cursor_hook_event_name',
      'codex_hook_event_name',
      'source_provenance',
    ]),
    contentHash: stringOrNull(payloadRecord.content_hash),
  }
}

/**
 * Evaluate deterministic capability policy for a normalized guard action.
 *
 * Time complexity: O(p + d) where p is target-path count and d is destination
 * count. Space complexity: O(f) in emitted findings.
 */
export function evaluateGuardActionPolicy(
  action: NormalizedGuardAction,
  config: GuardPolicyConfig,
): GuardActionPolicyResult {
  const findings: RuleFinding[] = []
  let verdict: Verdict = POLICY_FLOOR

  const record = (finding: RuleFinding): void => {
    findings.push(finding)
    verdict = escalate(verdict, finding.severity)
  }

  for (const path of action.targetPaths) {
    if (matchesMarker(path, config.guardSensitivePathMarkers)) {
      record({
        ruleId: 'guard.sensitive_path_access',
        severity: REVIEW,
        detail: `tool call accesses sensitive path ${path}`,
      })
    }
    if (action.operation === 'write_file' && matchesMarker(path, config.guardConfigPathMarkers)) {
      record({
        ruleId: 'guard.config_change',
        severity: REVIEW,
        detail: `tool call changes configuration path ${path}`,
      })
    }
    if (isAbsolutePathOutsideWorkspace(path, action.workspaceRoot)) {
      record({
        ruleId: 'guard.path_outside_workspace',
        severity: REVIEW,
        detail: `tool call targets a path outside the workspace: ${path}`,
      })
    }
  }

  if (action.operation === 'mcp_tool_call') {
    record({
      ruleId: 'guard.mcp_tool_call',
      severity: REVIEW,
      detail: `MCP tool call ${action.toolName} requires capability review`,
    })
  }

  if (action.operation === 'network_request' && action.networkDestinations.length > 0) {
    record({
      ruleId: 'guard.network_destination',
      severity: REVIEW,
      detail: `tool call reaches network destination ${action.networkDestinations[0]}`,
    })
  }

  if (action.operation === 'unknown') {
    record({
      ruleId: 'guard.unknown_operation',
      severity: REVIEW,
      detail: `tool ${action.toolName} maps to an unknown operation`,
    })
  }

  if (action.commandStructure !== null) {
    if (commandTouchesSensitivePath(action.commandStructure.command, config.guardSensitivePathMarkers)) {
      record({
        ruleId: 'guard.sensitive_path_access',
        severity: REVIEW,
        detail: `shell command accesses a sensitive path: ${action.commandStructure.command}`,
      })
    }
    recordCommandFinding(action.commandStructure, record)
  }

  return { verdict, findings }
}

function classifyOperation(input: {
  toolKey: string
  commandStructure: GuardCommandStructure | null
  networkDestinations: readonly string[]
  mcpServerIdentity: string | null
  config: GuardPolicyConfig
}): GuardActionOperation {
  const { toolKey, commandStructure, networkDestinations, mcpServerIdentity, config } = input
  if (isMcpTool(toolKey, config) || mcpServerIdentity !== null) {
    return 'mcp_tool_call'
  }
  if (commandStructure !== null || config.guardShellTools.has(toolKey)) {
    return 'execute_shell'
  }
  if (config.guardReadTools.has(toolKey)) {
    return 'read_file'
  }
  if (config.guardWriteTools.has(toolKey)) {
    return 'write_file'
  }
  if (networkDestinations.length > 0 || config.guardNetworkTools.has(toolKey)) {
    return 'network_request'
  }
  return 'unknown'
}

function isMcpTool(toolKey: string, config: GuardPolicyConfig): boolean {
  for (const prefix of config.guardMcpToolPrefixes) {
    if (toolKey.startsWith(prefix)) {
      return true
    }
  }
  return false
}

function capabilitiesFor(operation: GuardActionOperation): readonly GuardActionCapability[] {
  switch (operation) {
    case 'read_file':
      return ['filesystem.read']
    case 'write_file':
      return ['filesystem.write']
    case 'execute_shell':
      return ['shell.execute']
    case 'network_request':
      return ['network.egress']
    case 'mcp_tool_call':
      return ['mcp.invoke']
    case 'unknown':
      return ['unknown']
  }
}

function recordCommandFinding(
  command: GuardCommandStructure,
  record: (finding: RuleFinding) => void,
): void {
  switch (command.class) {
    case 'safe_shell':
      return
    case 'package_install':
      record({
        ruleId: 'guard.package_install',
        severity: REVIEW,
        detail: `shell command requests package install: ${command.command}`,
      })
      return
    case 'package_script_execution':
      record({
        ruleId: 'guard.package_script_execution',
        severity: REVIEW,
        detail: `shell command runs package script: ${command.command}`,
      })
      return
    case 'destructive_file_change':
      record({
        ruleId: 'guard.destructive_file_change',
        severity: REVIEW,
        detail: `shell command can delete, move, overwrite, or copy files: ${command.command}`,
      })
      return
    case 'permission_change':
      record({
        ruleId: 'guard.permission_change',
        severity: REVIEW,
        detail: `shell command changes permissions or ownership: ${command.command}`,
      })
      return
    case 'unknown_shell':
      record({
        ruleId: 'guard.unknown_shell_command',
        severity: REVIEW,
        detail: `unknown shell command requires review: ${command.command}`,
      })
      return
  }
}

function buildCommandStructure(
  command: string,
  config: GuardPolicyConfig,
): GuardCommandStructure {
  const words = shellWords(command).map((word) => baseCommand(word.toLowerCase()))
  return {
    command,
    words,
    class: classifyCommand(command, words, config),
  }
}

function classifyCommand(
  command: string,
  words: readonly string[],
  config: GuardPolicyConfig,
): GuardCommandClass {
  if (hasCommand(words, config.guardDestructiveCommands)) {
    return 'destructive_file_change'
  }
  if (hasCommand(words, config.guardPermissionCommands)) {
    return 'permission_change'
  }
  if (hasPackageInstall(words, config)) {
    return 'package_install'
  }
  if (hasPackageScriptExecution(words, config)) {
    return 'package_script_execution'
  }
  const first = firstExecutableWord(words)
  if (!hasShellMetacharacters(command) && first !== null && config.guardSafeShellCommands.has(first)) {
    return 'safe_shell'
  }
  return 'unknown_shell'
}

function hasCommand(words: readonly string[], commands: ReadonlySet<string>): boolean {
  for (const word of words) {
    if (commands.has(word)) {
      return true
    }
  }
  return false
}

function hasPackageInstall(words: readonly string[], config: GuardPolicyConfig): boolean {
  for (const [index, word] of words.entries()) {
    if (!config.guardPackageManagers.has(word)) {
      continue
    }
    const next = words[index + 1]
    if (next !== undefined && config.guardPackageInstallWords.has(next)) {
      return true
    }
  }
  return false
}

function hasPackageScriptExecution(
  words: readonly string[],
  config: GuardPolicyConfig,
): boolean {
  for (const [index, word] of words.entries()) {
    if (word === 'npx') {
      return true
    }
    if (!config.guardPackageManagers.has(word)) {
      continue
    }
    const next = words[index + 1]
    if (next !== undefined && config.guardPackageScriptWords.has(next)) {
      return true
    }
  }
  return false
}

function firstExecutableWord(words: readonly string[]): string | null {
  for (const word of words) {
    if (word.length === 0 || word === 'sudo' || word === 'env' || word.includes('=')) {
      continue
    }
    return word
  }
  return null
}

function shellWords(command: string): string[] {
  const words: string[] = []
  let current = ''
  let quote: string | null = null
  for (const char of command) {
    if ((char === '"' || char === "'") && quote === null) {
      quote = char
      continue
    }
    if (quote === char) {
      quote = null
      continue
    }
    if (quote === null && isShellSeparator(char)) {
      if (current.length > 0) {
        words.push(current)
        current = ''
      }
      continue
    }
    current += char
  }
  if (current.length > 0) {
    words.push(current)
  }
  return words
}

function isShellSeparator(char: string): boolean {
  return (
    char === ' ' || char === '\t' || char === '\n' || char === '\r' ||
    char === '|' || char === ';' || char === '&'
  )
}

function baseCommand(word: string): string {
  let clean = word.trim()
  clean = trimWrapping(clean, '"')
  clean = trimWrapping(clean, "'")
  clean = clean.replaceAll('\\', '/')
  const parts = clean.split('/')
  const last = parts[parts.length - 1] ?? clean
  if (last.endsWith('.exe') || last.endsWith('.cmd')) {
    return last.slice(0, -4)
  }
  return last
}

function trimWrapping(value: string, wrapper: string): string {
  let result = value
  while (result.startsWith(wrapper)) {
    result = result.slice(1)
  }
  while (result.endsWith(wrapper)) {
    result = result.slice(0, -1)
  }
  return result
}

function collectTargetPaths(toolInput: Record<string, unknown>): string[] {
  const paths: string[] = []
  for (const field of TOOL_INPUT_PATH_FIELDS) {
    const value = stringOrNull(toolInput[field])
    if (value !== null) {
      paths.push(value)
    }
  }
  for (const field of TOOL_INPUT_PATH_LIST_FIELDS) {
    const value = toolInput[field]
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.trim().length > 0) {
          paths.push(item)
        }
      }
    }
  }
  return uniqueStrings(paths)
}

function collectNetworkDestinations(toolInput: Record<string, unknown>): string[] {
  const destinations: string[] = []
  for (const field of TOOL_INPUT_NETWORK_FIELDS) {
    const value = stringOrNull(toolInput[field])
    if (value !== null) {
      destinations.push(value)
    }
  }
  return uniqueStrings(destinations)
}

function uniqueStrings(values: readonly string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const value of values) {
    if (seen.has(value)) {
      continue
    }
    seen.add(value)
    result.push(value)
  }
  return result
}

function firstStringField(
  record: Record<string, unknown>,
  fields: readonly string[],
): string | null {
  for (const field of fields) {
    const value = stringOrNull(record[field])
    if (value !== null) {
      return value
    }
  }
  return null
}

function stringOrDefault(value: unknown, fallback: string): string {
  const stringValue = stringOrNull(value)
  return stringValue === null ? fallback : stringValue
}

function stringOrNull(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null
  }
  const trimmed = value.trim()
  return trimmed.length === 0 ? null : trimmed
}

function matchesMarker(path: string, markers: ReadonlySet<string>): boolean {
  const normalized = path.replaceAll('\\', '/').toLowerCase()
  for (const marker of markers) {
    if (normalized.includes(marker)) {
      return true
    }
  }
  return false
}

/**
 * True when an absolute path is not contained within a known workspace root.
 * When no workspace root is known the check is skipped (returns false) to avoid
 * flagging every cwd-less call; system secret paths are still caught by the
 * sensitive-path markers, so this is a defense-in-depth layer, not the only one.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function isAbsolutePathOutsideWorkspace(path: string, workspaceRoot: string | null): boolean {
  if (workspaceRoot === null) {
    return false
  }
  const normalized = path.replaceAll('\\', '/')
  const isAbsolute = normalized.startsWith('/') || normalized.startsWith('~') || /^[a-z]:\//i.test(normalized)
  if (!isAbsolute) {
    return false
  }
  const root = workspaceRoot.replaceAll('\\', '/').replace(/\/+$/, '')
  return normalized !== root && !normalized.startsWith(`${root}/`)
}
