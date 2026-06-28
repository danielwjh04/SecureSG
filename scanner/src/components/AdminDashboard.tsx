/**
 * The owner-only admin analytics dashboard. The parent (`App`) gates the
 * `#admin` route so only an admin reaches this surface; on mount it loads
 * `GET /api/admin/overview` and renders sitewide metrics in the shared dark/glass
 * shell: headline stat cards, a 30-day sign-ups trend (recharts, zero-filled
 * client-side), a tier-breakdown donut, and verdict-colored sitewide totals.
 *
 * Every chart is themed dark with the verdict palette — no default light recharts
 * theme leaks through — matching the protection Dashboard.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import { motion } from 'motion/react'
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  CheckCircle2,
  Crown,
  FileText,
  Link2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Trash2,
  Users,
  Wallet,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  ApiError,
  fetchAdminOverview,
  fetchMembers,
  fetchThreats,
  removeMember,
  setMemberRole,
  setMemberTier,
} from '../api/client'
import {
  ADMIN_SEARCH_DEBOUNCE_MS,
  ADMIN_THREATS_LIMIT,
  STATS_TREND_DAYS,
} from '../config'
import { relativeTime } from '../lib/format'
import { zeroFillSignups } from '../lib/stats'
import { ThreatDetailModal } from './ThreatDetailModal'
import type {
  AccountTier,
  AdminMember,
  AdminOverview,
  AdminThreat,
  AdminTierCounts,
  AssignableRole,
} from '../api/types'

/** The plans an owner may assign from the members directory, in display order. */
const ASSIGNABLE_TIERS: readonly AccountTier[] = ['free', 'pro', 'enterprise']

/** The shared palette, so cards and charts use exact, consistent colors. */
const COLOR = {
  allow: '#34d399',
  review: '#fbbf24',
  block: '#f87171',
  signups: 'rgba(255,255,255,0.7)',
  axis: 'rgba(255,255,255,0.35)',
  free: 'rgba(255,255,255,0.45)',
  pro: '#34d399',
  enterprise: '#60a5fa',
} as const

/** Shared dark tooltip styling so recharts never paints its light default. */
const TOOLTIP_STYLE = {
  background: 'rgba(10,12,16,0.92)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 12,
  fontSize: 12,
  color: '#fff',
} as const

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; overview: AdminOverview }
  | { phase: 'error'; message: string }

/**
 * The admin analytics dashboard. `canManageRoles` (owner-only, sourced from
 * `/api/me`) gates the per-row role controls in the members directory: an admin
 * viewer sees the directory read-only, an owner sees the Member/Admin selects and
 * a Remove action. `viewerEmail` (the signed-in account's email) identifies the
 * viewer's own row, on which the destructive Remove action is hidden.
 */
export function AdminDashboard({
  canManageRoles = false,
  viewerEmail = null,
}: {
  canManageRoles?: boolean
  viewerEmail?: string | null
}) {
  const [load, setLoad] = useState<LoadState>({ phase: 'loading' })

  const refresh = useCallback((): (() => void) => {
    let active = true
    setLoad({ phase: 'loading' })
    fetchAdminOverview()
      .then((overview) => {
        if (active) setLoad({ phase: 'ready', overview })
      })
      .catch(() => {
        if (active) setLoad({ phase: 'error', message: 'Could not load admin analytics.' })
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => refresh(), [refresh])

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-8">
        <Header
          generatedAt={load.phase === 'ready' ? load.overview.generatedAt : null}
          onRefresh={() => refresh()}
          busy={load.phase === 'loading'}
        />

        {load.phase === 'loading' && (
          <p className="text-white/45 font-mono text-sm py-20 text-center">
            Loading sitewide analytics…
          </p>
        )}
        {load.phase === 'error' && (
          <p className="text-block/90 font-mono text-sm py-20 text-center">{load.message}</p>
        )}
        {load.phase === 'ready' && <OverviewBody overview={load.overview} />}

        <MembersSection canManageRoles={canManageRoles} viewerEmail={viewerEmail} />

        <ThreatsSection />
      </div>
    </section>
  )
}

/**
 * Debounce a fast-changing value: returns the latest `value`, but only after it
 * has stopped changing for `delayMs`. Used to keep an admin search input off the
 * keystroke hot path — a refetch fires once typing pauses, not per character.
 *
 * Time complexity: O(1) per update. Space complexity: O(1).
 */
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}

interface HeaderProps {
  generatedAt: string | null
  onRefresh: () => void
  busy: boolean
}

/** The title row: admin label, heading, generated-at stamp, and refresh. */
function Header({ generatedAt, onRefresh, busy }: HeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4"
    >
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          Admin analytics
        </span>
        <h1
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[38px] font-medium tracking-[-0.01em] text-white leading-tight"
        >
          Sitewide overview
        </h1>
      </div>
      <div className="flex items-center gap-3">
        {generatedAt !== null && (
          <span className="text-white/40 font-mono text-[11px]">
            Generated {formatStamp(generatedAt)}
          </span>
        )}
        <button
          type="button"
          onClick={onRefresh}
          disabled={busy}
          className="glass-pill inline-flex items-center gap-1.5 px-3.5 py-1.5 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>
    </motion.div>
  )
}

/** One headline stat tile. */
interface StatTile {
  key: string
  Icon: LucideIcon
  label: string
  value: number
  accent: string
}

function OverviewBody({ overview }: { overview: AdminOverview }) {
  const filledSignups = useMemo(
    () => zeroFillSignups(overview.signupsDaily, STATS_TREND_DAYS),
    [overview.signupsDaily],
  )
  const hasAny =
    overview.totalUsers > 0 || overview.usageTotals.scans > 0 || overview.activeSubscriptions > 0

  const tiles: StatTile[] = [
    { key: 'users', Icon: Users, label: 'Total sign-ups', value: overview.totalUsers, accent: 'text-white' },
    { key: 'subs', Icon: Wallet, label: 'Pro subscribers', value: overview.activeSubscriptions, accent: 'text-allow' },
    { key: 'scans', Icon: ShieldCheck, label: 'Total scans', value: overview.usageTotals.scans, accent: 'text-white' },
    { key: 'blocks', Icon: ShieldX, label: 'Threats blocked', value: overview.usageTotals.blocks, accent: 'text-block' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-6"
    >
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {tiles.map(({ key, Icon, label, value, accent }) => (
          <div key={key} className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
            <Icon className={`w-5 h-5 ${accent}`} />
            <div
              className={`text-3xl md:text-4xl font-medium tabular-nums ${accent}`}
              style={{ fontFamily: "'Instrument Serif', serif" }}
            >
              {formatCount(value)}
            </div>
            <div className="text-white/70 text-[13px] font-medium leading-snug">{label}</div>
          </div>
        ))}
      </div>

      {!hasAny ? (
        <EmptyState />
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <SignupsTrend signups={filledSignups} className="lg:col-span-2" />
            <TierBreakdown tiers={overview.usersByTier} total={overview.totalUsers} />
          </div>
          <VerdictTotals totals={overview.usageTotals} />
        </>
      )}
    </motion.div>
  )
}

/** The intentional empty state when nothing has happened sitewide yet. */
function EmptyState() {
  return (
    <div className="liquid-glass rounded-2xl p-10 flex flex-col items-center text-center gap-3">
      <Users className="w-7 h-7 text-allow" />
      <h3 style={{ fontFamily: "'Instrument Serif', serif" }} className="text-2xl font-medium text-white">
        No activity yet
      </h3>
      <p className="text-white/55 text-[14px] max-w-md leading-relaxed">
        Once people sign up and run scans, sign-up trends, tier mix, and sitewide
        verdict totals will appear here.
      </p>
    </div>
  )
}

/** The 30-day sign-ups trend, themed dark. */
function SignupsTrend({
  signups,
  className,
}: {
  signups: AdminOverview['signupsDaily']
  className?: string
}) {
  const data = signups.map((row) => ({ ...row, label: row.day.slice(5) }))
  return (
    <div className={`liquid-glass rounded-2xl p-5 flex flex-col gap-4 ${className ?? ''}`}>
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Last {signups.length} days · sign-ups
      </h3>
      <div className="h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="adminSignupsFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.signups} stopOpacity={0.32} />
                <stop offset="100%" stopColor={COLOR.signups} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="label"
              tick={{ fill: COLOR.axis, fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              minTickGap={24}
            />
            <YAxis
              tick={{ fill: COLOR.axis, fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
              width={28}
            />
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#fff' }} />
            <Area
              type="monotone"
              dataKey="count"
              name="Sign-ups"
              stroke={COLOR.signups}
              strokeWidth={1.5}
              fill="url(#adminSignupsFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/** Tier breakdown as a donut (free / pro / enterprise). */
function TierBreakdown({ tiers, total }: { tiers: AdminTierCounts; total: number }) {
  const data = [
    { name: 'Free', value: tiers.free, color: COLOR.free },
    { name: 'Pro', value: tiers.pro, color: COLOR.pro },
    { name: 'Enterprise', value: tiers.enterprise, color: COLOR.enterprise },
  ]
  const hasUsers = total > 0
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Tier breakdown
      </h3>
      <div className="h-[200px] relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={hasUsers ? data : [{ name: 'None', value: 1, color: 'rgba(255,255,255,0.08)' }]}
              dataKey="value"
              nameKey="name"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={hasUsers ? 2 : 0}
              stroke="none"
            >
              {(hasUsers ? data : [{ name: 'None', value: 1, color: 'rgba(255,255,255,0.08)' }]).map(
                (entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ),
              )}
            </Pie>
            {hasUsers && (
              <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#fff' }} />
            )}
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span
            className="text-2xl font-medium text-white tabular-nums"
            style={{ fontFamily: "'Instrument Serif', serif" }}
          >
            {formatCount(total)}
          </span>
          <span className="text-white/45 font-mono text-[10px] uppercase tracking-[0.14em]">
            users
          </span>
        </div>
      </div>
      <div className="flex items-center justify-center gap-4 text-[11px] font-mono">
        {data.map((entry) => (
          <span key={entry.name} className="inline-flex items-center gap-1.5 text-white/60">
            <span className="w-2 h-2 rounded-full" style={{ background: entry.color }} />
            {entry.name} {entry.value}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Sitewide verdict totals (Allow / Review / Block) + IOCs caught. */
function VerdictTotals({ totals }: { totals: AdminOverview['usageTotals'] }) {
  const cells = [
    { key: 'allows', Icon: CheckCircle2, label: 'Allowed', value: totals.allows, accent: 'text-allow' },
    { key: 'reviews', Icon: ShieldAlert, label: 'Reviews', value: totals.reviews, accent: 'text-review' },
    { key: 'blocks', Icon: ShieldX, label: 'Blocked', value: totals.blocks, accent: 'text-block' },
    { key: 'flagged', Icon: ShieldAlert, label: 'IOCs caught', value: totals.flagged, accent: 'text-block' },
  ]
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Sitewide verdict totals
      </h3>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {cells.map(({ key, Icon, label, value, accent }) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Icon className={`w-4 h-4 ${accent}`} />
            <span className={`text-2xl font-medium tabular-nums ${accent}`} style={{ fontFamily: "'Instrument Serif', serif" }}>
              {formatCount(value)}
            </span>
            <span className="text-white/55 text-[12px]">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/** The members directory load lifecycle, mirroring the overview's. */
type MembersState =
  | { phase: 'loading' }
  | { phase: 'ready'; members: AdminMember[]; total: number }
  | { phase: 'error'; message: string }

/**
 * The members directory: a searchable table of every account (Email, Tier, Role,
 * Joined, Scans) loaded from `GET /api/admin/members`. A search input filters by
 * email via the server-side `q` param (debounced ~300ms so a fast typist sends
 * one request, not one per character); the heading count reflects the filtered
 * total. An owner (`canManageRoles`) gets a per-row free/pro/enterprise plan
 * select, a Member/Admin role select, plus a Remove action on non-owner rows;
 * owners' rows show a static "Owner" role badge (but their plan stays
 * switchable), and a non-owner viewer sees every plan and role read-only with no
 * Remove action. The viewer's OWN row (matched by `viewerEmail`) never shows the
 * Remove action.
 */
function MembersSection({
  canManageRoles,
  viewerEmail,
}: {
  canManageRoles: boolean
  viewerEmail: string | null
}) {
  const [state, setState] = useState<MembersState>({ phase: 'loading' })
  /** The raw search box value; the debounced form drives the actual refetch. */
  const [query, setQuery] = useState('')
  const debouncedQuery = useDebouncedValue(query.trim(), ADMIN_SEARCH_DEBOUNCE_MS)
  /** The user id whose role/removal is mid-flight, so its row can disable + spin. */
  const [pendingId, setPendingId] = useState<string | null>(null)

  const load = useCallback(
    (search: string): (() => void) => {
      let active = true
      setState({ phase: 'loading' })
      fetchMembers(search)
        .then((page) => {
          if (active) setState({ phase: 'ready', members: page.members, total: page.total })
        })
        .catch(() => {
          if (active) setState({ phase: 'error', message: 'Could not load members.' })
        })
      return () => {
        active = false
      }
    },
    [],
  )

  // Reload whenever the debounced query changes (including the initial empty
  // query, which loads the first unfiltered page).
  useEffect(() => load(debouncedQuery), [load, debouncedQuery])

  const changeRole = useCallback(
    async (userId: string, role: AssignableRole): Promise<void> => {
      setPendingId(userId)
      try {
        await setMemberRole(userId, role)
        // Re-read the current query so the table reflects authoritative state.
        load(debouncedQuery)
      } catch (error) {
        const message =
          error instanceof ApiError ? error.message : 'Could not update the role.'
        setState({ phase: 'error', message })
      } finally {
        setPendingId(null)
      }
    },
    [load, debouncedQuery],
  )

  const changeTier = useCallback(
    async (userId: string, tier: AccountTier): Promise<void> => {
      setPendingId(userId)
      try {
        await setMemberTier(userId, tier)
        // Re-read the current query so the table reflects authoritative state.
        load(debouncedQuery)
      } catch (error) {
        const message =
          error instanceof ApiError ? error.message : 'Could not update the plan.'
        setState({ phase: 'error', message })
      } finally {
        setPendingId(null)
      }
    },
    [load, debouncedQuery],
  )

  const remove = useCallback(
    async (member: AdminMember): Promise<void> => {
      // A destructive, irreversible action: confirm with the operator first, named
      // by the target's email so they cannot mistake the row.
      if (!window.confirm(`Remove ${member.email}? This deletes their account and data.`)) {
        return
      }
      setPendingId(member.id)
      try {
        await removeMember(member.id)
        // Re-read the current query so the removed row disappears and the count
        // reflects the server.
        load(debouncedQuery)
      } catch (error) {
        const message =
          error instanceof ApiError ? error.message : 'Could not remove the member.'
        setState({ phase: 'error', message })
      } finally {
        setPendingId(null)
      }
    },
    [load, debouncedQuery],
  )

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="liquid-glass rounded-2xl p-5 flex flex-col gap-4"
    >
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
          Members{state.phase === 'ready' ? ` · ${state.total}` : ''}
        </h3>
        <Users className="w-4 h-4 text-white/40" />
      </div>

      <SearchInput
        value={query}
        onChange={setQuery}
        placeholder="Search members by email or plan"
        ariaLabel="Search members by email or plan"
      />
      <p className="-mt-2 text-white/35 font-mono text-[10px]">
        Tip: type a plan to filter by tier — free / pro / enterprise.
      </p>

      {state.phase === 'loading' && (
        <p className="text-white/45 font-mono text-sm py-8 text-center">Loading members…</p>
      )}
      {state.phase === 'error' && (
        <p className="text-block/90 font-mono text-sm py-8 text-center">{state.message}</p>
      )}
      {state.phase === 'ready' &&
        (state.members.length === 0 ? (
          <p className="text-white/45 font-mono text-sm py-8 text-center">
            {debouncedQuery.length > 0 ? 'No members match your search.' : 'No members yet.'}
          </p>
        ) : (
          <MembersTable
            members={state.members}
            canManageRoles={canManageRoles}
            viewerEmail={viewerEmail}
            pendingId={pendingId}
            onChangeRole={changeRole}
            onChangeTier={changeTier}
            onRemove={remove}
          />
        ))}
    </motion.div>
  )
}

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder: string
  ariaLabel: string
}

/**
 * A glass search field with a leading magnifier, matching the dashboard's dark
 * styling. Purely controlled — the parent owns the value and debounces the
 * refetch, so this only renders the input and forwards keystrokes.
 */
function SearchInput({ value, onChange, placeholder, ariaLabel }: SearchInputProps) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/35" />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        className="w-full rounded-xl bg-white/[0.04] border border-white/10 pl-9 pr-3 py-2 text-[13px] text-white placeholder:text-white/35 focus:outline-none focus:border-white/25 transition-colors"
      />
    </div>
  )
}

interface MembersTableProps {
  members: AdminMember[]
  canManageRoles: boolean
  viewerEmail: string | null
  pendingId: string | null
  onChangeRole: (userId: string, role: AssignableRole) => void
  onChangeTier: (userId: string, tier: AccountTier) => void
  onRemove: (member: AdminMember) => void
}

/**
 * The scrollable members table. Columns: Email, Tier, Role, Joined, Scans, and —
 * for an owner viewer only — an Actions column carrying the per-row Remove
 * control. The Remove control is never shown for an owner row or for the viewer's
 * own row.
 */
function MembersTable({
  members,
  canManageRoles,
  viewerEmail,
  pendingId,
  onChangeRole,
  onChangeTier,
  onRemove,
}: MembersTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="text-[10px] font-mono uppercase tracking-[0.14em] text-white/40">
            <th className="font-medium py-2 pr-4">Email</th>
            <th className="font-medium py-2 pr-4">Tier</th>
            <th className="font-medium py-2 pr-4">Role</th>
            <th className="font-medium py-2 pr-4">Joined</th>
            <th className="font-medium py-2 pr-4 text-right tabular-nums">Scans</th>
            {canManageRoles && (
              <th className="font-medium py-2 pr-4 text-right">
                <span className="sr-only">Actions</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {members.map((member) => (
            <tr
              key={member.id}
              className="border-t border-white/5 text-[13px] text-white/80 align-middle"
            >
              <td className="py-2.5 pr-4 font-medium text-white break-all">{member.email}</td>
              <td className="py-2.5 pr-4">
                <TierCell
                  member={member}
                  canManageRoles={canManageRoles}
                  pending={pendingId === member.id}
                  onChangeTier={onChangeTier}
                />
              </td>
              <td className="py-2.5 pr-4">
                <RoleCell
                  member={member}
                  canManageRoles={canManageRoles}
                  pending={pendingId === member.id}
                  onChangeRole={onChangeRole}
                />
              </td>
              <td className="py-2.5 pr-4 text-white/55 font-mono text-[11px] whitespace-nowrap">
                {formatJoined(member.createdAt)}
              </td>
              <td className="py-2.5 pr-4 text-right tabular-nums text-white/70">
                {formatCount(member.scans)}
              </td>
              {canManageRoles && (
                <td className="py-2.5 pr-4 text-right">
                  <RemoveCell
                    member={member}
                    viewerEmail={viewerEmail}
                    pending={pendingId === member.id}
                    onRemove={onRemove}
                  />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

interface RemoveCellProps {
  member: AdminMember
  viewerEmail: string | null
  pending: boolean
  onRemove: (member: AdminMember) => void
}

/**
 * The Remove cell (owner viewer only). Renders nothing for an OWNER row (an owner
 * can never be removed via the API) or for the viewer's OWN row (matched
 * case-insensitively by email). Otherwise a small destructive trash button that
 * confirms before deleting the account and its data.
 */
function RemoveCell({ member, viewerEmail, pending, onRemove }: RemoveCellProps) {
  const isOwnRow =
    viewerEmail !== null && member.email.toLowerCase() === viewerEmail.toLowerCase()
  if (member.role === 'owner' || isOwnRow) {
    return null
  }
  return (
    <button
      type="button"
      aria-label={`Remove ${member.email}`}
      title={`Remove ${member.email}`}
      disabled={pending}
      onClick={() => onRemove(member)}
      className="glass-pill inline-flex items-center justify-center w-7 h-7 rounded-full text-block/80 hover:text-block hover:bg-block/10 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <Trash2 className="w-3.5 h-3.5" />
    </button>
  )
}

interface TierCellProps {
  member: AdminMember
  canManageRoles: boolean
  pending: boolean
  onChangeTier: (userId: string, tier: AccountTier) => void
}

/**
 * The plan/tier cell. An owner viewer (`canManageRoles`) gets a free/pro/
 * enterprise select to switch any member's plan; everyone else sees the static
 * tier label. Mirrors {@link RoleCell}'s control exactly (styling, pending +
 * refetch), with no owner carve-out — an owner's own plan is switchable too,
 * since plan is not access control.
 */
function TierCell({ member, canManageRoles, pending, onChangeTier }: TierCellProps) {
  if (!canManageRoles) {
    return (
      <span className="text-white/60 font-mono text-[11px] uppercase tracking-[0.1em]">
        {member.tier}
      </span>
    )
  }
  return (
    <select
      aria-label={`Plan for ${member.email}`}
      value={member.tier}
      disabled={pending}
      onChange={(event) => onChangeTier(member.id, event.target.value as AccountTier)}
      className="glass-pill bg-transparent text-white/80 text-[12px] font-medium px-2.5 py-1 rounded-full cursor-pointer focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed [&>option]:bg-black [&>option]:text-white"
    >
      {ASSIGNABLE_TIERS.map((tier) => (
        <option key={tier} value={tier}>
          {tier.charAt(0).toUpperCase() + tier.slice(1)}
        </option>
      ))}
    </select>
  )
}

interface RoleCellProps {
  member: AdminMember
  canManageRoles: boolean
  pending: boolean
  onChangeRole: (userId: string, role: AssignableRole) => void
}

/**
 * The role cell. An OWNER row is always a static "Owner" badge (an owner can
 * never be demoted via the API). For a non-owner row, an owner viewer gets a
 * Member/Admin select; everyone else sees a static role label.
 */
function RoleCell({ member, canManageRoles, pending, onChangeRole }: RoleCellProps) {
  if (member.role === 'owner') {
    return (
      <span className="glass-pill inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono uppercase tracking-[0.12em] text-review">
        <Crown className="w-3 h-3" />
        Owner
      </span>
    )
  }
  if (!canManageRoles) {
    return (
      <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-white/60">
        {member.role}
      </span>
    )
  }
  return (
    <select
      aria-label={`Role for ${member.email}`}
      value={member.role}
      disabled={pending}
      onChange={(event) => onChangeRole(member.id, event.target.value as AssignableRole)}
      className="glass-pill bg-transparent text-white/80 text-[12px] font-medium px-2.5 py-1 rounded-full cursor-pointer focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed [&>option]:bg-black [&>option]:text-white"
    >
      <option value="member">Member</option>
      <option value="admin">Admin</option>
    </select>
  )
}

/** The blocked-threats report load lifecycle, mirroring the members section's. */
type ThreatsState =
  | { phase: 'loading' }
  | { phase: 'ready'; threats: AdminThreat[]; total: number }
  | { phase: 'error'; message: string }

/**
 * The blocked-threats report ("the report"): every scan that ended in a `BLOCK`,
 * loaded from `GET /api/admin/threats`. A search input filters by scanned URL or
 * owning member email via the server-side `q` param (debounced ~300ms); the
 * table lists Member (email), Source (truncated URL, or "Pasted skill" for a
 * pasted skill), Flagged (indicator count), and When (relative time), each row
 * tagged with a red BLOCK pill. Empty state: "No blocked threats yet." Loads the
 * first {@link ADMIN_THREATS_LIMIT} rows; a "Load more" control raises the page
 * size when the server total exceeds the rows shown.
 */
function ThreatsSection() {
  const [state, setState] = useState<ThreatsState>({ phase: 'loading' })
  const [query, setQuery] = useState('')
  const debouncedQuery = useDebouncedValue(query.trim(), ADMIN_SEARCH_DEBOUNCE_MS)
  const [limit, setLimit] = useState(ADMIN_THREATS_LIMIT)
  /** The threat row whose detail modal is open, or null when none is open. */
  const [openThreat, setOpenThreat] = useState<AdminThreat | null>(null)

  // A new search resets the page size so a filtered view starts from the first
  // page rather than carrying an expanded limit from the previous query.
  const previousQueryRef = useRef(debouncedQuery)
  useEffect(() => {
    if (previousQueryRef.current !== debouncedQuery) {
      previousQueryRef.current = debouncedQuery
      setLimit(ADMIN_THREATS_LIMIT)
    }
  }, [debouncedQuery])

  useEffect(() => {
    let active = true
    setState({ phase: 'loading' })
    fetchThreats(debouncedQuery, limit)
      .then((page) => {
        if (active) setState({ phase: 'ready', threats: page.threats, total: page.total })
      })
      .catch(() => {
        if (active) setState({ phase: 'error', message: 'Could not load blocked threats.' })
      })
    return () => {
      active = false
    }
  }, [debouncedQuery, limit])

  const shown = state.phase === 'ready' ? state.threats.length : 0
  const total = state.phase === 'ready' ? state.total : 0

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="liquid-glass rounded-2xl p-5 flex flex-col gap-4"
    >
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
          Threats blocked{state.phase === 'ready' ? ` · ${total}` : ''}
        </h3>
        <ShieldX className="w-4 h-4 text-block/70" />
      </div>

      <SearchInput
        value={query}
        onChange={setQuery}
        placeholder="Search blocked threats by URL or member"
        ariaLabel="Search blocked threats by URL or member"
      />

      {state.phase === 'loading' && (
        <p className="text-white/45 font-mono text-sm py-8 text-center">
          Loading blocked threats…
        </p>
      )}
      {state.phase === 'error' && (
        <p className="text-block/90 font-mono text-sm py-8 text-center">{state.message}</p>
      )}
      {state.phase === 'ready' &&
        (state.threats.length === 0 ? (
          <p className="text-white/45 font-mono text-sm py-8 text-center">
            {debouncedQuery.length > 0
              ? 'No blocked threats match your search.'
              : 'No blocked threats yet.'}
          </p>
        ) : (
          <>
            <ThreatsTable threats={state.threats} onOpen={setOpenThreat} />
            {total > shown && (
              <button
                type="button"
                onClick={() => setLimit((current) => current + ADMIN_THREATS_LIMIT)}
                className="glass-pill self-center inline-flex items-center gap-1.5 px-4 py-1.5 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer"
              >
                Load more · {shown} of {total}
              </button>
            )}
          </>
        ))}

      {openThreat !== null && (
        <ThreatDetailModal
          scanId={openThreat.id}
          email={openThreat.email}
          onClose={() => setOpenThreat(null)}
        />
      )}
    </motion.div>
  )
}

/**
 * The scrollable blocked-threats table. Columns: Member, Source, Flagged, When.
 * Every row carries a red BLOCK pill (the report lists only blocked threats) and
 * is clickable: selecting a row calls `onOpen` with that threat so the parent can
 * open its malicious-artifact detail view.
 */
function ThreatsTable({
  threats,
  onOpen,
}: {
  threats: AdminThreat[]
  onOpen: (threat: AdminThreat) => void
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="text-[10px] font-mono uppercase tracking-[0.14em] text-white/40">
            <th className="font-medium py-2 pr-4">Member</th>
            <th className="font-medium py-2 pr-4">Source</th>
            <th className="font-medium py-2 pr-4 text-right tabular-nums">Flagged</th>
            <th className="font-medium py-2 pr-4 text-right">When</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((threat) => (
            <ThreatRow key={threat.headHash} threat={threat} onOpen={onOpen} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** A small red BLOCK pill — every threat row is a blocked verdict. */
function BlockPill() {
  return (
    <span className="inline-flex items-center justify-center rounded-full bg-block/10 px-2.5 py-1 text-[10px] font-mono font-bold uppercase tracking-[0.1em] text-block">
      BLOCK
    </span>
  )
}

/**
 * One blocked-threat row: member email, source, flagged count, relative time.
 * The whole row is an activatable control (click, Enter, or Space) that opens the
 * malicious-artifact detail view for this scan; `role="button"` + `tabIndex` keep
 * it reachable and operable from the keyboard.
 */
function ThreatRow({
  threat,
  onOpen,
}: {
  threat: AdminThreat
  onOpen: (threat: AdminThreat) => void
}) {
  const isUrl = threat.source.kind === 'url'
  const SourceIcon = isUrl ? Link2 : FileText
  const sourceLabel = isUrl ? truncateUrl(threat.source.ref) : 'Pasted skill'
  const open = (): void => onOpen(threat)
  const onKeyDown = (event: KeyboardEvent<HTMLTableRowElement>): void => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      open()
    }
  }
  return (
    <tr
      role="button"
      tabIndex={0}
      aria-label={`View scan detail for ${threat.email}`}
      onClick={open}
      onKeyDown={onKeyDown}
      className="border-t border-white/5 text-[13px] text-white/80 align-middle cursor-pointer transition-colors hover:bg-white/[0.03] focus:outline-none focus-visible:bg-white/[0.05]"
    >
      <td className="py-2.5 pr-4">
        <div className="flex items-center gap-2">
          <BlockPill />
          <span className="font-medium text-white break-all">{threat.email}</span>
        </div>
      </td>
      <td className="py-2.5 pr-4">
        <span className="flex min-w-0 items-center gap-1.5">
          <SourceIcon className="w-3.5 h-3.5 shrink-0 text-white/40" />
          <span className="truncate text-white/75 max-w-[220px]" title={threat.source.ref}>
            {sourceLabel}
          </span>
        </span>
      </td>
      <td className="py-2.5 pr-4 text-right tabular-nums">
        <span className="inline-flex items-center gap-1 text-block">
          <ShieldAlert className="w-3 h-3" />
          {formatCount(threat.flagged)}
        </span>
      </td>
      <td className="py-2.5 pr-4 text-right font-mono text-[11px] text-white/45 whitespace-nowrap tabular-nums">
        {relativeTime(threat.scannedAt)}
      </td>
    </tr>
  )
}

/**
 * Shorten a scanned URL for the report: drop the scheme and any trailing slash,
 * so `https://evil.example/x/` reads as `evil.example/x`. Falls back to the raw
 * value when it is not a parseable absolute URL.
 *
 * Time complexity: O(n) in the URL length. Space complexity: O(1).
 */
function truncateUrl(url: string): string {
  try {
    const parsed = new URL(url)
    const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '')
    return `${parsed.host}${path}${parsed.search}`
  } catch {
    return url
  }
}

/** Format an ISO signup timestamp as a short local date, falling back to raw. */
function formatJoined(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' })
}

/** Format a count with thousands separators, never `NaN`. */
function formatCount(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : '0'
}

/** Format an ISO stamp as a short local date-time, falling back to the raw string. */
function formatStamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
