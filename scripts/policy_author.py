"""Propose/activate CLI for LLM policy authoring (the human-in-the-loop gate).

``propose`` authors a validated proposal from intent and writes it to the staging
dir with intent provenance — nothing is active. ``activate`` re-validates a staged
file, promotes it into the policy dir (where ``load_policy`` reads it), and appends
a tamper-evident activation record to the audit chain. Run with
``python -m scripts.policy_author propose "<intent>" --tools a,b`` then
``python -m scripts.policy_author activate <staged-file>``.
"""

import argparse
import asyncio
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import yaml
from pydantic import ValidationError

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.exceptions import AuthoringError
from secureSG.guard.policy import PolicySchema, load_policy
from secureSG.models.loader import load_guard_provider
from secureSG.models.provider import ModelProvider
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict
from secureSG.warden.authoring import PolicyProposal, author_policy


def _policy_to_dict(policy: PolicySchema) -> dict[str, object]:
    """Serialize a policy to plain, human-readable YAML types. O(policy size)."""
    return {
        "denylist": sorted(policy.denylist),
        "external_comms_tools": sorted(policy.external_comms_tools),
        "content_scan_sources": sorted(policy.content_scan_sources),
        "tool_rules": {t: v.value for t, v in sorted(policy.tool_rules.items())},
        "taint_sources": {
            t: tier.name for t, tier in sorted(policy.taint_sources.items())
        },
    }


def _render_staged_file(proposal: PolicyProposal) -> str:
    """Render a staged proposal: a provenance header above the policy YAML."""
    header = [
        "# Proposed policy (LLM-authored) - REVIEW BEFORE ACTIVATING.",
        f"# Intent: {proposal.intent}",
        "# Effect vs active policy:",
    ]
    header += [f"#   {line}" for line in proposal.diff.render().splitlines()]
    body = yaml.safe_dump(_policy_to_dict(proposal.policy), sort_keys=True)
    return "\n".join(header) + "\n" + body


async def propose_policy(
    provider: ModelProvider,
    intent: str,
    *,
    tools: list[str],
    policy_dir: Path,
    proposed_dir: Path,
    name: str,
) -> tuple[Path, PolicyProposal]:
    """Author a proposal against the active policy and stage it. No activation.

    Time complexity: O(inference) + O(policy size). Space complexity: O(same).
    """
    current = load_policy(policy_dir)
    proposal = await author_policy(
        provider, intent, tools=tools, current_policy=current
    )
    await asyncio.to_thread(proposed_dir.mkdir, parents=True, exist_ok=True)
    path = proposed_dir / f"{name}.yaml"
    await asyncio.to_thread(
        path.write_text, _render_staged_file(proposal), encoding="utf-8"
    )
    return path, proposal


async def activate_policy(
    staged_file: Path,
    *,
    policy_dir: Path,
    audit_logger: AuditLogger,
    transaction_id: UUID,
) -> Path:
    """Validate a staged proposal, promote it into the policy dir, and audit it.

    Raises:
        AuthoringError: if the staged file no longer parses as a valid policy.

    Time complexity: O(file size) + O(1) audit append. Space complexity: O(file).
    """
    text = await asyncio.to_thread(staged_file.read_text, encoding="utf-8")
    try:
        PolicySchema.model_validate(yaml.safe_load(text) or {})
    except (yaml.YAMLError, ValidationError) as exc:
        raise AuthoringError(
            f"staged policy {staged_file.name} is invalid: {exc}"
        ) from exc
    target = policy_dir / staged_file.name
    await asyncio.to_thread(target.write_text, text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    await audit_logger.append(
        AuditRecord(
            transaction_id=transaction_id,
            created_at=datetime.now(UTC),
            verdict=Verdict.ALLOW,
            tool_name=None,
            details={
                "event": "policy.activated",
                "file": staged_file.name,
                "policy_sha256": digest,
            },
        )
    )
    return target


async def _run_propose(args: argparse.Namespace, settings: Settings) -> None:
    provider = load_guard_provider(settings)
    tools: list[str] = [t.strip() for t in str(args.tools).split(",") if t.strip()]
    path, proposal = await propose_policy(
        provider,
        str(args.intent),
        tools=tools,
        policy_dir=settings.policy_dir,
        proposed_dir=settings.proposed_policy_dir,
        name=str(args.name),
    )
    print(f"Staged proposal: {path}")
    print(proposal.diff.render())
    print(f"Review it, then: python -m scripts.policy_author activate {path}")


async def _run_activate(args: argparse.Namespace, settings: Settings) -> None:
    logger = AuditLogger(
        db_path=settings.db_path,
        genesis_hash=derive_genesis_hash(settings.genesis_seed),
    )
    await logger.initialize()
    try:
        target = await activate_policy(
            Path(str(args.file)),
            policy_dir=settings.policy_dir,
            audit_logger=logger,
            transaction_id=uuid4(),
        )
    finally:
        await logger.close()
    print(f"Activated: {target}")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for proposing and activating authored policies."""
    parser = argparse.ArgumentParser(description="LLM policy authoring")
    sub = parser.add_subparsers(dest="command", required=True)
    propose = sub.add_parser("propose", help="author and stage a policy proposal")
    propose.add_argument("intent", help="natural-language policy intent")
    propose.add_argument("--tools", required=True, help="comma-separated tool names")
    propose.add_argument("--name", default="proposal", help="staged file name stem")
    activate = sub.add_parser("activate", help="activate a staged proposal")
    activate.add_argument("file", help="path to the staged proposal file")
    args = parser.parse_args(argv)
    settings = Settings()
    if args.command == "propose":
        asyncio.run(_run_propose(args, settings))
    else:
        asyncio.run(_run_activate(args, settings))


if __name__ == "__main__":
    main()
