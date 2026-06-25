"""Typed exception hierarchy for SecureSG.

Every error raised inside SecureSG derives from :class:`SecureSGError` so callers
can catch the whole family with a single ``except``. Subsystems extend their own
branch (the audit branch is defined here; the guard/warden branches are added by
the cycles that raise them).
"""


class SecureSGError(Exception):
    """Base class for every SecureSG error."""


class AuditError(SecureSGError):
    """Base class for failures in the audit subsystem."""


class ChainIntegrityError(AuditError):
    """Raised when the audit hash chain fails an integrity check."""


class PolicyError(SecureSGError):
    """Raised when a policy file cannot be loaded or is malformed."""


class ModelError(SecureSGError):
    """Base class for failures in the semantic model subsystem."""


class ModelLoadError(ModelError):
    """Raised when guard-model weights cannot be loaded at startup."""


class InferenceError(ModelError):
    """Raised when an inference fails or yields a degenerate, unusable result."""
