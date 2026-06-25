"""Tests for the SecureSG exception hierarchy."""

from secureSG.exceptions import AuditError, ChainIntegrityError, SecureSGError


def test_securesg_error_is_exception() -> None:
    assert issubclass(SecureSGError, Exception)


def test_audit_error_is_securesg_error() -> None:
    assert issubclass(AuditError, SecureSGError)


def test_chain_integrity_error_is_audit_error() -> None:
    assert issubclass(ChainIntegrityError, AuditError)


def test_chain_integrity_error_carries_message() -> None:
    err = ChainIntegrityError("chain broken at seq 3")
    assert str(err) == "chain broken at seq 3"
    assert isinstance(err, SecureSGError)
