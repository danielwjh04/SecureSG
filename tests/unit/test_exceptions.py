"""Tests for the SecureSG exception hierarchy."""

from secureSG.exceptions import (
    AuditError,
    AuthoringError,
    ChainIntegrityError,
    InferenceError,
    ModelError,
    ModelLoadError,
    SecureSGError,
)


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


def test_model_error_is_securesg_error() -> None:
    assert issubclass(ModelError, SecureSGError)


def test_model_load_error_is_model_error() -> None:
    assert issubclass(ModelLoadError, ModelError)


def test_inference_error_is_model_error() -> None:
    assert issubclass(InferenceError, ModelError)


def test_model_errors_carry_message() -> None:
    err = ModelLoadError("weights not found at /x")
    assert str(err) == "weights not found at /x"
    assert isinstance(err, SecureSGError)


def test_authoring_error_is_securesg_error() -> None:
    assert issubclass(AuthoringError, SecureSGError)
    assert isinstance(AuthoringError("bad policy proposal"), SecureSGError)
