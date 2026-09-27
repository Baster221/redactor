"""Submission, fees, single-scan semantics, certificates and accounting."""

import pytest

from conftest import CLEAN_DOC, DIRTY_DOC, FEE, GEN, POLICY, findings_answer, scan, submit


@pytest.mark.parametrize(
    "title, policy, document, fee, message",
    [
        ("Weekly notes", POLICY, CLEAN_DOC, FEE - 1, "exactly the scan fee"),
        ("Weekly notes", POLICY, CLEAN_DOC, FEE + 1, "exactly the scan fee"),
        ("W", POLICY, CLEAN_DOC, FEE, "title must be"),
        ("Weekly notes", "short", CLEAN_DOC, FEE, "policy must be"),
        ("Weekly notes", POLICY, "too short to be a document", FEE, "document must be"),
        ("Weekly notes", POLICY, "x" * 4001, FEE, "document must be"),
    ],
)
def test_submission_validation(env, title, policy, document, fee, message):
    with env["vm"].expect_revert(message):
        submit(env, document, title=title, policy=policy, fee=fee)


def test_document_is_stored_normalized(env):
    did = submit(env, "  " + CLEAN_DOC.replace(" ", "   ") + "  ")
    doc = env["c"].get_document(did)
    assert doc["text"] == CLEAN_DOC
    assert doc["status"] == "PENDING" and doc["publisher"] == env["publisher"].as_hex


def test_scan_pays_the_keeper_and_runs_once(env):
    c, vm = env["c"], env["vm"]
    did = submit(env, CLEAN_DOC)
    assert c.get_accounting() == {"documents": 1, "total_fees_held_wei": FEE, "total_credits_wei": 0}

    out = scan(env, did)
    assert out["fee_paid_wei"] == FEE
    assert c.get_credit(env["keeper"].as_hex) == FEE
    assert c.get_accounting() == {"documents": 1, "total_fees_held_wei": 0, "total_credits_wei": FEE}

    vm.sender = env["stranger"]
    with vm.expect_revert("already scanned"):
        c.scan(did)


def test_certificate_is_bound_to_the_exact_text(env):
    c = env["c"]
    did = submit(env, CLEAN_DOC)
    scan(env, did)
    assert c.is_cleared(CLEAN_DOC)["cleared"] is True
    assert c.is_cleared(CLEAN_DOC + " One more sentence was added later.")["cleared"] is False


def test_flagged_document_keeps_a_redaction_and_no_certificate(env):
    c = env["c"]
    did = submit(env, DIRTY_DOC)
    out = scan(env, did, findings_answer())
    doc = c.get_document(did)
    assert out["status"] == "FLAGGED"
    assert doc["redacted"].count("[redacted]") >= 5
    assert c.is_cleared(DIRTY_DOC)["cleared"] is False
    assert doc["scanner"] == env["keeper"].as_hex and doc["scanned_at"] > 0


def test_two_documents_with_the_same_text(env):
    c = env["c"]
    first = submit(env, CLEAN_DOC)
    scan(env, first)
    second = submit(env, CLEAN_DOC)
    assert c.is_cleared(CLEAN_DOC)["document_id"] == first
    scan(env, second)
    assert c.is_cleared(CLEAN_DOC)["document_id"] == second   # the latest certificate wins


def test_config_and_unknown_ids(env):
    cfg = env["c"].get_config()
    assert cfg["scan_fee_wei"] == FEE
    assert cfg["categories"][-1] == "CONTEXTUAL_PII"
    assert cfg["entropy_floor_milli"] == 3200
    with env["vm"].expect_revert("unknown document"):
        env["c"].get_document(7)


def test_withdraw_guard(env):
    env["vm"].sender = env["stranger"]
    with env["vm"].expect_revert("nothing to withdraw"):
        env["c"].withdraw()


def test_constructor_validates_the_fee(direct_vm, direct_deploy):
    from conftest import CONTRACT

    with direct_vm.expect_revert("scan fee out of range"):
        direct_deploy(CONTRACT, 0)
