"""Submission, the scan window, the abandon path, fees and accounting."""

import pytest

from conftest import (
    CLEAN_DOC,
    CONTEXTUAL_DOC,
    CONTEXTUAL_SPAN,
    DIRTY_DOC,
    FEE,
    GEN,
    POLICY,
    URL,
    WINDOW,
    at,
    hash_of,
    mock_scan,
    scan,
    spans_answer,
    submit,
    warp,
)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"fee": FEE - 1}, "exactly the scan fee"),
        ({"fee": FEE + 1}, "exactly the scan fee"),
        ({"title": "W"}, "title must be"),
        ({"policy": "short"}, "policy must be"),
        ({"document_hash": "0xdeadbeef"}, "document hash must be"),
        ({"document_hash": "not-a-hash"}, "document hash must be"),
        ({"window": 60}, "scan window must be"),
        ({"window": 40 * 86400}, "scan window must be"),
        ({"url": "http://docs.example.org/draft.txt"}, "plain https url"),
        ({"url": "https://user@docs.example.org/draft.txt"}, "plain domain name"),
        ({"url": "https://docs.example.org:8443/draft.txt"}, "plain domain name"),
        ({"url": "https://93.184.216.34/draft.txt"}, "plain domain name"),
        ({"url": "https://a.b"}, "url must be 12-300 chars"),
    ],
)
def test_submission_validation(env, kwargs, message):
    with env["vm"].expect_revert(message):
        submit(env, CLEAN_DOC, **kwargs)


def test_submission_records_only_commitments(env):
    did = submit(env, CLEAN_DOC)
    doc = env["c"].get_document(did)
    assert doc["doc_hash"] == hash_of(CLEAN_DOC)
    assert doc["url"] == URL
    assert doc["status"] == "PENDING" and doc["publisher"] == env["publisher"].as_hex
    assert doc["scan_deadline"] > doc["scanned_at"] == 0
    assert env["c"].get_accounting() == {"documents": 1, "total_fees_held_wei": FEE, "total_credits_wei": 0}


def test_scan_pays_the_keeper_and_runs_once(env):
    c, vm = env["c"], env["vm"]
    did = submit(env, CLEAN_DOC)
    out = scan(env, did, CLEAN_DOC)
    assert out["fee_paid_wei"] == FEE
    assert c.get_credit(env["keeper"].as_hex) == FEE
    assert c.get_accounting() == {"documents": 1, "total_fees_held_wei": 0, "total_credits_wei": FEE}

    vm.sender = env["stranger"]
    with vm.expect_revert("already settled"):
        c.scan(did)


# ---------------------------------------------------------------- the recovery path
def test_a_document_that_never_settles_can_be_abandoned_for_a_refund(env):
    """Repeated validator disagreement leaves the document PENDING; the publisher is not stuck."""
    c, vm = env["c"], env["vm"]

    # A round that cannot settle: the leader's model sees nothing while this node's model
    # finds contextual PII. On a real network the transaction reaches no consensus and
    # writes nothing, which is what leaves a document PENDING forever.
    disputed = submit(env, CONTEXTUAL_DOC)
    scan(env, disputed, CONTEXTUAL_DOC)
    mock_scan(vm, CONTEXTUAL_DOC, spans_answer(CONTEXTUAL_SPAN))
    assert vm.run_validator() is False

    # The document in that situation stays PENDING, so the publisher uses the exit.
    did = submit(env, CONTEXTUAL_DOC, title="Second attempt")
    assert c.get_document(did)["status"] == "PENDING"

    vm.sender = env["publisher"]
    with vm.expect_revert("scan window still open"):
        c.abandon(did)

    warp(vm, at(WINDOW))
    vm.sender = env["keeper"]
    with vm.expect_revert("scan window closed"):
        c.scan(did)

    vm.sender = env["stranger"]
    with vm.expect_revert("only the publisher"):
        c.abandon(did)

    vm.sender = env["publisher"]
    assert c.abandon(did) == FEE
    doc = c.get_document(did)
    assert (doc["status"], doc["reason"]) == ("ABANDONED", "abandoned_after_deadline")
    assert c.get_credit(env["publisher"].as_hex) == FEE
    assert c.get_document(did)["fee_wei"] == 0


def test_abandon_cannot_take_the_fee_twice_or_after_a_scan(env):
    c, vm = env["c"], env["vm"]
    did = submit(env, CLEAN_DOC)
    scan(env, did, CLEAN_DOC)
    warp(vm, at(WINDOW + 1))
    vm.sender = env["publisher"]
    with vm.expect_revert("already settled"):
        c.abandon(did)

    second = submit(env, DIRTY_DOC)
    warp(vm, at(3 * WINDOW))
    vm.sender = env["publisher"]
    c.abandon(second)
    with vm.expect_revert("already settled"):
        c.abandon(second)
    assert c.get_credit(env["publisher"].as_hex) == FEE


def test_a_rescan_after_a_failed_round_still_works(env):
    """Nothing was written by the failed round, so the next keeper simply tries again."""
    c = env["c"]
    did = submit(env, CONTEXTUAL_DOC)
    scan(env, did, CONTEXTUAL_DOC)                         # settled CLEAN in this node's view
    assert c.get_document(did)["status"] == "CLEAN"

    # a different document whose first scan hit a hash mismatch and changed nothing
    other = submit(env, DIRTY_DOC)
    out = scan(env, other, DIRTY_DOC + " changed after submission")
    assert out["reason"] == "HASH_MISMATCH" and c.get_document(other)["status"] == "PENDING"
    assert c.get_accounting()["total_fees_held_wei"] == FEE          # the fee is still escrowed
    out = scan(env, other, DIRTY_DOC)
    assert out["status"] == "FLAGGED" and out["fee_paid_wei"] == FEE


def test_config_and_unknown_ids(env):
    cfg = env["c"].get_config()
    assert cfg["scan_fee_wei"] == FEE
    assert cfg["categories"][-1] == "CONTEXTUAL_PII"
    assert (cfg["min_scan_window"], cfg["max_scan_window"]) == (600, 30 * 86400)
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
