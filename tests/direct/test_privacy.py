"""The chain must never hold the document, the sensitive spans, or the redacted text."""

import json

from conftest import (
    CLEAN_DOC,
    CONTEXTUAL_DOC,
    CONTEXTUAL_SPAN,
    DIRTY_DOC,
    hash_of,
    scan,
    spans_answer,
    submit,
)

SECRETS = ["mia.chen@example.com", "4111 1111 1111 1111", "GB82WEST12345698765432",
           "sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3", "+44 20 7946 0958"]


def stored_blob(env, did):
    """Everything a reader of the chain can see about this document."""
    return json.dumps(env["c"].get_document(did))


def test_submission_never_carries_the_document(env):
    did = submit(env, DIRTY_DOC)
    blob = stored_blob(env, did)
    for secret in SECRETS:
        assert secret not in blob
    assert "Support handover" not in blob            # not even the harmless prose
    doc = env["c"].get_document(did)
    assert doc["doc_hash"] == hash_of(DIRTY_DOC)
    assert doc["url"].startswith("https://") and doc["status"] == "PENDING"


def test_a_flagged_report_stores_locations_not_text(env):
    did = submit(env, DIRTY_DOC)
    out = scan(env, did, DIRTY_DOC)
    assert out["status"] == "FLAGGED"
    assert out["categories"] == ["API_KEY", "EMAIL", "IBAN", "PAYMENT_CARD", "PHONE"]

    blob = stored_blob(env, did)
    for secret in SECRETS:
        assert secret not in blob
    assert "[redacted]" not in blob                   # not even the redacted copy is stored
    doc = env["c"].get_document(did)
    assert all(set(f) == {"category", "start", "length"} for f in doc["findings"])
    assert doc["redacted_hash"].startswith("0x") and len(doc["redacted_hash"]) == 66


def test_contextual_findings_are_stored_as_offsets_too(env):
    did = submit(env, CONTEXTUAL_DOC)
    out = scan(env, did, CONTEXTUAL_DOC, spans_answer(CONTEXTUAL_SPAN))
    assert out["categories"] == ["CONTEXTUAL_PII"]
    blob = stored_blob(env, did)
    assert "Dana Kovacs" not in blob and "sick leave" not in blob
    start, length = out["findings"][0]["start"], out["findings"][0]["length"]
    assert CONTEXTUAL_DOC[start:start + length] == CONTEXTUAL_SPAN


def test_the_locators_are_enough_to_rebuild_the_redaction_locally(env):
    """The publisher holds the text; the chain holds offsets. Together they reproduce the result."""
    did = submit(env, DIRTY_DOC)
    out = scan(env, did, DIRTY_DOC)
    local = env["c"].verify_locally(did, DIRTY_DOC)
    assert local["hash_matches"] is True and local["redaction_matches"] is True
    for secret in SECRETS:
        assert secret not in local["redacted"]
    assert local["redacted"].count("[redacted]") == 5
    assert set(local["spans"]) == set(SECRETS)
    assert out["redacted_hash"] == hash_of(local["redacted"])


def test_verify_locally_rejects_the_wrong_text(env):
    did = submit(env, DIRTY_DOC)
    scan(env, did, DIRTY_DOC)
    other = env["c"].verify_locally(did, DIRTY_DOC.replace("mia.chen", "max.chen"))
    assert other["hash_matches"] is False


def test_certificates_are_looked_up_by_hash_not_by_text(env):
    did = submit(env, CLEAN_DOC)
    out = scan(env, did, CLEAN_DOC)
    assert out["status"] == "CLEAN"
    assert env["c"].is_cleared(hash_of(CLEAN_DOC)) == {
        "cleared": True, "document_id": did, "doc_hash": hash_of(CLEAN_DOC)
    }
    assert env["c"].is_cleared(hash_of(CLEAN_DOC + " extra sentence."))["cleared"] is False


def test_the_scan_refuses_a_document_that_does_not_match_its_commitment(env):
    """Swapping the document after submitting it cannot produce a certificate."""
    did = submit(env, CLEAN_DOC)
    out = scan(env, did, CLEAN_DOC + " PS: call mia.chen@example.com for the password.")
    assert (out["status"], out["reason"]) == ("PENDING", "HASH_MISMATCH")
    assert out["fee_paid_wei"] == 0
    assert env["c"].get_document(did)["status"] == "PENDING"
    assert env["vm"].run_validator() is True


def test_an_unreachable_document_settles_nothing(env):
    did = submit(env, CLEAN_DOC)
    env["vm"].clear_mocks()                      # the fetch raises on every node
    env["vm"].sender = env["keeper"]
    out = env["c"].scan(did)
    assert (out["status"], out["reason"], out["fee_paid_wei"]) == ("PENDING", "UNREACHABLE", 0)
    assert env["vm"].run_validator() is True
