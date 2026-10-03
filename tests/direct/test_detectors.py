"""The deterministic layer: Luhn, IBAN mod-97, entropy, phone and email shapes, redaction."""

import pytest

from conftest import CLEAN_DOC, DIRTY_DOC, submit


def cats(out):
    return out["categories"]


def test_detects_every_structured_category(env):
    out = env["c"].detect(DIRTY_DOC)
    assert cats(out) == ["API_KEY", "EMAIL", "IBAN", "PAYMENT_CARD", "PHONE"]
    spans = {f["category"]: f["span"] for f in out["findings"]}
    assert spans["EMAIL"] == "mia.chen@example.com"
    assert spans["PAYMENT_CARD"] == "4111 1111 1111 1111"
    assert spans["IBAN"] == "GB82WEST12345698765432"
    assert spans["API_KEY"] == "sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3"
    assert "+44 20 7946 0958" in spans["PHONE"]


def test_clean_document_has_nothing_to_find(env):
    out = env["c"].detect(CLEAN_DOC)
    assert out["findings"] == [] and out["redacted"] == CLEAN_DOC


def test_redaction_masks_every_span(env):
    out = env["c"].detect(DIRTY_DOC)
    red = out["redacted"]
    for probe in ["mia.chen@example.com", "4111 1111 1111 1111", "GB82WEST12345698765432",
                  "sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3"]:
        assert probe not in red
    assert red.count("[redacted]") >= 5
    assert "Support handover" in red      # nothing else is touched


@pytest.mark.parametrize(
    "number, is_card",
    [
        ("4111 1111 1111 1111", True),
        ("4111-1111-1111-1111", True),
        ("5500005555555559", True),
        ("3782 822463 10005", True),   # Amex grouping
        ("4111111111111111", True),
        ("4111 1111 1111 1112", False),   # fails Luhn
        ("1234 5678 9012 3456", False),
        ("1234567890", False),            # too short for a card
    ],
)
def test_luhn_gate_on_card_numbers(env, number, is_card):
    out = env["c"].check_span("PAYMENT_CARD", number)
    assert out["detector_agrees"] is is_card


@pytest.mark.parametrize(
    "iban, valid",
    [
        ("GB82WEST12345698765432", True),
        ("DE89370400440532013000", True),
        ("GB82WEST12345698765433", False),   # fails mod-97
        ("XX00NOTANIBAN12345", False),
    ],
)
def test_iban_mod97(env, iban, valid):
    assert env["c"].check_span("IBAN", iban)["detector_agrees"] is valid


@pytest.mark.parametrize(
    "token, is_secret",
    [
        ("sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3", True),
        ("api_key_aaaaaaaaaaaaaaaaaaaaaa", False),    # long, hinted, but low entropy
        ("9fQ2xTb7Lm4Zc8Rv1Kd3Wp6Yh", False),         # high entropy, no key-like hint
        ("token_short1", False),                       # below the minimum length
    ],
)
def test_entropy_and_hint_gate_on_keys(env, token, is_secret):
    out = env["c"].check_span("API_KEY", token)
    assert out["detector_agrees"] is is_secret


def test_entropy_is_reported_for_auditors(env):
    low = env["c"].check_span("API_KEY", "api_key_aaaaaaaaaaaaaaaaaaaaaa")["entropy_milli"]
    high = env["c"].check_span("API_KEY", "sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3")["entropy_milli"]
    assert low < 3200 <= high


def test_phone_detector_does_not_swallow_card_numbers(env):
    out = env["c"].detect("Call 020 7946 0958 about card 4111 1111 1111 1111 please today")
    phones = [f["span"] for f in out["findings"] if f["category"] == "PHONE"]
    cards = [f["span"] for f in out["findings"] if f["category"] == "PAYMENT_CARD"]
    assert cards == ["4111 1111 1111 1111"]
    assert len(phones) == 1 and "0958" in phones[0] and "4111" not in phones[0]


def test_a_phone_next_to_a_card_is_still_found(env):
    """Card digits are masked before the phone scan, so neither hides the other."""
    out = env["c"].detect("Card 4111 1111 1111 1111 020 7946 0958 is the callback line for today")
    by_cat = {f["category"] for f in out["findings"]}
    assert by_cat == {"PAYMENT_CARD", "PHONE"}
    phone = next(f["span"] for f in out["findings"] if f["category"] == "PHONE")
    assert phone.strip() == "020 7946 0958"


def test_short_digit_groups_are_not_phone_numbers(env):
    out = env["c"].detect("Meeting at 10 30 in room 12 14 tomorrow, bring the 24 25 slides along")
    assert [f for f in out["findings"] if f["category"] == "PHONE"] == []


def test_long_reference_numbers_are_neither_cards_nor_phones(env):
    """16 digits that fail Luhn are a reference number, not a card and not a phone."""
    assert env["c"].detect("Reference number 4111 1111 1111 1112 is safe to publish today")["findings"] == []


def test_low_entropy_key_shaped_tokens_are_not_secrets(env):
    doc = "The placeholder api_key_aaaaaaaaaaaaaaaaaaaaaa is documented in the sample config file"
    assert env["c"].detect(doc)["findings"] == []


def test_version_numbers_are_not_phone_numbers(env):
    out = env["c"].detect("We shipped release 1.2.3 and bumped the indexer to build 4567 today")
    assert out["findings"] == []


def test_contextual_category_has_no_deterministic_detector(env):
    out = env["c"].check_span("CONTEXTUAL_PII", "anything at all")
    assert out["known_category"] is True and out["detector_agrees"] is False


def test_doc_hash_is_whitespace_insensitive(env):
    a = env["c"].detect(CLEAN_DOC)["doc_hash"]
    b = env["c"].detect("   " + CLEAN_DOC.replace(" ", "  ") + "   ")["doc_hash"]
    assert a == b and a.startswith("0x") and len(a) == 66
