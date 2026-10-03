import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

if sys.platform == "win32":
    # gltest's direct loader unlinks the message temp file while it is still
    # dup2'd onto stdin, which Windows refuses. Deleting it later is harmless.
    _real_unlink = os.unlink
    _tmp = os.path.normcase(tempfile.gettempdir())

    def _tolerant_unlink(path, *args, **kwargs):
        try:
            return _real_unlink(path, *args, **kwargs)
        except PermissionError:
            if not os.path.normcase(str(path)).startswith(_tmp):
                raise

    os.unlink = _tolerant_unlink

CONTRACT = os.environ.get("RD_CONTRACT") or str(
    Path(__file__).resolve().parents[2] / "contracts" / "redactor.py"
)

GEN = 10**18
FEE = GEN // 10
WINDOW = 3600
T0 = "2026-10-03T09:00:00Z"
T0_TS = int(__import__("datetime").datetime.fromisoformat(T0.replace("Z", "+00:00")).timestamp())
SCAN_RE = r"screening a document before publication"
CONFIRM_RE = r"double-checking contextual privacy findings"

POLICY = "no personal data, payment details or credentials may appear in published notes"
URL = "https://docs.example.org/drafts/handover-2026-10.txt"
URL_RE = r"docs\.example\.org/drafts/handover"

CLEAN_DOC = (
    "Release notes for the indexer: we reduced reorg handling latency, added a health endpoint "
    "and documented the retry policy. The upgrade window opens on Thursday and no action is "
    "required from operators."
)

# 4111111111111111 passes Luhn; 4111111111111112 does not. GB82WEST12345698765432 is a valid IBAN.
DIRTY_DOC = (
    "Support handover: the customer wrote from mia.chen@example.com and called +44 20 7946 0958. "
    "Her card 4111 1111 1111 1111 was declined twice, the refund goes to GB82WEST12345698765432, "
    "and the staging key sk_live_9fQ2xTb7Lm4Zc8Rv1Kd3 still works."
)

CONTEXTUAL_DOC = (
    "Incident notes: our contractor Dana Kovacs is on sick leave after surgery and has asked for a "
    "salary advance, so the migration slipped by a week. The steering group will review timelines "
    "on Monday and publish an updated plan."
)
CONTEXTUAL_SPAN = (
    "our contractor Dana Kovacs is on sick leave after surgery and has asked for a salary advance"
)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip()


def hash_of(text: str) -> str:
    return "0x" + hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()


def spans_answer(*spans):
    return json.dumps({"findings": [{"span": s} for s in spans]})


def confirm_answer(*, sensitive=True, count=6):
    return json.dumps({"results": [{"id": i, "sensitive": sensitive} for i in range(count)]})


def mock_scan(vm, document, spans_json=None, confirm_json=None, url_pattern=URL_RE, clear=True):
    """Mock the fetch and both model passes."""
    if clear:
        vm.clear_mocks()
    vm.mock_web(url_pattern, {"status": 200, "body": document})
    vm.mock_llm(CONFIRM_RE, confirm_json if confirm_json is not None else confirm_answer())
    vm.mock_llm(SCAN_RE, spans_json if spans_json is not None else spans_answer())


def warp(vm, iso):
    vm.warp(iso)
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = iso


def at(seconds: int) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(T0_TS + seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def env(direct_vm, direct_deploy):
    from gltest.direct import create_address

    warp(direct_vm, T0)
    c = direct_deploy(CONTRACT, FEE)
    publisher = create_address("publisher")
    keeper = create_address("keeper")
    stranger = create_address("stranger")
    return {"vm": direct_vm, "c": c, "publisher": publisher, "keeper": keeper, "stranger": stranger}


def submit(env, document=CLEAN_DOC, *, title="Weekly notes", policy=POLICY, url=URL,
           document_hash=None, window=WINDOW, fee=FEE, sender=None):
    vm = env["vm"]
    vm.sender = sender or env["publisher"]
    vm.value = fee
    try:
        return env["c"].submit(title, policy, url, document_hash or hash_of(document), window)
    finally:
        vm.value = 0


def scan(env, did, document, spans_json=None, confirm_json=None, sender=None, url_pattern=URL_RE):
    mock_scan(env["vm"], document, spans_json, confirm_json, url_pattern)
    env["vm"].sender = sender or env["keeper"]
    return env["c"].scan(did)


def locators(out):
    return [(f["category"], f["start"], f["length"]) for f in out["findings"]]
