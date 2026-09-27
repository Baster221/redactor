import json
import os
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
T0 = "2026-09-28T09:00:00Z"
SCAN_RE = r"screening a document before publication"
CONFIRM_RE = r"double-checking contextual privacy findings"

POLICY = "no personal data, payment details or credentials may appear in published notes"

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


def findings_answer(*pairs):
    return json.dumps({"findings": [{"category": c, "span": s} for c, s in pairs]})


def confirm_answer(*, sensitive=True, count=4):
    return json.dumps({"results": [{"id": i, "sensitive": sensitive} for i in range(count)]})


def mock_scanner(vm, findings_json, confirm_json=None, clear=True):
    """Mock both model passes: the scan itself and the contextual double-check."""
    if clear:
        vm.clear_mocks()
    vm.mock_llm(CONFIRM_RE, confirm_json if confirm_json is not None else confirm_answer())
    vm.mock_llm(SCAN_RE, findings_json)


def warp(vm, iso):
    vm.warp(iso)
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = iso


@pytest.fixture
def env(direct_vm, direct_deploy):
    from gltest.direct import create_address

    warp(direct_vm, T0)
    c = direct_deploy(CONTRACT, FEE)
    publisher = create_address("publisher")
    keeper = create_address("keeper")
    stranger = create_address("stranger")
    return {"vm": direct_vm, "c": c, "publisher": publisher, "keeper": keeper, "stranger": stranger}


def submit(env, document=CLEAN_DOC, title="Weekly notes", policy=POLICY, sender=None, fee=FEE):
    vm = env["vm"]
    vm.sender = sender or env["publisher"]
    vm.value = fee
    try:
        return env["c"].submit(title, policy, document)
    finally:
        vm.value = 0


def scan(env, did, findings_json=None, confirm_json=None, sender=None):
    mock_scanner(env["vm"], findings_json if findings_json is not None else findings_answer(), confirm_json)
    env["vm"].sender = sender or env["keeper"]
    return env["c"].scan(did)
