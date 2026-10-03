"""Mutation check: every privacy, detector, consensus and recovery guard must have a test
that fails when that guard is removed.

Usage (from the repository root): python scripts/mutation_check.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "contracts" / "redactor.py").read_text(encoding="utf8")

# Some properties are structural rather than guarded by a check, and some guards cannot be
# told apart by any test. They are deliberately absent from this list:
#   * "the chain never stores the document or its spans" is a property of the data model:
#     no method takes the text and no field holds it, so there is nothing to mutate. The
#     tests in test_privacy.py assert the property directly against stored state instead.
#   * the span length bounds in structured_detector_agrees(), which every category pattern
#     already enforces, and the re-check of a locator's bounds after slice_at() returned "".
#   * merging a validator's own confirmed spans, which can only ever contain spans the
#     leader already claimed.
# All of them stay in the contract; counting them as "killed" here would be dishonest.
MUTATIONS = {
    # --- privacy: the document and its spans must never reach storage
    "privacy: the commitment binds the scanned bytes": (
        "if not fetched or doc_hash(fetched) != committed:",
        "if not fetched:",
    ),
    "privacy: certificates are keyed by the committed hash": (
        "            self.cleared[d.doc_hash] = u256(did)",
        "            self.cleared[d.redacted_hash] = u256(did)",
    ),
    "privacy: submission validates the hash shape": (
        '        if not re.fullmatch(r"0x[0-9a-f]{64}", h):\n            raise gl.vm.UserError("document hash must be 0x + 64 hex chars")\n',
        "",
    ),
    # --- consensus
    "validator: CLEAN must be unanimous": (
        "            for locator in out[\"mine\"]:\n                if locator not in claimed:\n                    return False\n",
        "",
    ),
    "validator: every locator must check out here": (
        "            for locator in claimed:\n                if not locator_is_admissible(text, locator, out[\"ok\"]):\n                    return False\n",
        "",
    ),
    "validator: contextual findings need this node's confirmation": (
        "    return [category, start, length] in [list(c) for c in contextual_ok]",
        "    return True",
    ),
    "validator: the redaction hash must match": (
        'return str(theirs.get("redacted_hash", "")) == expected_hash',
        "return True",
    ),
    "validator: the verdict must follow the findings": (
        "            if verdict != (V_FLAGGED if claimed else V_CLEAN):\n                return False\n",
        "",
    ),
    "validator: the report must be canonical": (
        "if len(claimed) != len(theirs[\"findings\"]) or canonical(claimed) != claimed:",
        "if False:",
    ),
    "validator: unreachable and mismatched documents settle nothing": (
        "                return verdict == out[\"verdict\"] and not claimed",
        "                return True",
    ),
    "validator: a leader error is not a report": ("if not isinstance(leader_result, gl.vm.Return):", "if False:"),
    # --- the leader's own discipline
    "leader: model spans must be found in the document": (
        "        start = text.find(span)\n        if start < 0 or (start, len(span)) in seen:\n            continue\n",
        "        start = text.find(span)\n        if (start, len(span)) in seen:\n            continue\n",
    ),
    "leader: contextual spans need the second pass": (
        "                confirmed = [c for i, c in enumerate(candidates) if i in keep]",
        "                confirmed = candidates",
    ),
    "leader: only explicit confirmations count": (
        'if not isinstance(item, dict) or item.get("sensitive") is not True:',
        "if not isinstance(item, dict):",
    ),
    "detector: Luhn check on cards": (
        "    for m in CARD_RE.finditer(text):\n        if luhn_ok(m.group(0)):",
        "    for m in CARD_RE.finditer(text):\n        if True:",
    ),
    "detector: IBAN mod-97": ("    return remainder == 1", "    return True"),
    "detector: entropy floor on keys": ("if SECRET_HINT.search(token) and shannon_milli(token) >= ENTROPY_FLOOR_MILLI:", "if SECRET_HINT.search(token):"),
    "detector: key-shaped hint": ("if SECRET_HINT.search(token) and shannon_milli(token) >= ENTROPY_FLOOR_MILLI:", "if shannon_milli(token) >= ENTROPY_FLOOR_MILLI:"),
    "detector: phone digit range": ("if 7 <= digits <= 12 and not luhn_ok(span):", "if True:"),
    "detector: card detector accepts only card lengths": ("    if not (13 <= len(ds) <= 19):\n        return False\n", ""),
    "detector: structured gate answers per category": ('if category == CARD:\n        return luhn_ok(s)', "if category == CARD:\n        return True"),
    "redaction: every located span is masked": (
        "        out.append(text[cursor:start])\n        out.append(MASK)",
        "        out.append(text[cursor:start])\n        out.append(text[start:start + length])",
    ),
    # --- submission, fees and the recovery path
    "submit: exact fee": ("if fee != int(self.scan_fee_wei):", "if False:"),
    "submit: https-only urls": ('    m = URL_RE.fullmatch(url)\n    if m is None:\n        raise gl.vm.UserError("url must be a plain https url")\n', "    m = URL_RE.match(url)\n"),
    "submit: no credentials, ports or IP hosts": ('    if "@" in host or ":" in host or re.fullmatch(r"[0-9.]+", host):\n        raise gl.vm.UserError("url host must be a plain domain name")\n', ""),
    "submit: url length": ("if not (12 <= len(url) <= MAX_URL):", "if False:"),
    "submit: scan window bounds": ("if not (MIN_SCAN_WINDOW <= scan_window_seconds <= MAX_SCAN_WINDOW):", "if False:"),
    "scan: runs once": ("if d.status != S_PENDING:\n            raise gl.vm.UserError(\"document already settled\")\n        if self._now() >= int(d.scan_deadline):", "if False:\n            raise gl.vm.UserError(\"document already settled\")\n        if self._now() >= int(d.scan_deadline):"),
    "scan: stops at the deadline": ("if self._now() >= int(d.scan_deadline):\n            raise gl.vm.UserError(\"scan window closed; the publisher can abandon\")", "if False:\n            raise gl.vm.UserError(\"scan window closed; the publisher can abandon\")"),
    "scan: pays the keeper": ("fee = self._release_fee(d, gl.message.sender_address)", "fee = self._release_fee(d, d.publisher)"),
    "abandon: publisher only": ("if gl.message.sender_address != d.publisher:", "if False:"),
    "abandon: waits for the deadline": ("if self._now() < int(d.scan_deadline):", "if False:"),
    "abandon: only while still pending": ('        if d.status != S_PENDING:\n            raise gl.vm.UserError("document already settled")\n        if self._now() < int(d.scan_deadline):', "        if False:\n            pass\n        if self._now() < int(d.scan_deadline):"),
    "abandon: refunds the publisher": ("refund = self._release_fee(d, d.publisher)", "refund = 0"),
}


def main() -> int:
    survivors = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, (old, new) in MUTATIONS.items():
            if old not in SOURCE:
                print(f"[stale]    {name}: pattern not found")
                survivors.append(name)
                continue
            mutant = Path(tmp) / "mutant.py"
            mutant.write_text(SOURCE.replace(old, new, 1), encoding="utf8")
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x"],
                cwd=ROOT, env={**os.environ, "RD_CONTRACT": str(mutant)},
                capture_output=True, text=True,
            )
            killed = proc.returncode != 0
            print(f"[{'killed' if killed else 'SURVIVED'}] {name}")
            if not killed:
                survivors.append(name)
    print(f"\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutants killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
