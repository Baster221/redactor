"""Mutation check: every detector, consensus and settlement guard must have a test
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

# Three guards are intentionally not mutated because no test can distinguish them:
# the payload shape check (a malformed payload fails the per-item checks anyway), and the
# two places where the detector floor is re-applied after the unanimity rule has already
# enforced it. They stay in the contract as defence in depth; listing them here as "killed"
# would be dishonest.
MUTATIONS = {
    # --- consensus
    "validator: CLEAN must be unanimous": (
        "            for f in out[\"mine\"]:\n                if f not in theirs:\n                    return False\n",
        "",
    ),
    "validator: contextual findings need this node's confirmation": (
        "                if f[0] == CONTEXTUAL and f not in confirmed:\n                    return False\n",
        "",
    ),
    "validator: every span must be in the document": (
        "                if category not in CATEGORIES or not span_is_present(text, span):\n                    return False\n",
        "",
    ),
    "validator: structured claims must satisfy their detector": (
        "                if category in STRUCTURED and not structured_detector_agrees(category, span):\n                    return False\n",
        "",
    ),
    "validator: the report must be canonical": (
        "if len(theirs) > MAX_FINDINGS or theirs != sorted(theirs):",
        "if False:",
    ),
    "validator: a leader error is not a report": ("if not isinstance(leader_result, gl.vm.Return):", "if False:"),
    "leader: keeps only spans that are really in the document": (
        "        if category not in CATEGORIES or not span_is_present(text, span):\n            continue\n",
        "",
    ),
    "leader: keeps only structured spans its detector accepts": (
        "        if category in STRUCTURED and not structured_detector_agrees(category, span):\n            continue\n",
        "",
    ),
    "leader: double-checks its own contextual findings": (
        "                confirmed = [pair for i, pair in enumerate(candidates) if i in keep]",
        "                confirmed = candidates",
    ),
    "leader: only explicit confirmations count": (
        'if not isinstance(item, dict) or item.get("sensitive") is not True:',
        "if not isinstance(item, dict):",
    ),
    # --- the deterministic floor, recomputed on-chain
    "contract: FLAGGED when anything was found": (
        "d.status = S_FLAGGED if findings else S_CLEAN",
        "d.status = S_CLEAN",
    ),
    "contract: only CLEAN documents get a certificate": (
        "        if d.status == S_CLEAN:\n            self.cleared[d.doc_hash] = u256(did)",
        "        if True:\n            self.cleared[d.doc_hash] = u256(did)",
    ),
    "contract: redacts every finding": ("d.redacted = redact(text, findings) if findings else \"\"", "d.redacted = text"),
    # --- detectors
    "detector: Luhn check on cards": (
        "    for m in CARD_RE.finditer(text):" + chr(10) + "        if luhn_ok(m.group(0)):",
        "    for m in CARD_RE.finditer(text):" + chr(10) + "        if True:",
    ),
    "detector: IBAN mod-97": ("    return remainder == 1", "    return True"),
    "detector: entropy floor on keys": ("if SECRET_HINT.search(token) and shannon_milli(token) >= ENTROPY_FLOOR_MILLI:", "if SECRET_HINT.search(token):"),
    "detector: key-shaped hint": ("if SECRET_HINT.search(token) and shannon_milli(token) >= ENTROPY_FLOOR_MILLI:", "if shannon_milli(token) >= ENTROPY_FLOOR_MILLI:"),
    "detector: phone digit range": ("if 7 <= digits <= 12 and not luhn_ok(span):", "if True:"),
    "detector: card detector accepts only card lengths": ("    if not (13 <= len(ds) <= 19):\n        return False\n", ""),
    "detector: structured gate answers per category": ('if category == CARD:\n        return luhn_ok(s)', "if category == CARD:\n        return True"),
    # --- documents and fees
    "submit: exact fee": ("if fee != int(self.scan_fee_wei):", "if False:"),
    "submit: document bounds": ("if not (MIN_DOC_CHARS <= len(text) <= MAX_DOC_CHARS):", "if False:"),
    "submit: title bounds": ("if not (3 <= len(t) <= 100):", "if False:"),
    "submit: policy bounds": ("if not (10 <= len(pol) <= 300):", "if False:"),
    "scan: runs once": ("if d.status != S_PENDING:", "if False:"),
    "scan: pays the keeper": ("self._credit(gl.message.sender_address, fee)", "self._credit(d.publisher, fee)"),
    "hash: whitespace normalised": (
        '    return "0x" + hashlib.sha256(re.sub(r"\\s+", " ", document).strip().encode("utf-8")).hexdigest()',
        '    return "0x" + hashlib.sha256(document.encode("utf-8")).hexdigest()',
    ),
    "constructor: fee range": ("if not (0 < scan_fee_wei <= 10**21):", "if False:"),
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
