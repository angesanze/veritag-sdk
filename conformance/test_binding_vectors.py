"""Guard the cross-SDK binding contract itself.

The TS and Dart suites assert their buildBinding matches binding_vectors.json;
this asserts the JSON's expected hashes are themselves correct, so the contract
file can't drift via a typo. Run:

    attestcore/.venv/bin/python -m pytest sdk/conformance/test_binding_vectors.py -q
"""
import hashlib
import json
from pathlib import Path

VECTORS = Path(__file__).with_name("binding_vectors.json")


def test_binding_vectors_are_self_consistent():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert data["vectors"], "no vectors"
    for v in data["vectors"]:
        expected = hashlib.sha256(f"{v['uid']}|{v['context']}".encode()).hexdigest()
        assert v["binding_hex"] == expected, f"bad vector for {v['uid']}|{v['context']}"
