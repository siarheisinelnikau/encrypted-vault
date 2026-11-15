"""Verify vendored cryptographic source against upstream Git blob IDs."""
from pathlib import Path
import hashlib
import json
import sys

root = Path(__file__).resolve().parents[1] / "vendor/argon2"
manifest = json.loads((root / "PROVENANCE.json").read_text(encoding="utf-8"))
normalize = "--normalize-line-endings" in sys.argv
for entry in manifest["files"]:
    path = root / entry["path"]
    original = path.read_bytes()
    candidates = [original]
    if normalize:
        data = original.replace(b"\r\n", b"\n")
        candidates += [data, data.rstrip(b"\n") + b"\n", data.rstrip(b"\n")]
    found = None
    for candidate in candidates:
        blob = b"blob " + str(len(candidate)).encode() + b"\0" + candidate
        if hashlib.sha1(blob).hexdigest() == entry["gitBlob"]:
            found = candidate
            break
    if found is None:
        raise SystemExit(f"Upstream source integrity mismatch: {entry['path']}")
    if normalize and original != found:
        path.write_bytes(found)
print(f"Verified {len(manifest['files'])} upstream files from {manifest['ref']}.")
