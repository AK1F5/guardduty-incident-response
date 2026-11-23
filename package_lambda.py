import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

root = Path(__file__).resolve().parent
output = root / "build" / "handler.zip"
output.parent.mkdir(exist_ok=True)
with ZipFile(output, "w") as bundle:
    for path in sorted((root / "app").glob("*.py")):
        entry = ZipInfo(path.relative_to(root).as_posix(), (2026, 1, 1, 0, 0, 0))
        bundle.writestr(entry, path.read_bytes(), compress_type=ZIP_DEFLATED)
digest = hashlib.sha256(output.read_bytes()).hexdigest()
print(f"guardduty-case-tracker/{digest}.zip")
