"""Audit immutable dataset partitions for entity, temporal and provenance leakage."""
import argparse
import csv
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import sys

FIELDS = ("row_id", "split", "entity_id", "content_sha256", "source_id",
          "cutoff_at", "feature_max_at", "label_ready_at")
SPLITS = ("train", "validation", "test")
SQL = Path(__file__).with_name("checks.sql")


def read_bytes(path):
    data = Path(path).read_bytes()
    return data, sha256(data).hexdigest()


def utc(value):
    """Normalize offset timestamps to fixed width UTC for SQL ordering."""
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or "T" not in value:
            raise ValueError
        return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"expected an ISO timestamp with explicit timezone: {value!r}") from exc


def hash_valid(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= set("0123456789abcdef")


def ingest(db, table, data, fields):
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
    if reader.fieldnames != list(fields):
        raise ValueError(f"{table}: expected column headers {', '.join(fields)}")
    rows = []
    for row in reader:
        line = reader.line_num
        try:
            if None in row or any(not value or value != value.strip() for value in row.values()):
                raise ValueError("missing value, padding, or extra column")
            if table == "samples":
                if row["split"] not in SPLITS:
                    raise ValueError("unknown split")
                if not hash_valid(row["content_sha256"]):
                    raise ValueError("invalid content fingerprint")
                for key in ("cutoff_at", "feature_max_at", "label_ready_at"):
                    row[key] = utc(row[key])
            elif not hash_valid(row["artifact_sha256"]):
                raise ValueError("invalid declared artifact hash")
            rows.append(tuple(row[key] for key in fields))
        except ValueError as exc:
            raise ValueError(f"{table} CSV line {line}: {exc}") from exc
    if not rows:
        raise ValueError(f"{table}: empty CSV")
    try:
        db.executemany(f"INSERT INTO {table} VALUES ({','.join('?' for _ in fields)})", rows)
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"{table}: IDs must be unique") from exc


def run_audit(dataset, registry, policy):
    policy_json = json.loads(policy)
    if not isinstance(policy_json, dict) or set(policy_json) != {"train_frozen_at", "validation_frozen_at"}:
        raise ValueError("policy requires exactly train_frozen_at and validation_frozen_at")
    if not all(isinstance(v, str) for v in policy_json.values()):
        raise ValueError("policy timestamps must be strings")
    train_end = utc(policy_json["train_frozen_at"])
    val_end = utc(policy_json["validation_frozen_at"])
    if train_end >= val_end:
        raise ValueError("validation freeze must be later than the training freeze")
    with sqlite3.connect(":memory:") as db:
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE samples (
              row_id TEXT PRIMARY KEY,
              split TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              content_sha256 TEXT NOT NULL,
              source_id TEXT NOT NULL,
              cutoff_at TEXT NOT NULL,
              feature_max_at TEXT NOT NULL,
              label_ready_at TEXT NOT NULL
            );
            CREATE TABLE registry (source_id TEXT PRIMARY KEY, artifact_sha256 TEXT NOT NULL);
            CREATE INDEX samples_entity ON samples(entity_id, split);
            CREATE INDEX samples_fingerprint ON samples(content_sha256, split);
        """)
        ingest(db, "samples", dataset, FIELDS)
        ingest(db, "registry", registry, ("source_id", "artifact_sha256"))
        totals = dict(db.execute("SELECT split, count(*) FROM samples GROUP BY split").fetchall())
        if any(split not in totals for split in SPLITS):
            raise ValueError("every split must contain at least one sample")
        rows = db.execute(SQL.read_text(encoding="utf-8"), {"train_end": train_end, "val_end": val_end})
        violations = [dict(row) for row in rows]
    counts = {}
    for violation in violations:
        check = violation["check_name"]
        counts[check] = counts.get(check, 0) + 1
    return {"passed": not violations, "samples_by_split": totals, "findings_by_check": counts,
            "findings": violations, "freeze_utc": {"train": train_end, "validation": val_end}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset")
    parser.add_argument("registry")
    parser.add_argument("policy")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        inputs = [args.dataset, args.registry, args.policy]
        dataset, registry, policy = [read_bytes(path) for path in inputs]
        result = run_audit(dataset[0], registry[0], policy[0])
        result["input_sha256"] = dict(zip(("dataset", "registry", "policy"), (dataset[1], registry[1], policy[1])))
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            dest = Path(args.output).resolve()
            if dest in {Path(path).resolve() for path in inputs}:
                raise ValueError("output must not overwrite an input")
            dest.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0 if result["passed"] else 2
    except (OSError, ValueError, csv.Error, sqlite3.Error) as error:
        print(f"dataset-audit: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

