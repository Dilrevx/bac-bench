#!/usr/bin/env python3
"""Deterministic, offline normalization of the pinned BAC-Bench index.

This module uses only the Python 3.9+ standard library. It does not clone target
repositories, execute dataset commands, run PoCs, or perform model evaluation.
The CLI verifies every upstream data/ blob before writing derived files. Existing
derived files are never overwritten: identical bytes are a no-op, and differing
bytes require an explicit, separately reviewed removal or mechanical update.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit


UPSTREAM_REPOSITORY = "https://github.com/avduarte333/Absentia"
UPSTREAM_COMMIT = "80e30361ebe3d6a779886ecb42a8ecbe7e75a561"
RAW_PATH = "data/authz_instances.jsonl"
RAW_SHA256 = "c630f6c4b2b576ac893797a5d3ca4a3df93aa4e22f83d20226080ba748a58607"
CASES_PATH = "datasets/bac-bench/cases.jsonl"
SOURCE_PATH = "datasets/bac-bench/source.json"
SUMMARY_PATH = "datasets/bac-bench/summary.json"
CASE_SCHEMA = "bac.case.v1"
NORMALIZATION_VERSION = "bac-normalize-v1"
LICENSE_NOTE = "No explicit upstream data license; no blanket relicensing"
EXPECTED_COUNTS = {
    "advisories": 30,
    "repositories": 25,
    "vulnerable_snapshots": 30,
    "fixed_snapshots": 30,
    "sink_ranges": 87,
}
PROMOTED_RAW_FIELDS = frozenset(
    {"id", "repo", "language", "framework", "vulnerable_commit", "fixed_commit"}
)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
COMMIT_PATTERN = re.compile(r"[a-f0-9]{40}", re.I)


class NormalizationError(ValueError):
    """Input, provenance, or derived artifacts violate the data contract."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical record hashing and pretty-printed metadata serialization."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def jsonl_bytes(records: Sequence[Mapping[str, Any]]) -> bytes:
    return "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False) + "\n"
        for record in records
    ).encode("utf-8")


def _unique_json_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise NormalizationError("duplicate JSON object key: " + key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise NormalizationError("non-JSON numeric constant: " + value)


def _required_string(record: Mapping[str, Any], key: str, line: int) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError("line {}: {} must be a nonempty string".format(line, key))
    return value


def advisory_id(advisory_url: str) -> str:
    """Extract a single GHSA identifier from the advisory URL's path."""
    try:
        path = urlsplit(advisory_url).path
    except ValueError as exc:
        raise NormalizationError("invalid advisory_url: " + str(exc)) from exc
    matches = GHSA_PATTERN.findall(path)
    if len(matches) != 1:
        raise NormalizationError("advisory_url must contain exactly one GHSA identifier")
    return matches[0].upper()


def parse_raw(raw_bytes: bytes) -> List[Tuple[int, Dict[str, Any]]]:
    """Parse source order, preserving physical 1-based nonempty-line positions."""
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NormalizationError("raw JSONL must be UTF-8") from exc
    records = []
    seen_ids = set()
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=_unique_json_object,
                                parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, NormalizationError) as exc:
            raise NormalizationError("line {}: {}".format(line_number, exc)) from exc
        if not isinstance(record, dict):
            raise NormalizationError("line {}: expected a JSON object".format(line_number))
        source_id = _required_string(record, "id", line_number)
        if source_id in seen_ids:
            raise NormalizationError("line {}: duplicate source id {}".format(line_number, source_id))
        seen_ids.add(source_id)
        for key in ("repo", "language", "framework", "advisory_url"):
            _required_string(record, key, line_number)
        advisory_id(record["advisory_url"])
        for key in ("vulnerable_commit", "fixed_commit"):
            value = _required_string(record, key, line_number)
            if not COMMIT_PATTERN.fullmatch(value):
                raise NormalizationError("line {}: {} must be a full commit SHA".format(line_number, key))
        sink_locations = record.get("sink_locations")
        if not isinstance(sink_locations, list):
            raise NormalizationError("line {}: sink_locations must be a list".format(line_number))
        for location in sink_locations:
            if not isinstance(location, dict):
                raise NormalizationError("line {}: sink range must be an object".format(line_number))
            _required_string(location, "file", line_number)
            start, end = location.get("line_start"), location.get("line_end")
            if (type(start) is not int or type(end) is not int or start < 1 or end < start):
                raise NormalizationError("line {}: invalid sink line range".format(line_number))
        records.append((line_number, record))
    if not records:
        raise NormalizationError("raw JSONL contains no records")
    return records


def normalize_record(record: Mapping[str, Any], line_number: int) -> Dict[str, Any]:
    """Promote only identity, repository, and revision fields; retain all others."""
    return {
        "schema_version": CASE_SCHEMA,
        "record_id": "bac-bench::" + record["id"],
        "source": "absentia",
        "source_record_id": record["id"],
        "repository_url": record["repo"],
        "language": record["language"],
        "framework": record["framework"],
        "revisions": {
            "checkout": record["vulnerable_commit"],
            "checkout_kind": "vulnerable_commit",
            "fix": record["fixed_commit"],
        },
        "vulnerability_ids": [advisory_id(record["advisory_url"])],
        "raw_ref": {
            "path": RAW_PATH,
            "jsonl_line": line_number,
            "record_sha256": sha256(canonical_json_bytes(record)),
        },
        "provenance": {
            "upstream_repository": UPSTREAM_REPOSITORY,
            "upstream_commit": UPSTREAM_COMMIT,
            "upstream_review": "author_reported_human_validation",
        },
        "review": {"local_status": "pending_review"},
        "runtime_status": "not_run",
        "training_status": "not_assessed",
        "pool_status": "not_built",
        "evaluator_only": {
            key: value for key, value in record.items() if key not in PROMOTED_RAW_FIELDS
        },
    }


def actual_counts(records: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    """Count distinct advisory IDs and repository/revision snapshot pairs.

    Different advisories may share a snapshot; snapshots are not record IDs.
    Sink ranges count annotations, not their lengths or globally unique ranges.
    """
    return {
        "advisories": len({identifier for record in records
                           for identifier in record["vulnerability_ids"]}),
        "repositories": len({record["repository_url"] for record in records}),
        "vulnerable_snapshots": len({(record["repository_url"], record["revisions"]["checkout"])
                                     for record in records}),
        "fixed_snapshots": len({(record["repository_url"], record["revisions"]["fix"])
                                for record in records}),
        "sink_ranges": sum(len(record["evaluator_only"]["sink_locations"]) for record in records),
    }


def build_artifacts(raw_bytes: bytes) -> Dict[str, bytes]:
    """Pure deterministic transform; CLI separately enforces the pinned input."""
    raw_records = parse_raw(raw_bytes)
    cases = [normalize_record(record, line) for line, record in raw_records]
    cases_bytes = jsonl_bytes(cases)
    counts = actual_counts(cases)
    source = {
        "schema_version": "bac.source.v1",
        "source": "absentia",
        "upstream_repository": UPSTREAM_REPOSITORY,
        "upstream_commit": UPSTREAM_COMMIT,
        "normalization": {"schema": CASE_SCHEMA, "version": NORMALIZATION_VERSION},
        "files": {
            RAW_PATH: {"sha256": sha256(raw_bytes), "bytes": len(raw_bytes)},
            CASES_PATH: {"sha256": sha256(cases_bytes), "bytes": len(cases_bytes)},
        },
        "selected_record_sha256": {
            record["id"]: sha256(canonical_json_bytes(record)) for _, record in raw_records
        },
        "counts": counts,
        "license_note": LICENSE_NOTE,
    }
    summary = {
        "schema_version": "bac.summary.v1",
        "source": "absentia",
        "counts": counts,
        "review": {"local_status": "pending_review"},
        "runtime_status": "not_run",
        "training_status": "not_assessed",
        "pool_status": "not_built",
        "scope_note": "Positive-only author index; normalization is not independent review or runtime reproduction.",
        "license_note": LICENSE_NOTE,
    }
    return {
        CASES_PATH: cases_bytes,
        SOURCE_PATH: canonical_json_bytes(source),
        SUMMARY_PATH: canonical_json_bytes(summary),
    }


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(root)] + list(args),
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NormalizationError("cannot read pinned local Git objects: " + str(exc)) from exc
    return result.stdout


def load_pinned_raw(root: Path) -> bytes:
    """Verify worktree data/ bytes against the recorded upstream Git tree."""
    root = root.resolve()
    git_root = Path(_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if git_root != root:
        raise NormalizationError("--root must be the repository root")
    paths = _git(root, "ls-tree", "-rz", "--name-only", UPSTREAM_COMMIT, "--", "data/")
    source_paths = [path.decode("utf-8") for path in paths.split(b"\0") if path]
    if RAW_PATH not in source_paths:
        raise NormalizationError("pinned Git tree does not contain " + RAW_PATH)
    raw_bytes = None
    for relative_path in source_paths:
        path = root / relative_path
        if path.is_symlink() or not path.is_file():
            raise NormalizationError("upstream data file is missing or not a regular file: " + relative_path)
        expected = _git(root, "show", UPSTREAM_COMMIT + ":" + relative_path)
        actual = path.read_bytes()
        if actual != expected:
            raise NormalizationError("upstream data file differs from pinned Git blob: " + relative_path)
        if relative_path == RAW_PATH:
            raw_bytes = actual
    if raw_bytes is None or sha256(raw_bytes) != RAW_SHA256:
        raise NormalizationError("raw JSONL hash differs from the pinned SHA-256")
    return raw_bytes


def _pinned_artifacts(root: Path) -> Dict[str, bytes]:
    artifacts = build_artifacts(load_pinned_raw(root))
    source = json.loads(artifacts[SOURCE_PATH])
    if source["counts"] != EXPECTED_COUNTS:
        raise NormalizationError("actual counts differ from the pinned index: " + repr(source["counts"]))
    return artifacts


def _safe_output_path(root: Path, relative_path: str) -> Path:
    path = root / relative_path
    for component in (path,) + tuple(path.parents):
        if component == root:
            break
        if component.is_symlink():
            raise NormalizationError("derived path must not use symlinks: " + relative_path)
    return path


def write_artifacts(root: Path, artifacts: Mapping[str, bytes]) -> int:
    """Preflight all outputs, then exclusively create missing files only."""
    root = root.resolve()
    missing = []
    for relative_path, expected in artifacts.items():
        path = _safe_output_path(root, relative_path)
        if path.exists():
            if not path.is_file() or path.read_bytes() != expected:
                raise NormalizationError("refusing to overwrite differing derived file: " + relative_path)
        else:
            missing.append((relative_path, path, expected))
    for relative_path, path, expected in missing:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as output:
                output.write(expected)
        except FileExistsError as exc:
            # Do not overwrite another session's output, even after preflight.
            raise NormalizationError("derived file appeared during generation: " + relative_path) from exc
    return len(missing)


def generate(root: Path) -> int:
    return write_artifacts(root, _pinned_artifacts(root))


def validate(root: Path) -> Dict[str, int]:
    """Require exact reconstruction, source hashes, unique identities and counts."""
    root = root.resolve()
    expected_artifacts = _pinned_artifacts(root)
    actual_artifacts = {}
    for relative_path, expected in expected_artifacts.items():
        path = _safe_output_path(root, relative_path)
        if not path.is_file():
            raise NormalizationError("missing derived file: " + relative_path)
        actual = path.read_bytes()
        if actual != expected:
            raise NormalizationError("derived file differs from deterministic reconstruction: " + relative_path)
        actual_artifacts[relative_path] = actual
    cases = [json.loads(line) for line in actual_artifacts[CASES_PATH].splitlines()]
    record_ids = [record["record_id"] for record in cases]
    source_ids = [record["source_record_id"] for record in cases]
    if len(set(record_ids)) != len(cases) or len(set(source_ids)) != len(cases):
        raise NormalizationError("normalized record identities are not unique")
    source = json.loads(actual_artifacts[SOURCE_PATH])
    for relative_path, info in source["files"].items():
        file_bytes = (root / relative_path).read_bytes()
        if info != {"sha256": sha256(file_bytes), "bytes": len(file_bytes)}:
            raise NormalizationError("source file hash or byte count mismatch: " + relative_path)
    counts = actual_counts(cases)
    summary = json.loads(actual_artifacts[SUMMARY_PATH])
    if counts != source["counts"] or counts != summary["counts"] or counts != EXPECTED_COUNTS:
        raise NormalizationError("normalized, source, summary or pinned counts disagree")
    return counts


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "validate"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="repository root (defaults to this script's repository)")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            created = generate(args.root)
            print("Generated {} derived file(s); identical existing files left unchanged.".format(created))
        else:
            counts = validate(args.root)
            print("Validated pinned source and all derived files: " + json.dumps(counts, sort_keys=True))
    except (NormalizationError, OSError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
