"""Offline tests for the BAC normalization and provenance boundary."""

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bac_normalize", REPOSITORY_ROOT / "tools/normalize.py")
normalize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalize)


def sample_record(source_id="first", ghsa="GHSA-abcd-1234-efgh"):
    return {
        "id": source_id,
        "repo": "https://github.com/example/project",
        "language": "python",
        "framework": "example",
        "vulnerable_commit": "1" * 40,
        "fixed_commit": "2" * 40,
        "advisory_url": "https://github.com/advisories/" + ghsa,
        "fix_url": "https://github.com/example/project/commit/" + "2" * 40,
        "sink_locations": [{"file": "app.py", "line_start": 4, "line_end": 7}],
        "invariant": "The caller owns the resource.",
        "violation": "Author-reported missing ownership check.",
        "expected_cwes": ["CWE-639"],
        "match_criteria": "Evaluator-only matching guidance.",
        "runtime_status": "upstream_claim_must_not_override_local_status",
        "future_field": {"unicode": "权限", "nested": [True, None, 3]},
    }


def raw_bytes(records):
    return ("\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n").encode("utf-8")


def cases_from(artifacts):
    return [json.loads(line) for line in artifacts[normalize.CASES_PATH].splitlines()]


class NormalizationTests(unittest.TestCase):
    def test_exact_canonical_record_hash_and_record_reference(self):
        record = sample_record()
        data = b"\n\n" + raw_bytes([record]) + b"\n"
        artifacts = normalize.build_artifacts(data)
        case = cases_from(artifacts)[0]
        expected_bytes = (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        expected_hash = hashlib.sha256(expected_bytes).hexdigest()
        self.assertEqual(case["raw_ref"], {
            "path": "data/authz_instances.jsonl", "jsonl_line": 3,
            "record_sha256": expected_hash,
        })
        self.assertEqual(case["record_id"], "bac-bench::first")
        self.assertEqual(case["source_record_id"], "first")
        self.assertEqual(case["vulnerability_ids"], ["GHSA-ABCD-1234-EFGH"])
        source = json.loads(artifacts[normalize.SOURCE_PATH])
        self.assertEqual(source["selected_record_sha256"], {"first": expected_hash})
        self.assertEqual(source["files"][normalize.RAW_PATH], {
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        })
        cases_bytes = artifacts[normalize.CASES_PATH]
        self.assertEqual(source["files"][normalize.CASES_PATH], {
            "sha256": hashlib.sha256(cases_bytes).hexdigest(), "bytes": len(cases_bytes),
        })

    def test_deterministic_bytes_and_source_order(self):
        first = sample_record("z-record", "GHSA-aaaa-bbbb-cccc")
        second = sample_record("a-record", "GHSA-dddd-eeee-ffff")
        data = raw_bytes([first, second])
        artifacts = normalize.build_artifacts(data)
        self.assertEqual(artifacts, normalize.build_artifacts(data))
        cases = cases_from(artifacts)
        self.assertEqual([case["source_record_id"] for case in cases], ["z-record", "a-record"])
        self.assertEqual(artifacts[normalize.CASES_PATH], normalize.jsonl_bytes(cases))
        for path in (normalize.SOURCE_PATH, normalize.SUMMARY_PATH):
            parsed = json.loads(artifacts[path])
            self.assertEqual(artifacts[path], normalize.canonical_json_bytes(parsed))
        # Object insertion order must not affect canonical per-record hashes.
        reversed_record = dict(reversed(list(first.items())))
        self.assertEqual(normalize.canonical_json_bytes(first), normalize.canonical_json_bytes(reversed_record))

    def test_statuses_are_honest_and_evaluator_fields_preserved(self):
        raw = sample_record()
        artifacts = normalize.build_artifacts(raw_bytes([raw]))
        case = cases_from(artifacts)[0]
        self.assertEqual(case["schema_version"], "bac.case.v1")
        self.assertEqual(case["source"], "absentia")
        self.assertEqual(case["review"], {"local_status": "pending_review"})
        self.assertEqual(case["runtime_status"], "not_run")
        self.assertEqual(case["training_status"], "not_assessed")
        self.assertEqual(case["pool_status"], "not_built")
        self.assertEqual(case["provenance"], {
            "upstream_repository": normalize.UPSTREAM_REPOSITORY,
            "upstream_commit": normalize.UPSTREAM_COMMIT,
            "upstream_review": "author_reported_human_validation",
        })
        self.assertEqual(case["evaluator_only"], {
            key: value for key, value in raw.items() if key not in normalize.PROMOTED_RAW_FIELDS
        })
        self.assertEqual(case["revisions"]["fix"], raw["fixed_commit"])
        for key in ("advisory_url", "fix_url", "sink_locations", "violation", "match_criteria", "expected_cwes", "future_field"):
            self.assertNotIn(key, case)
        summary = json.loads(artifacts[normalize.SUMMARY_PATH])
        self.assertEqual(summary["review"], {"local_status": "pending_review"})
        for key in ("runtime_status", "training_status", "pool_status"):
            self.assertEqual(summary[key], case[key])
        self.assertNotIn("evaluator_only", summary)
        self.assertNotIn("sink_locations", summary)
        self.assertNotIn("match_criteria", summary)

    def test_duplicate_source_ids_rejected(self):
        first, second = sample_record(), sample_record(ghsa="GHSA-aaaa-bbbb-cccc")
        with self.assertRaisesRegex(normalize.NormalizationError, "duplicate source id"):
            normalize.build_artifacts(raw_bytes([first, second]))

    def test_shared_snapshots_are_legal_and_counted_once(self):
        first = sample_record("first", "GHSA-aaaa-bbbb-cccc")
        second = sample_record("second", "GHSA-dddd-eeee-ffff")
        artifacts = normalize.build_artifacts(raw_bytes([first, second]))
        self.assertEqual(len(cases_from(artifacts)), 2)
        source = json.loads(artifacts[normalize.SOURCE_PATH])
        summary = json.loads(artifacts[normalize.SUMMARY_PATH])
        expected = {"advisories": 2, "repositories": 1, "vulnerable_snapshots": 1,
                    "fixed_snapshots": 1, "sink_ranges": 2}
        self.assertEqual(source["counts"], expected)
        self.assertEqual(summary["counts"], expected)

    def test_invalid_source_json_or_ranges_rejected(self):
        for data in (b"[]\n", b"{broken}\n", b"\n", b"\xff\n",
                     b'{"id":"first","id":"second"}\n', b'{"id":NaN}\n'):
            with self.subTest(data=data), self.assertRaises(normalize.NormalizationError):
                normalize.build_artifacts(data)
        for key, value in (("fixed_commit", "short"), ("advisory_url", "https://example.org/no-id"),
                           ("sink_locations", [{"file": "x", "line_start": True, "line_end": 7}]),
                           ("sink_locations", [{"file": "x", "line_start": 8, "line_end": 7}])):
            record = sample_record()
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(normalize.NormalizationError):
                normalize.build_artifacts(raw_bytes([record]))

    def test_generation_noop_and_refuses_to_overwrite_before_any_write(self):
        artifacts = normalize.build_artifacts(raw_bytes([sample_record()]))
        with tempfile.TemporaryDirectory(prefix="bac-normalize-test-") as directory:
            root = Path(directory)
            self.assertEqual(normalize.write_artifacts(root, artifacts), 3)
            before = {path: (root / path).stat().st_mtime_ns for path in artifacts}
            self.assertEqual(normalize.write_artifacts(root, artifacts), 0)
            self.assertEqual(before, {path: (root / path).stat().st_mtime_ns for path in artifacts})
            with self.assertRaisesRegex(normalize.NormalizationError, "refusing to overwrite"):
                normalize.write_artifacts(root, {normalize.CASES_PATH: b"changed\n"})
            self.assertEqual((root / normalize.CASES_PATH).read_bytes(), artifacts[normalize.CASES_PATH])
            # Later conflict must prevent creation of an earlier missing file.
            conflict = {"datasets/bac-bench/new.json": b"{}\n", normalize.SOURCE_PATH: b"changed\n"}
            with self.assertRaises(normalize.NormalizationError):
                normalize.write_artifacts(root, conflict)
            self.assertFalse((root / "datasets/bac-bench/new.json").exists())

    def test_generation_refuses_symlink_outputs(self):
        artifacts = normalize.build_artifacts(raw_bytes([sample_record()]))
        with tempfile.TemporaryDirectory(prefix="bac-normalize-test-") as directory:
            root = Path(directory)
            (root / "external").mkdir()
            (root / "datasets").symlink_to(root / "external", target_is_directory=True)
            with self.assertRaisesRegex(normalize.NormalizationError, "symlinks"):
                normalize.write_artifacts(root, artifacts)
            self.assertEqual(list((root / "external").iterdir()), [])

    def test_pinned_repository_reconstructs_and_counts_match(self):
        data = normalize.load_pinned_raw(REPOSITORY_ROOT)
        self.assertEqual(normalize.sha256(data), normalize.RAW_SHA256)
        artifacts = normalize.build_artifacts(data)
        self.assertEqual(json.loads(artifacts[normalize.SOURCE_PATH])["counts"], normalize.EXPECTED_COUNTS)
        self.assertEqual(normalize.validate(REPOSITORY_ROOT), normalize.EXPECTED_COUNTS)
        self.assertEqual(normalize.generate(REPOSITORY_ROOT), 0)

    def test_pinned_input_rejects_changes_to_any_original_data_file(self):
        originals = {
            path: (REPOSITORY_ROOT / path).read_bytes()
            for path in (normalize.RAW_PATH, "data/README.md", "data/instances.csv")
        }
        with tempfile.TemporaryDirectory(prefix="bac-normalize-test-") as directory:
            root = Path(directory).resolve()
            (root / "data").mkdir()
            for path, content in originals.items():
                (root / path).write_bytes(content)

            def fake_git(git_root, *args):
                self.assertEqual(git_root, root)
                if args == ("rev-parse", "--show-toplevel"):
                    return (str(root) + "\n").encode("utf-8")
                if args == ("ls-tree", "-rz", "--name-only", normalize.UPSTREAM_COMMIT, "--", "data/"):
                    return b"\0".join(path.encode("utf-8") for path in originals) + b"\0"
                if args[0] == "show":
                    self.assertTrue(args[1].startswith(normalize.UPSTREAM_COMMIT + ":"))
                    return originals[args[1].split(":", 1)[1]]
                self.fail("unexpected Git command: " + repr(args))

            with mock.patch.object(normalize, "_git", side_effect=fake_git):
                self.assertEqual(normalize.load_pinned_raw(root), originals[normalize.RAW_PATH])
                for path, content in originals.items():
                    (root / path).write_bytes(content + b"changed\n")
                    with self.subTest(path=path), self.assertRaisesRegex(normalize.NormalizationError, "pinned Git blob"):
                        normalize.load_pinned_raw(root)
                    (root / path).write_bytes(content)

    def test_validate_rejects_hash_or_count_tampering(self):
        artifacts = normalize.build_artifacts(normalize.load_pinned_raw(REPOSITORY_ROOT))
        with tempfile.TemporaryDirectory(prefix="bac-normalize-test-") as directory:
            root = Path(directory)
            normalize.write_artifacts(root, artifacts)
            source_path = root / normalize.SOURCE_PATH
            source = json.loads(source_path.read_bytes())
            for field in ("counts", "files"):
                changed = copy.deepcopy(source)
                if field == "counts":
                    changed["counts"]["advisories"] = 31
                else:
                    changed["files"][normalize.RAW_PATH]["sha256"] = "0" * 64
                # Test-only tampering stays inside this temporary directory.
                source_path.write_bytes(normalize.canonical_json_bytes(changed))
                with mock.patch.object(normalize, "_pinned_artifacts", return_value=artifacts):
                    with self.subTest(field=field), self.assertRaisesRegex(normalize.NormalizationError, "reconstruction"):
                        normalize.validate(root)


if __name__ == "__main__":
    unittest.main()
