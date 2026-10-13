# BAC-Bench

30 authorization advisories across 25 repositories, with 87 sink-location spans. The author-maintained data are from [ABSENTIA](https://github.com/avduarte333/Absentia); this repository is an adaptation, not the original benchmark.

## Data

- [`dataset/cases.jsonl`](dataset/cases.jsonl): the shared `bench-dataset-v1` records: identity/group, split, origin, language, identifiers, source versions, labels, patches, runtime references and provenance.
- [`dataset/manifest.json`](dataset/manifest.json): counts, original file receipts, asset hashes, modes and license associations.
- `dataset/assets/`: byte-preserved source/evidence/oracle/knowledge/license assets, indexed by the manifest. Answer-bearing data are not model inputs.

Original files remain available at [the fixed pre-migration commit](https://github.com/Dilrevx/bac-bench/tree/468613c67618bc93f784f7da110c9d45c5b76b4e). Original records and meaningful annotations are translated into the common cases, not used as an alternative runtime format. Models, experiments and results belong in [embed](https://github.com/Dilrevx/embed).

## Use

Use embed's [`benchmarks/bac-bench/dataset-lock.json`](https://github.com/Dilrevx/embed/blob/spec-audit-ab/benchmarks/bac-bench/dataset-lock.json) and [common runner](https://github.com/Dilrevx/embed/blob/spec-audit-ab/docs/method-runner.md). From the embed checkout:

```sh
PYTHONPATH=src python -m embedbench validate-dataset \
  --benchmark-checkout ../bac-bench \
  --lock benchmarks/bac-bench/dataset-lock.json
```

Validation checks all cases, references, asset bytes and file modes without executing targets. Labels are location/assessment evidence, not proof of exploitation; a fixed version is not a blanket safe-repository label. Missing original version bindings remain explicitly recorded.

## Rights

Original attribution and licensing boundaries are retained in the root legal files and `manifest.license`; nested legal texts are byte-preserved assets with their original scopes. No blanket relicensing of third-party target code or data is asserted.
