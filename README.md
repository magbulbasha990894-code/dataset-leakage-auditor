# Dataset Leakage Auditor

A Python and SQLite audit gate for temporal train/validation/test datasets. The demo represents fictional prediction snapshots for service cases. Fresh labels can arrive after feature collection; using a future feature or a late-arriving training label would make the evaluation look better than it would have been at deployment.

## Quick start

Python 3.11+; no extra packages.

```sh
python audit.py demo/clean.csv demo/sources.csv demo/policy.json
python audit.py demo/leaky.csv demo/sources.csv demo/policy.json --output findings.json
python -m unittest discover -s tests -v
```

The clean run exits **0**. The second exits **2** and emits row-level findings with seven check codes. Invalid inputs exit **1**. The SHA-256 hashes in the report identify the exact three inputs, and findings have a stable sort.

## Evidence model

| Input | Contract |
| --- | --- |
| dataset CSV | Unique row ID, split, stable entity identifier, lower-case SHA-256 fingerprint of canonical feature payload, declared source ID, and three timestamp columns |
| source registry CSV | Unique source ID and declared SHA-256 of the source artifact; the check detects undeclared source IDs but does not inspect or authenticate underlying artifacts |
| policy JSON | ISO timestamps for training and validation freeze; training cutoff ≤ first freeze, validation after the first freeze through the second, test strictly after the second freeze |

`cutoff_at` is the simulated prediction time, `feature_max_at` the latest time any feature was available to serve, and `label_ready_at` the time the outcome was first known. Timestamp offsets are normalized to UTC. Equality at the feature cutoff or applicable label freeze is permitted. Test labels are scored retrospectively, so no test label freeze is checked.

Examples in the leakage file include the same payload attached to different entity IDs and the same entity with different payloads. A cross-split collision reports **each participating row**, not every pair. These policies assume the evaluation should generalize to previously unseen entities and payloads; repeatedly scoring known entities would need a different contamination policy. The tool does not infer canonical identities, verify supplied hashes from payloads or model training, or detect approximate duplicates and paraphrases. This is an audit over supplied data and metadata, not a proof of contamination-free training.

All fixtures are fictional. This repository is an AI-assisted portfolio demonstration.

