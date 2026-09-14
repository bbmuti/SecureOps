# Reproducible External Benchmarking

SentinelScope keeps two evaluations deliberately separate:

1. `scripts/evaluate_model.py` is a deterministic synthetic regression check for the complete hybrid rule-and-anomaly path.
2. `scripts/benchmark_beth.py` evaluates the Isolation Forest algorithm family on labeled, real host telemetry from BETH.

Neither result should be presented as the other. In particular, the BETH benchmark is not an end-to-end measurement of the authentication/API event schema.

## Why BETH

[BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset) contains more than eight million real process events collected from 23 cloud honeypots and includes benign and malicious labels. The dataset is released under CC0. The accompanying research paper is [BETH Dataset: Real Cybersecurity Data for Unsupervised Anomaly Detection Research](https://www.gatsby.ucl.ac.uk/~balaji/udl2021/accepted-papers/UDL2021-paper-033.pdf).

The reproducible run in this repository uses the public author-owned Kaggle release, version 3:

```text
https://www.kaggle.com/datasets/katehighnam/beth-dataset
```

The Kaggle archive is approximately 42 MB compressed and 928 MB after extraction. It is intentionally not committed to this repository.

## Run the benchmark

Download and extract the official archive. Then run from `backend/`:

```bash
python -m scripts.benchmark_beth \
  --train /path/to/labelled_training_data.csv \
  --validation /path/to/labelled_validation_data.csv \
  --test /path/to/labelled_testing_data.csv \
  --max-train 100000 \
  --max-validation 100000 \
  --max-test 100000 \
  --source-revision "$(git rev-parse HEAD)" \
  --output artifacts/beth-benchmark.json
```

The script uses deterministic reservoir sampling, fits only benign training records, and trains three 1,000-tree Isolation Forest runs with independent fixed seeds. The operational score is the mean of those runs. Its decision threshold is selected from the 95th percentile of the separate benign-only validation ensemble scores (a 5% validation alert budget) and frozen before the labelled test split is evaluated. It reports:

- precision, recall, and F1;
- ROC-AUC and average precision;
- false-positive rate;
- confusion matrix;
- deterministic 95% bootstrap intervals;
- every individual-seed run and aggregate variation;
- a fixed random-score baseline;
- sampled class counts;
- runtime package/Python versions and SHA-256 hashes of all three input files.

File hashes for all three splits, fixed seeds, feature names, sampling limits, and threshold methodology make a result reproducible. Pass the current commit through `--source-revision`; CI uses `GITHUB_SHA` automatically. A local run without either value is marked `uncommitted-working-tree` instead of inventing provenance. Do not commit the downloaded dataset. A generated report may be committed only when it was produced by this script without manual metric editing.

## Versioned result

The committed [BETH report](../backend/artifacts/beth-benchmark.json) was generated on 2026-08-20 from version 3 with 100,000 sampled records in each stage:

The original run was captured before its benchmark changes were committed, so its `source_revision` remains `uncommitted-working-tree` rather than being rewritten after the fact. The artifact records the first commit that introduced that report; future runs resolve the source revision automatically.

| Metric | Test result |
|---|---:|
| Precision | 0.9729 |
| Recall | 0.9145 |
| F1 | 0.9428 |
| ROC-AUC | 0.8412 |
| Average precision | 0.9187 |
| False-positive rate | 0.1327 |
| FPR 95% bootstrap interval | 0.1276–0.1384 |

The strong ensemble precision and recall do not cancel out the 13.27% benign test false-positive rate. Individual runs also show that a validation-only unsupervised threshold can be unstable under test-distribution shift even when ranking metrics remain useful. Both gaps are recorded in the versioned artifact rather than hidden. The ensemble reduces seed sensitivity, but it does not turn this result into production validation.

## Interpretation

Accuracy alone is misleading for rare security events. Prioritize recall, precision, average precision, and false-positive rate. A useful detector must find attacks without producing an alert volume that analysts cannot triage.

The BETH benchmark validates the anomaly-detection algorithm family on real process telemetry. The random baseline, confidence intervals, and repeated runs make a single favorable seed harder to overstate, but no experiment here validates the full SentinelScope authentication pipeline. A separate LANL authentication benchmark is a future extension because the official comprehensive LANL authentication file is 7.2 GB compressed.
