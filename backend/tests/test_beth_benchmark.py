import numpy as np

from scripts.benchmark_beth import (
    FEATURE_NAMES,
    beth_features,
    beth_label,
    bootstrap_intervals,
    metrics,
    select_threshold,
    source_revision,
)


def test_beth_feature_vector_is_fixed_and_finite():
    row = {
        "timestamp": "12345.0",
        "processId": "101",
        "parentProcessId": "1",
        "userId": "1001",
        "mountNamespace": "4026531840",
        "eventId": "257",
        "argsNum": "3",
        "returnValue": "-13",
    }
    values = beth_features(row)
    assert len(values) == len(FEATURE_NAMES)
    assert np.isfinite(values).all()
    assert values[2:6] == [1.0, 0.0, 1.0, 0.0]


def test_beth_label_accepts_numeric_and_boolean_values():
    assert beth_label({"evil": "1"}) == 1
    assert beth_label({"evil": "true"}) == 1
    assert beth_label({"evil": "0"}) == 0


def test_benchmark_metrics_report_class_imbalance_safe_measures():
    report = metrics(
        np.array([0, 0, 1, 1]),
        np.array([0, 1, 1, 0]),
        np.array([0.1, 0.7, 0.9, 0.4]),
    )
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert "average_precision" in report
    assert report["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}


def test_threshold_is_selected_from_validation_distribution():
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    threshold = select_threshold(scores, 75)
    assert np.isclose(threshold, 0.825)


def test_bootstrap_intervals_are_deterministic_and_bounded():
    labels = np.array([0, 0, 0, 1, 1, 1])
    predictions = np.array([0, 1, 0, 1, 1, 0])
    first = bootstrap_intervals(labels, predictions, repetitions=20, seed=7)
    second = bootstrap_intervals(labels, predictions, repetitions=20, seed=7)
    assert first == second
    assert all(0 <= lower <= upper <= 1 for lower, upper in first.values())


def test_source_revision_prefers_ci_commit(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    assert source_revision() == "a" * 40
    assert source_revision("b" * 40) == "b" * 40
