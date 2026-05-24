"""Quick evaluation script for the risk model using training_data.csv.

Handles mixed legacy rows by normalizing missing columns.
Outputs accuracy, precision, and recall (macro/weighted).
"""
from __future__ import annotations

import csv
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split

DATA_PATH = Path("training_data.csv")

# Expected features: failed_attempts, short_interval, unknown_device, unusual_hour,
# password_match, ip_risk, typing_speed_anomaly
FEATURE_NAMES = [
    "failed_attempts",
    "short_interval",
    "unknown_device",
    "unusual_hour",
    "password_match",
    "ip_risk",
    "typing_speed_anomaly",
]


def parse_row(row: list[str]) -> tuple[list[int], int] | None:
    # Remove empty fields
    row = [r.strip() for r in row if r.strip() != ""]
    if not row:
        return None

    # Header row
    if row[0] == "failed_attempts":
        return None

    # Handle legacy rows with 6 columns: missing ip_risk, typing_speed_anomaly
    if len(row) == 6:
        fa, si, ud, uh, pm, label = row
        ip_risk = 0
        tsa = 0
        values = [fa, si, ud, uh, pm, ip_risk, tsa]
        return [int(x) for x in values], int(label)

    # Handle current rows with 8 columns
    if len(row) == 8:
        fa, si, ud, uh, pm, ip_risk, tsa, label = row
        values = [fa, si, ud, uh, pm, ip_risk, tsa]
        return [int(x) for x in values], int(label)

    # Skip malformed rows
    return None


def load_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    features: list[list[int]] = []
    labels: list[int] = []

    with path.open(newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            parsed = parse_row(row)
            if parsed is None:
                continue
            x, y = parsed
            features.append(x)
            labels.append(y)

    if not features:
        raise RuntimeError("No valid rows found in training_data.csv")

    return np.array(features, dtype=int), np.array(labels, dtype=int)


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError("training_data.csv not found")

    X, y = load_dataset(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)

    accuracy = accuracy_score(y_test, preds)
    precision_macro = precision_score(y_test, preds, average="macro", zero_division=0)
    recall_macro = recall_score(y_test, preds, average="macro", zero_division=0)
    precision_weighted = precision_score(y_test, preds, average="weighted", zero_division=0)
    recall_weighted = recall_score(y_test, preds, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, preds, labels=[0, 1, 2])

    print("Dataset:")
    print(f"  samples: {len(y)}")
    print(f"  features: {FEATURE_NAMES}")
    print("Metrics (test split 80/20):")
    print(f"  accuracy: {accuracy:.4f}")
    print(f"  precision_macro: {precision_macro:.4f}")
    print(f"  recall_macro: {recall_macro:.4f}")
    print(f"  precision_weighted: {precision_weighted:.4f}")
    print(f"  recall_weighted: {recall_weighted:.4f}")
    print("Confusion matrix (labels: 0=low, 1=medium, 2=high):")
    for row in cm:
        print(f"  {row.tolist()}")


if __name__ == "__main__":
    main()
