"""Train a RandomForest risk model using synthetic data.
This script generates labeled examples by applying the existing simple_risk_engine
logic to randomized feature vectors, then trains a RandomForestClassifier and
saves the model to models/risk_model.joblib.

Run:
    python train_risk_model.py

Requirements: scikit-learn, pandas, numpy, joblib
"""
import os
from pathlib import Path
import random
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Recreate the simple risk logic here for synthetic labeling

def simple_risk_label_from_features(f):
    score = 0
    if f['failed_attempts'] >= 3:
        score += 2
    if f['short_interval']:
        score += 2
    if f['unknown_device']:
        score += 1
    if f['unusual_hour']:
        score += 1
    if not f['password_match']:
        score += 2
    if score >= 5:
        return 2  # high
    if score >= 3:
        return 1  # medium
    return 0  # low


def generate_synthetic_example():
    # failed_attempts: 0-6
    fa = np.random.poisson(0.8)
    fa = int(min(max(fa, 0), 6))
    short_interval = int(np.random.rand() < 0.15 if fa > 0 else np.random.rand() < 0.05)
    unknown_device = int(np.random.rand() < 0.2)
    unusual_hour = int(np.random.rand() < 0.1)
    ip_risk = int(np.random.rand() < 0.15)
    typing_speed_anomaly = int(np.random.rand() < 0.08)
    password_match = int(np.random.rand() < 0.85)
    return {
        'failed_attempts': fa,
        'short_interval': int(short_interval),
        'unknown_device': int(unknown_device),
        'unusual_hour': int(unusual_hour),
        'ip_risk': int(ip_risk),
        'typing_speed_anomaly': int(typing_speed_anomaly),
        'password_match': int(password_match),
    }


def synth_dataset(n=5000):
    rows = []
    for _ in range(n):
        f = generate_synthetic_example()
        label = simple_risk_label_from_features(f)
        rows.append({**f, 'label': label})
    return pd.DataFrame(rows)


if __name__ == '__main__':
    out_dir = Path('models')
    out_dir.mkdir(exist_ok=True)

    print('Generating synthetic dataset...')
    df = synth_dataset(4000)
    X = df[['failed_attempts','short_interval','unknown_device','unusual_hour','password_match','ip_risk','typing_speed_anomaly']].values
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print('Training RandomForestClassifier...')
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    print('Classification report:')
    print(classification_report(y_test, preds))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, preds))

    model_path = out_dir / 'risk_model.joblib'
    dump(clf, model_path)
    print(f'Model saved to {model_path}')
