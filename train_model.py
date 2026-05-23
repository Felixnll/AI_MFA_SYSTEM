"""
Train a RandomForest risk model on synthetic data and save to models/risk_model.joblib
Run: python train_model.py
"""
import os
from pathlib import Path
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

MODEL_DIR = Path('models')
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / 'risk_model.joblib'

# Generate synthetic dataset
N = 5000
X = []
Y = []
for _ in range(N):
    failed_attempts = random.choices([0,1,2,3,4], weights=[50,20,15,10,5])[0]
    short_interval = random.choices([0,1], weights=[85,15])[0]
    unknown_device = random.choices([0,1], weights=[80,20])[0]
    unusual_hour = random.choices([0,1], weights=[85,15])[0]
    ip_risk = random.choices([0,1], weights=[85,15])[0]
    typing_speed_anomaly = random.choices([0,1], weights=[92,8])[0]
    password_match = random.choices([0,1], weights=[20,80])[0]  # 1 means correct password

    # Compute label using same heuristic as rule engine
    score = 0
    if failed_attempts >= 3:
        score += 2
    if short_interval:
        score += 2
    if unknown_device:
        score += 1
    if ip_risk:
        score += 1
    if typing_speed_anomaly:
        score += 1
    if unusual_hour:
        score += 1
    if not password_match:
        score += 2

    if score >= 5:
        label = 2  # high
    elif score >= 3:
        label = 1  # medium
    else:
        label = 0  # low

    X.append([failed_attempts, short_interval, unknown_device, unusual_hour, password_match, ip_risk, typing_speed_anomaly])
    Y.append(label)

import numpy as _np
X = _np.array(X)
Y = _np.array(Y)

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42, stratify=Y)
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
pred = model.predict(X_test)
print(classification_report(y_test, pred, digits=3))

# Save model
joblib.dump(model, MODEL_PATH)
print(f"Saved model to {MODEL_PATH}")
