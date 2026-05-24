# ML Risk Model Evaluation Report

## Summary
This report summarizes the latest evaluation of the Random Forest risk model using the current training_data.csv dataset.

## Dataset
- Source: training_data.csv
- Samples: 1582
- Features: failed_attempts, short_interval, unknown_device, unusual_hour, password_match, ip_risk, typing_speed_anomaly,label
- Labels: 0 = low, 1 = medium, 2 = high

## Method
- Train/test split: 80/20
- Model: RandomForestClassifier (n_estimators = 200)
- Metrics: accuracy, precision, recall (macro and weighted)

## Results
- Accuracy: 0.9842
- Precision (macro): 0.9847
- Recall (macro): 0.9836
- Precision (weighted): 0.9844
- Recall (weighted): 0.9842

Confusion Matrix (labels: 0=low, 1=medium, 2=high)
- [66, 1, 0]
- [1, 113, 3]
- [0, 0, 133]

## Interpretation
- The model correctly classifies most low/medium/high risk cases.
- Errors are minimal and mostly between neighboring classes.
- This is a prototype-level evaluation; results are based on the current dataset and should be validated further with real-world login data.
