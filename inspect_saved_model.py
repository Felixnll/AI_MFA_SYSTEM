from joblib import load
m = load('models/risk_model.joblib')
print('classes_', getattr(m,'classes_', None))
print('feature_importances_', getattr(m,'feature_importances_', None))
print('n_estimators=', getattr(m,'n_estimators', None))
