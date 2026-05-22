import app
import numpy as np

app.load_risk_model()
M = app.RISK_MODEL
print('MODEL_LOADED:', M is not None)
if M is not None:
    print('classes_:', getattr(M,'classes_', None))
    print('feature_importances_:', getattr(M,'feature_importances_', None))
    sample = np.array([[0,0,0,0,1]])
    probs = M.predict_proba(sample)[0]
    print('sample_input:', sample.tolist())
    print('predict_proba:', probs.tolist())
    print('predicted_label_index:', int(np.argmax(probs)))
