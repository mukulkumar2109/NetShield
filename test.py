import numpy as np
import pandas as pd
import sklearn
from detection.detectionEngine import detectionEngine
import joblib
import random


loaded = joblib.load('top20features.pkl')
X_test = loaded['X_test']
y_test = loaded['y_test']

engine = detectionEngine()

for _ in range(10):
    ran = random.randint(0, len(X_test) - 1)
    
    test_sample = X_test.iloc[ran].to_frame().T  # Single sample as DataFrame
    label = y_test.iloc[ran]
    
    print(f"\n[Sample #{ran}] True Label: {label}")
    engine.test(test_sample, label)
