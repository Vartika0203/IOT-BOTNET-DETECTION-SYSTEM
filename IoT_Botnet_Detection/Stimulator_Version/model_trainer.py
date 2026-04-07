"""
Model Training Module
Trains Random Forest classifier for botnet detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

class BotnetDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.feature_names = None
        
    def train(self, features, labels):
        """
        Train the Random Forest classifier
        """
        print("=" * 60)
        print("TRAINING BOTNET DETECTION MODEL")
        print("=" * 60)
        
        # Convert labels to binary (0=normal, 1=attack)
        y = np.array([0 if label == 'normal' else 1 for label in labels])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(features)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"\nTraining samples: {len(X_train)}")
        print(f"Test samples: {len(X_test)}")
        print(f"Attack ratio in training: {y_train.mean():.2%}")
        
        # Train Random Forest
        print("\n[1] Training Random Forest...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nRandom Forest Results:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Cross-validation (5-fold): {cross_val_score(self.model, X_scaled, y, cv=5).mean():.4f}")
        
        # Detailed classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        # Feature importance
        if self.feature_names:
            importance_df = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(importance_df.head(10).to_string(index=False))
        
        # [2] Train Isolation Forest (unsupervised)
        print("\n[2] Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expected anomaly rate
            random_state=42
        )
        self.isolation_forest.fit(X_scaled)
        
        return accuracy
    
    def predict(self, features):
        """Predict if a feature vector is malicious"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        # Ensure features is 2D
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        X_scaled = self.scaler.transform(features)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        return predictions, probabilities
    
    def predict_anomaly_score(self, features):
        """Get anomaly score from Isolation Forest"""
        if self.isolation_forest is None:
            raise ValueError("Isolation Forest not trained yet!")
        
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        X_scaled = self.scaler.transform(features)
        # Isolation Forest returns -1 for anomaly, 1 for normal
        predictions = self.isolation_forest.predict(X_scaled)
        scores = self.isolation_forest.score_samples(X_scaled)
        
        return predictions, scores
    
    def save_model(self, filepath="botnet_model.pkl"):
        """Save trained model to disk"""
        joblib.dump({
            'random_forest': self.model,
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath="botnet_model.pkl"):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.model = data['random_forest']
        self.isolation_forest = data['isolation_forest']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        print(f"Model loaded from {filepath}")


def generate_training_data(n_samples=1000):
    """
    Generate synthetic training data for demonstration
    (In real scenario, you'd use actual captured traffic)
    """
    np.random.seed(42)
    
    n_features = 18
    
    # Generate synthetic feature vectors
    # Normal traffic patterns
    normal_features = np.random.randn(int(n_samples * 0.7), n_features)
    normal_features[:, 0] = np.random.poisson(5, int(n_samples * 0.7))  # packet_count
    normal_features[:, 6] = np.random.normal(2, 0.5, int(n_samples * 0.7))  # packet_rate
    
    # Attack traffic patterns
    attack_features = np.random.randn(int(n_samples * 0.3), n_features)
    attack_features[:, 0] = np.random.poisson(50, int(n_samples * 0.3))  # Higher packet count
    attack_features[:, 6] = np.random.normal(15, 3, int(n_samples * 0.3))  # Higher packet rate
    attack_features[:, 10] = np.random.normal(0.8, 0.2, int(n_samples * 0.3))  # syn_ratio (attack)
    
    # Combine
    features = np.vstack([normal_features, attack_features])
    labels = np.array(['normal'] * int(n_samples * 0.7) + ['attack'] * int(n_samples * 0.3))
    
    # Add some noise
    features += np.random.randn(*features.shape) * 0.1
    
    return features, labels


if __name__ == "__main__":
    print("=" * 60)
    print("MODEL TRAINING DEMO")
    print("=" * 60)
    
    # Generate synthetic data (replace with real captured traffic)
    features, labels = generate_training_data()
    
    print(f"\nDataset shape: {features.shape}")
    print(f"Normal samples: {(labels == 'normal').sum()}")
    print(f"Attack samples: {(labels == 'attack').sum()}")
    
    # Train detector
    detector = BotnetDetector()
    detector.feature_names = [f"F{i}" for i in range(features.shape[1])]
    detector.train(features, labels)
    
    # Save model
    detector.save_model()
    
    # Test prediction
    print("\n" + "=" * 60)
    print("TEST PREDICTION")
    print("=" * 60)
    
    test_normal = np.random.randn(1, features.shape[1])
    test_normal[0, 0] = 3  # Low packet count
    
    pred, prob = detector.predict(test_normal)
    print(f"Normal test sample -> Prediction: {'Attack' if pred[0] else 'Normal'} (confidence: {prob[0][1]:.2f})")
    
    test_attack = np.random.randn(1, features.shape[1])
    test_attack[0, 0] = 80  # High packet count (attack indicator)
    test_attack[0, 10] = 0.9  # High SYN ratio
    
    pred, prob = detector.predict(test_attack)
    print(f"Attack test sample -> Prediction: {'Attack' if pred[0] else 'Normal'} (confidence: {prob[0][1]:.2f})")