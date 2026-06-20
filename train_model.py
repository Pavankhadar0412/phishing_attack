"""
Machine Learning Model Training for Phishing Detection
Trains multiple ML models and selects the best performer
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import warnings
from feature_extraction import extract_url_features

warnings.filterwarnings('ignore')


class PhishingModelTrainer:
    """
    A class to train and evaluate phishing detection models.
    """
    
    def __init__(self, dataset_path='dataset/phishing_features.csv'):
        """
        Initialize the model trainer.
        
        Args:
            dataset_path (str): Path to the phishing dataset
        """
        self.dataset_path = dataset_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.best_model_name = None
        self.best_accuracy = 0.0
        
    def load_dataset(self):
        """
        Load the phishing dataset from CSV file.
        
        Returns:
            pd.DataFrame: The loaded dataset
        """
        try:
            if os.path.exists(self.dataset_path):
                df = pd.read_csv(self.dataset_path)
                print(f"Dataset loaded successfully: {df.shape}")
                return df
            else:
                print(f"Dataset file not found at {self.dataset_path}")
                print("Creating a synthetic dataset for demonstration...")
                return self._create_synthetic_dataset()
        except Exception as e:
            print(f"Error loading dataset: {e}")
            print("Creating a synthetic dataset for demonstration...")
            return self._create_synthetic_dataset()
    
    def _create_synthetic_dataset(self):
        """
        Create a synthetic phishing dataset for demonstration purposes.
        
        Returns:
            pd.DataFrame: Synthetic dataset with URL features
        """
        print("Generating synthetic phishing dataset...")
        
        # Sample legitimate and phishing URLs
        legitimate_urls = [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://www.linkedin.com",
            "https://www.twitter.com",
            "https://www.reddit.com",
            "https://www.wikipedia.org",
            "https://www.youtube.com",
            "https://www.netflix.com",
            "https://www.instagram.com",
            "https://www.paypal.com",
            "https://www.ebay.com",
            "https://www.yahoo.com",
            "https://www.bing.com",
            "https://www.twitch.tv",
            "https://www.spotify.com"
        ]
        
        phishing_urls = [
            "http://verify-account-secure.com/login",
            "http://secure-banking-update.net/verify",
            "http://login-verify-account.xyz/secure",
            "http://192.168.1.100/admin/login",
            "http://bit.ly/malicious-link",
            "http://secure-login-update.com/confirm",
            "http://account-verify-secure.tk/login",
            "http://banking-secure-update.gq/verify",
            "http://login-secure-account.cf/auth",
            "http://verify-secure-login.ml/confirm",
            "http://user@phishing-site.com/login",
            "http://secure-login.bit/verify",
            "http://account-confirm-secure.top/login",
            "http://phishing-site.com@malicious.com",
            "http://login-verify-account.zip/secure",
            "http://secure-banking-update.xyz/verify-account",
            "http://confirm-account-secure.gq/login",
            "http://verify-login-secure.cf/auth",
            "http://account-secure-login.ml/confirm",
            "http://secure-verify-account.top/login"
        ]
        
        # Create dataset
        data = []
        
        # Process legitimate URLs
        for url in legitimate_urls:
            features = extract_url_features(url)
            features['label'] = 0  # 0 for legitimate
            features['url'] = url
            data.append(features)
        
        # Process phishing URLs
        for url in phishing_urls:
            features = extract_url_features(url)
            features['label'] = 1  # 1 for phishing
            features['url'] = url
            data.append(features)
        
        df = pd.DataFrame(data)
        
        # Save the synthetic dataset
        os.makedirs('dataset', exist_ok=True)
        df.to_csv(self.dataset_path, index=False)
        print(f"Synthetic dataset saved to {self.dataset_path}")
        
        return df
    
    def preprocess_data(self, df):
        """
        Preprocess the dataset for training.
        
        Args:
            df (pd.DataFrame): The raw dataset
            
        Returns:
            tuple: (X, y) features and labels
        """
        # Drop non-feature columns
        feature_cols = [col for col in df.columns if col not in ['url', 'label']]
        self.feature_names = feature_cols
        
        X = df[feature_cols]
        y = df['label']
        
        # Handle missing values
        X = X.fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        print(f"Features extracted: {len(feature_cols)}")
        print(f"Feature names: {self.feature_names}")
        
        return X_scaled, y
    
    def train_random_forest(self, X_train, y_train):
        """
        Train a Random Forest classifier.
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            RandomForestClassifier: Trained model
        """
        print("\nTraining Random Forest Classifier...")
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        return rf
    
    def train_decision_tree(self, X_train, y_train):
        """
        Train a Decision Tree classifier.
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            DecisionTreeClassifier: Trained model
        """
        print("\nTraining Decision Tree Classifier...")
        dt = DecisionTreeClassifier(
            max_depth=10,
            random_state=42
        )
        dt.fit(X_train, y_train)
        return dt
    
    def train_xgboost(self, X_train, y_train):
        """
        Train an XGBoost classifier.
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            XGBClassifier: Trained model or None if XGBoost not available
        """
        try:
            from xgboost import XGBClassifier
            print("\nTraining XGBoost Classifier...")
            xgb = XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
            xgb.fit(X_train, y_train)
            return xgb
        except ImportError:
            print("XGBoost not available, skipping...")
            return None
    
    def evaluate_model(self, model, X_test, y_test, model_name):
        """
        Evaluate a trained model.
        
        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
            model_name: Name of the model
            
        Returns:
            float: Accuracy score
        """
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n{model_name} Results:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
        
        return accuracy
    
    def train_and_select_best_model(self):
        """
        Train multiple models and select the best one based on accuracy.
        
        Returns:
            object: Best trained model
        """
        # Load and preprocess data
        df = self.load_dataset()
        X, y = self.preprocess_data(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\nTraining set size: {X_train.shape[0]}")
        print(f"Test set size: {X_test.shape[0]}")
        print(f"Legitimate URLs: {sum(y == 0)}")
        print(f"Phishing URLs: {sum(y == 1)}")
        
        # Train models
        models = {}
        
        # Random Forest
        rf_model = self.train_random_forest(X_train, y_train)
        rf_accuracy = self.evaluate_model(rf_model, X_test, y_test, "Random Forest")
        models['Random Forest'] = (rf_model, rf_accuracy)
        
        # Decision Tree
        dt_model = self.train_decision_tree(X_train, y_train)
        dt_accuracy = self.evaluate_model(dt_model, X_test, y_test, "Decision Tree")
        models['Decision Tree'] = (dt_model, dt_accuracy)
        
        # XGBoost
        xgb_model = self.train_xgboost(X_train, y_train)
        if xgb_model is not None:
            xgb_accuracy = self.evaluate_model(xgb_model, X_test, y_test, "XGBoost")
            models['XGBoost'] = (xgb_model, xgb_accuracy)
        
        # Select best model
        print("\n" + "="*50)
        print("Model Comparison:")
        print("="*50)
        
        for name, (model, accuracy) in models.items():
            print(f"{name}: {accuracy:.4f}")
            if accuracy > self.best_accuracy:
                self.best_accuracy = accuracy
                self.best_model_name = name
                self.model = model
        
        print(f"\nBest Model: {self.best_model_name} with accuracy {self.best_accuracy:.4f}")
        
        return self.model
    
    def save_model(self, model_path='phishing_model.pkl'):
        """
        Save the trained model and scaler to disk.
        
        Args:
            model_path (str): Path to save the model
        """
        if self.model is None:
            print("No model to save. Train a model first.")
            return False
        
        try:
            # Save model, scaler, and feature names
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'best_model_name': self.best_model_name,
                'best_accuracy': self.best_accuracy
            }
            
            joblib.dump(model_data, model_path)
            print(f"\nModel saved successfully to {model_path}")
            print(f"Model type: {self.best_model_name}")
            print(f"Accuracy: {self.best_accuracy:.4f}")
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_path='phishing_model.pkl'):
        """
        Load a trained model from disk.
        
        Args:
            model_path (str): Path to the saved model
            
        Returns:
            object: Loaded model
        """
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.best_model_name = model_data['best_model_name']
            self.best_accuracy = model_data['best_accuracy']
            
            print(f"Model loaded successfully from {model_path}")
            print(f"Model type: {self.best_model_name}")
            print(f"Accuracy: {self.best_accuracy:.4f}")
            
            return self.model
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
    
    def predict_url(self, url):
        """
        Predict if a URL is phishing or legitimate.
        
        Args:
            url (str): URL to predict
            
        Returns:
            dict: Prediction results with confidence
        """
        if self.model is None:
            print("Model not loaded. Load or train a model first.")
            return None
        
        # Extract features
        features = extract_url_features(url)
        
        # Prepare features in correct order
        feature_vector = []
        for feature_name in self.feature_names:
            feature_vector.append(features.get(feature_name, 0))
        
        # Scale features
        feature_vector_scaled = self.scaler.transform([feature_vector])
        
        # Make prediction
        prediction = self.model.predict(feature_vector_scaled)[0]
        probability = self.model.predict_proba(feature_vector_scaled)[0]
        
        # Get confidence
        confidence = max(probability) * 100
        is_phishing = bool(prediction)
        
        result = {
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'probability_phishing': probability[1] * 100,
            'probability_legitimate': probability[0] * 100,
            'risk_level': self._get_risk_level(confidence, is_phishing)
        }
        
        return result
    
    def _get_risk_level(self, confidence, is_phishing):
        """
        Determine the risk level based on confidence and prediction.
        
        Args:
            confidence (float): Confidence percentage
            is_phishing (bool): Whether the URL is predicted as phishing
            
        Returns:
            str: Risk level (Low, Medium, High, Critical)
        """
        if not is_phishing:
            return 'Low'
        elif confidence >= 90:
            return 'Critical'
        elif confidence >= 70:
            return 'High'
        else:
            return 'Medium'


def main():
    """
    Main function to train and save the phishing detection model.
    """
    print("="*60)
    print("Phishing Detection Model Training")
    print("="*60)
    
    # Initialize trainer
    trainer = PhishingModelTrainer()
    
    # Train and select best model
    model = trainer.train_and_select_best_model()
    
    # Save the model
    trainer.save_model()
    
    # Test prediction
    print("\n" + "="*60)
    print("Testing Predictions")
    print("="*60)
    
    test_urls = [
        "https://www.google.com",
        "http://verify-account-secure.com/login",
        "https://github.com",
        "http://192.168.1.1/admin"
    ]
    
    for url in test_urls:
        result = trainer.predict_url(url)
        if result:
            status = "PHISHING" if result['is_phishing'] else "SAFE"
            print(f"\nURL: {url}")
            print(f"Status: {status}")
            print(f"Confidence: {result['confidence']:.2f}%")
            print(f"Risk Level: {result['risk_level']}")
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)


if __name__ == "__main__":
    main()
