import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import resample
from imblearn.over_sampling import SMOTE
import joblib
import logging
import os

class NIDSModel:
    def __init__(self, model_path="models/nids_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'packet_size',
            'protocol_type',
            'port',
            'flags',
            'time_interval'
        ]
        self.balance_method = 'smote'  # Options: 'none', 'upsample', 'smote'
        logging.basicConfig(level=logging.INFO)

    def balance_dataset(self, X, y):
        """Balance dataset using specified method"""
        if self.balance_method == 'none':
            return X, y
        
        if self.balance_method == 'upsample':
            # Separate majority and minority classes
            X_majority = X[y == 0]
            X_minority = X[y == 1]
            y_majority = y[y == 0]
            y_minority = y[y == 1]
            
            # Upsample minority class
            if len(X_minority) > 0:
                X_minority_upsampled, y_minority_upsampled = resample(
                    X_minority, 
                    y_minority,
                    replace=True,
                    n_samples=len(X_majority),
                    random_state=42
                )
                X = np.vstack([X_majority, X_minority_upsampled])
                y = np.hstack([y_majority, y_minority_upsampled])
        
        elif self.balance_method == 'smote':
            if len(np.unique(y)) > 1:
                smote = SMOTE(random_state=42)
                X, y = smote.fit_resample(X, y)
        
        return X, y

    def train(self, data_path, test_size=0.2):
        """Train the ML model using historical network traffic data"""
        try:
            # Load and prepare data
            data = pd.read_csv(data_path)
            
            # Data preprocessing
            for feature in self.feature_names:
                data[feature] = pd.to_numeric(data[feature], errors='coerce').fillna(0)
            
            X = data[self.feature_names].astype(float)
            y = data['is_attack'].astype(int)
            
            logging.info("Data shape: %s", X.shape)
            logging.info("Feature types:\n%s", X.dtypes)
            
            # Balance dataset before splitting
            X, y = self.balance_dataset(X.to_numpy(), y.to_numpy())
            
            # Split and scale data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Initialize and train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=5,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                random_state=42,
                class_weight='balanced'
            )
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
            logging.info(f"Mean CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Train final model and evaluate
            self.model.fit(X_train_scaled, y_train)
            y_pred = self.model.predict(X_test_scaled)
            test_score = self.model.score(X_test_scaled, y_test)
            
            # Ensure we have all possible classes represented
            all_possible_classes = [0, 1]  # Normal and Attack
            class_names = ['Normal', 'Attack']
            
            logging.info("\nModel Performance Metrics:")
            logging.info("=" * 50)
            logging.info(f"Test Accuracy: {test_score:.4f}")
            
            # Handle classification report with all possible classes
            report = classification_report(
                y_test,
                y_pred,
                target_names=class_names,
                labels=all_possible_classes,
                zero_division=0
            )
            logging.info(f"\nDetailed Classification Report:\n{report}")
            
            # Handle confusion matrix with all possible classes
            cm = confusion_matrix(
                y_test, 
                y_pred, 
                labels=all_possible_classes
            )
            cm_formatted = pd.DataFrame(
                cm,
                index=[f'True {name}' for name in class_names],
                columns=[f'Predicted {name}' for name in class_names]
            )
            logging.info("\nConfusion Matrix:")
            logging.info(f"\n{cm_formatted}")
            
            # Log detailed class distribution
            logging.info("\nClass Distribution in Test Set:")
            logging.info("-" * 30)
            unique, counts = np.unique(y_test, return_counts=True)
            total_samples = len(y_test)
            
            # Show counts for all possible classes
            for class_idx, class_name in enumerate(class_names):
                count = counts[unique == class_idx].item() if class_idx in unique else 0
                percentage = (count / total_samples) * 100
                logging.info(f"{class_name}: {count:,d} samples ({percentage:.1f}%)")
            
            # Add model validation warnings
            if len(np.unique(y)) == 1:
                logging.warning("WARNING: Only one class present in the dataset!")
                logging.warning("Model will not be able to detect attacks.")
            
            if np.sum(y == 1) == 0:
                logging.warning("WARNING: No attack samples in the dataset!")
                logging.warning("Consider adding attack samples for better detection.")
            
            # Save model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump((self.model, self.scaler), self.model_path)
            logging.info(f"\nModel saved to {self.model_path}")
            
            return test_score
            
        except Exception as e:
            logging.error(f"Error in model training: {e}")
            raise

    def predict(self, features):
        """Predict if packet is malicious"""
        try:
            if self.model is None:
                self.load()
            features_scaled = self.scaler.transform(features)
            return self.model.predict(features_scaled)[0]
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return 0

    def predict_proba(self, features):
        """Get probability scores for predictions"""
        try:
            if self.model is None:
                self.load()
            features_scaled = self.scaler.transform(features)
            return self.model.predict_proba(features_scaled)
        except Exception as e:
            logging.error(f"Prediction probability error: {e}")
            return [[1.0, 0.0]]  # Return safe default

    def load(self):
        """Load pre-trained model"""
        try:
            self.model, self.scaler = joblib.load(self.model_path)
            logging.info("Model loaded successfully")
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            raise