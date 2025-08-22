from ml_model import NIDSModel
import os

def train_new_model():
    try:
        model = NIDSModel()
        data_path = "data/raw/network_traffic.csv"
        
        if not os.path.exists(data_path):
            print("No training data found. Please run collect_data.py first.")
            return
            
        print("Training new model...")
        test_score = model.train(data_path)
        print(f"Model training completed! Test accuracy: {test_score:.4f}")
        
    except Exception as e:
        print(f"Error during training: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = train_new_model()
    if not success:
        print("Training failed. Please check the data and try again.")