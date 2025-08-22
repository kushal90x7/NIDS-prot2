import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense
import logging

class CNNNIDS:
    def __init__(self, sequence_length=100, img_size=(10, 10)):
        self.sequence_length = sequence_length
        self.img_size = img_size
        self.scaler = MinMaxScaler()
        self.model = None
        logging.basicConfig(level=logging.INFO)

    def reshape_to_image(self, data):
        num_samples, seq_len, num_features = data.shape
        if seq_len != self.img_size[0] * self.img_size[1]:
            raise ValueError("Sequence length must match image dimensions.")
        return data.reshape(num_samples, self.img_size[0], self.img_size[1], 1)

    def create_cnn_model(self, input_shape):
        model = Sequential([
            Conv2D(32, (3, 3), activation='relu', input_shape=input_shape),
            MaxPooling2D((2, 2)),
            Conv2D(64, (3, 3), activation='relu'),
            MaxPooling2D((2, 2)),
            Flatten(),
            Dense(64, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def fit(self, X, y, epochs=10, batch_size=32, validation_split=0.2):
        # Scale and reshape data
        X = X.reshape(-1, self.sequence_length)
        X = self.scaler.fit_transform(X)
        X = X.reshape(-1, self.sequence_length, 1)
        images = self.reshape_to_image(X)
        input_shape = images.shape[1:]
        self.model = self.create_cnn_model(input_shape)
        logging.info("Training CNN model...")
        history = self.model.fit(images, y, epochs=epochs, batch_size=batch_size, validation_split=validation_split)
        return history

    def evaluate(self, X, y):
        X = X.reshape(-1, self.sequence_length)
        X = self.scaler.transform(X)
        X = X.reshape(-1, self.sequence_length, 1)
        images = self.reshape_to_image(X)
        loss, accuracy = self.model.evaluate(images, y)
        logging.info(f"Model accuracy: {accuracy:.4f}")
        return loss, accuracy

    def predict(self, X):
        X = X.reshape(-1, self.sequence_length)
        X = self.scaler.transform(X)
        X = X.reshape(-1, self.sequence_length, 1)
        images = self.reshape_to_image(X)
        preds = self.model.predict(images)
        return preds
