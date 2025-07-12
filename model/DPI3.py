import kagglehub

# Download latest version
path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")

print("Path to dataset files:", path)



# STEP 1: Install required packages
!pip install -q tf2onnx joblib

# STEP 2: Imports
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import tensorflow as tf
from tensorflow.keras import layers, models, callbacks
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from google.colab import files

# STEP 3: Load Dataset
file_path = '/kaggle/input/network-intrusion-dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
df = pd.read_csv(file_path)

# STEP 4: Rename columns and trim whitespace
df.columns = df.columns.str.strip()

# STEP 5: Define subset of CIC features that are compatible with NFStreamer
features = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Destination Port'
]

# STEP 6: Subset and preprocess
df = df[features + ['Label']].copy()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# STEP 7: Encode labels & scale features
df['Label'] = df['Label'].str.strip()
X = df[features].astype(np.float32)
y = df['Label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save original features list
joblib.dump(features, 'features.pkl')

# Save scaler
joblib.dump(scaler, 'scaler.pkl')

# STEP 8: Separate BENIGN for training
X_train = X_scaled[y == 'BENIGN']
X_test = X_scaled
y_true = (y != 'BENIGN').astype(int)

print("X_train shape:", X_train.shape)
print("X_test shape:", X_test.shape)

# STEP 9: Build Autoencoder
input_dim = X_train.shape[1]
input_layer = layers.Input(shape=(input_dim,))

encoded = layers.Dense(64, activation='relu')(input_layer)
encoded = layers.Dense(32, activation='relu')(encoded)

decoded = layers.Dense(64, activation='relu')(encoded)
decoded = layers.Dense(input_dim, activation='linear')(decoded)

autoencoder = models.Model(inputs=input_layer, outputs=decoded)
autoencoder.compile(optimizer='adam', loss='mse')

# STEP 10: Train Autoencoder
early_stop = callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

history = autoencoder.fit(
    X_train, X_train,
    epochs=100,
    batch_size=64,
    validation_split=0.1,
    callbacks=[early_stop],
    verbose=1
)






# STEP 11: Predict & Threshold (Eager mode to avoid optree error)
print("Shape of X_train before prediction:", X_train.shape)

# ✅ Check for any corruption
assert not np.isnan(X_train).any(), "NaNs in X_train"
assert not np.isinf(X_train).any(), "Infs in X_train"

# ✅ Predict using eager mode
X_train_pred = autoencoder(X_train, training=False).numpy()
X_test_pred = autoencoder(X_test, training=False).numpy()

mse_train = np.mean(np.power(X_train - X_train_pred, 2), axis=1)
mse_test = np.mean(np.power(X_test - X_test_pred, 2), axis=1)

threshold = np.percentile(mse_train, 95)
print(f"Reconstruction Threshold (95th percentile): {threshold:.6f}")

joblib.dump(threshold, 'threshold.txt')


# STEP 12: Evaluate
y_pred = (mse_test > threshold).astype(int)

print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\nClassification Report:")
print(classification_report(y_true, y_pred))

# STEP 13: ROC Curve
fpr, tpr, _ = roc_curve(y_true, mse_test)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.3f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()
plt.grid(True)
plt.show()

# STEP 14: Save Keras model
autoencoder.save('autoencoder_model.h5')

# STEP 15: Convert to ONNX using tf2onnx
import tf2onnx

spec = (tf.TensorSpec((None, input_dim), tf.float32, name="input"),)
onnx_model, _ = tf2onnx.convert.from_keras(autoencoder, input_signature=spec, opset=13, output_path="autoencoder_model.onnx")

# STEP 16: Download all files
files.download("autoencoder_model.onnx")
files.download("scaler.pkl")
files.download("features.pkl")
with open("threshold.txt", "w") as f:
    f.write(str(threshold))
files.download("threshold.txt")
