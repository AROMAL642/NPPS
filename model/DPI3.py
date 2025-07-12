import kagglehub

# Download latest version
path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")

print("Path to dataset files:", path)




import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)

# Input data files are available in the read-only "../input/" directory
# For example, running this (by clicking run or pressing Shift+Enter) will list all files under the input directory

import os
for dirname, _, filenames in os.walk('/kaggle/input'):
    for filename in filenames:
        print(os.path.join(dirname, filename))

file_path = '/kaggle/input/network-intrusion-dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
df = pd.read_csv(file_path)

df.columns = df.columns.str.strip()
print(df.head())

print(df.columns)


import matplotlib.pyplot as plt

label_counts = df['Label'].value_counts()
print("Distribution of Classes:")
print(label_counts)

normal_count = label_counts.get('BENIGN', 0)
attack_count = label_counts.sum() - normal_count

print(f"\nNormal Connections (BENIGN): {normal_count}")
print(f"Attacks (of all types): {attack_count}")


label_counts = df['Label'].value_counts()

benign_count = label_counts.get('BENIGN', 0)

attack_counts = label_counts.drop('BENIGN')

plot_labels = ['BENIGN'] + attack_counts.index.tolist()
plot_sizes = [benign_count] + attack_counts.values.tolist()

plt.figure(figsize=(10,10))
plt.pie(plot_sizes, labels=plot_labels, autopct='%1.1f%%', startangle=90)
plt.title('Connection Types Distribution')
plt.show()




from sklearn.preprocessing import StandardScaler
from tensorflow.keras import layers, models, callbacks

df.columns = df.columns.str.strip()
features = df.columns.tolist()
features.remove('Label')

train_df = df[df['Label'] == 'BENIGN'].copy()
train_features = train_df[features]

train_features.replace([np.inf, -np.inf], np.nan, inplace=True)

train_features = train_features.fillna(train_features.median())

test_df = df.copy()
test_features = test_df[features]
test_features.replace([np.inf, -np.inf], np.nan, inplace=True)
test_features = test_features.fillna(test_features.median())

print("Train NaNs:", train_features.isna().sum().sum())
print("Train Infs:", np.isinf(train_features.values).sum())
print("Test NaNs:", test_features.isna().sum().sum())
print("Test Infs:", np.isinf(test_features.values).sum())

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(train_features)
X_test_scaled = scaler.transform(test_features)

print(X_train_scaled.shape, X_test_scaled.shape)

input_dim = X_train_scaled.shape[1]

input_layer = layers.Input(shape=(input_dim,))

encoded = layers.Dense(256)(input_layer)
encoded = layers.LeakyReLU(alpha=0.1)(encoded)
encoded = layers.BatchNormalization()(encoded)
encoded = layers.Dropout(0.3)(encoded)

encoded = layers.Dense(128)(encoded)
encoded = layers.LeakyReLU(alpha=0.1)(encoded)
encoded = layers.BatchNormalization()(encoded)
encoded = layers.Dropout(0.3)(encoded)

encoded = layers.Dense(64)(encoded)
encoded = layers.LeakyReLU(alpha=0.1)(encoded)
encoded = layers.BatchNormalization()(encoded)
encoded = layers.Dropout(0.2)(encoded)

encoded = layers.Dense(32)(encoded)
encoded = layers.LeakyReLU(alpha=0.1)(encoded)

decoded = layers.Dense(64)(encoded)
decoded = layers.LeakyReLU(alpha=0.1)(decoded)
decoded = layers.BatchNormalization()(decoded)
decoded = layers.Dropout(0.2)(decoded)

decoded = layers.Dense(128)(decoded)
decoded = layers.LeakyReLU(alpha=0.1)(decoded)
decoded = layers.BatchNormalization()(decoded)
decoded = layers.Dropout(0.3)(decoded)

decoded = layers.Dense(256)(decoded)
decoded = layers.LeakyReLU(alpha=0.1)(decoded)
decoded = layers.BatchNormalization()(decoded)
decoded = layers.Dropout(0.3)(decoded)

decoded = layers.Dense(input_dim, activation='linear')(decoded)

autoencoder = models.Model(inputs=input_layer, outputs=decoded)
autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.summary()

early_stop = callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

history = autoencoder.fit(
    X_train_scaled, X_train_scaled,
    epochs=100,
    batch_size=64,
    validation_split=0.1,
    shuffle=True,
    callbacks=[early_stop]
)

X_test_pred = autoencoder.predict(X_test_scaled)
mse = np.mean(np.power(X_test_scaled - X_test_pred, 2), axis=1)

X_train_pred = autoencoder.predict(X_train_scaled)
mse_train = np.mean(np.power(X_train_scaled - X_train_pred, 2), axis=1)





X_test_pred = autoencoder.predict(X_test_scaled)

mse = np.mean(np.power(X_test_scaled - X_test_pred, 2), axis=1)

X_train_pred = autoencoder.predict(X_train_scaled)
mse_train = np.mean(np.power(X_train_scaled - X_train_pred, 2), axis=1)

threshold = np.percentile(mse_train, 95)
print(f"Reconstruction Error Threshold (95th Percentile): {threshold}")

y_true = (df['Label'] != 'BENIGN').astype(int)

y_pred = (mse > threshold).astype(int)
print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\nClassification Report:")
print(classification_report(y_true, y_pred, target_names=['Normal', 'Anomalie']))

cm = confusion_matrix(y_true, y_pred)

plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Normal (0)', 'Anomaly (1)'],
            yticklabels=['Normal (0)', 'Anomaly (1)'])
plt.xlabel('Predicted Class')
plt.ylabel('True Class')
plt.title('Confusion Matrix')
plt.show()


fpr, tpr, thresholds = roc_curve(y_true, mse)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(8,6))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.3f})')
plt.plot([0,1], [0,1], 'k--', label='Random')
plt.xlabel('False Positive Rate (FPR)')
plt.ylabel('True Positive Rate (TPR)')
plt.title('ROC Curve for Anomaly Detection')
plt.legend(loc='lower right')
plt.show()
