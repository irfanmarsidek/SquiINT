import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout # type: ignore
from tensorflow.keras.utils import to_categorical # type: ignore
from scipy.io import arff
import joblib

# Load the .arff file
train_file_path = '/home/eatgrisha/Documents/squiint/dataset/kdd_train.csv'
test_file_path = '/home/eatgrisha/Documents/squiint/dataset/kdd_test.csv'
drop_columns = [
    "wrong_fragment",
    "urgent",
    "hot", 
    "num_failed_logins", 
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]
train_data = pd.read_csv(train_file_path)
train_data.drop(columns=drop_columns,inplace=True)
test_data = pd.read_csv(test_file_path)
test_data.drop(columns=drop_columns,inplace=True)

# Select categorical columns to encode
categorical_columns = ['protocol_type', 'service', 'flag']

# Set encoder
encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
encoded_features = encoder.fit_transform(train_data[categorical_columns])

# Save the encoder
joblib.dump(encoder, "encoder.joblib")

# Replace the original categorical columns with the encoded ones in your data
encoded_df = pd.DataFrame(encoded_features, columns=encoder.get_feature_names_out(categorical_columns))
train_data = pd.concat([train_data.drop(categorical_columns, axis=1), encoded_df], axis=1)
test_data = pd.concat([test_data.drop(categorical_columns, axis=1), encoded_df], axis=1)

# Standardize classes in test data and train data

picked_class = ['normal','neptune','nmap','satan','back','land']
test_data = test_data[test_data['labels'].isin(picked_class)]
train_data = train_data[train_data['labels'].isin(picked_class)]

# Map class labels to integers
class_mapping = {label: idx for idx, label in enumerate(train_data['labels'].unique())}
train_data['labels'] = train_data['labels'].map(class_mapping)
test_data['labels'] = test_data['labels'].map(class_mapping)

attacks = [label for label in class_mapping.keys()]

# Separate features and target
X_train = train_data.drop(columns=['labels'])
X_test = test_data.drop(columns=['labels'])
y_train = to_categorical(train_data['labels'], num_classes=len(class_mapping))
y_test = to_categorical(test_data['labels'], num_classes=len(class_mapping))

# Scaling
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Reshape data for CNN input (assuming a 1D CNN with shape (118, 1))
X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
X_test = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))

# Build CNN model
model = Sequential([
    Conv1D(32, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
    MaxPooling1D(pool_size=2),
    Dropout(0.25),
    
    Conv1D(64, kernel_size=3, activation='relu'),
    MaxPooling1D(pool_size=2),
    Dropout(0.25),
    
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.5),
    Dense(len(attacks), activation='softmax')  # 2 classes: anomaly (0) and normal (1)
])

# Compile the model
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Train the model with progress
history = model.fit(X_train, y_train, epochs=20, batch_size=64, validation_data=(X_test, y_test))

# Save the model
model.save('granular-cnn-model.h5')
joblib.dump(scaler, 'scaler.pkl')

# Evaluate the model
test_loss, test_accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_accuracy * 100:.2f}%")

# Optional: Print classification report
from sklearn.metrics import classification_report

y_pred = np.argmax(model.predict(X_test), axis=1)
y_true = np.argmax(y_test, axis=1)

print(classification_report(y_true, y_pred, target_names=attacks))
