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

train_file_path = '/home/eatgrisha/Documents/squiint/nslkdd/KDDTrain.csv'
train_data = pd.read_csv(train_file_path)
# print(train_data[train_data['protocol_type']=='udp']['flag'].unique())



nmap = train_data[train_data['attack_class']=='nmap']

nmap.to_csv("test.csv")