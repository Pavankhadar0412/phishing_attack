"""
Prepare dataset by extracting features from URLs
"""

import pandas as pd
from feature_extraction import extract_url_features

# Load the dataset
df = pd.read_csv('dataset/phishing.csv')
print(f"Original dataset shape: {df.shape}")

# Extract features for each URL
print("Extracting features from URLs...")
features_list = []

for idx, row in df.iterrows():
    url = row['url']
    label = row['label']
    
    # Extract features
    features = extract_url_features(url)
    features['label'] = label
    
    features_list.append(features)
    
    if (idx + 1) % 10 == 0:
        print(f"Processed {idx + 1}/{len(df)} URLs")

# Create new dataframe with features
features_df = pd.DataFrame(features_list)
print(f"Features dataset shape: {features_df.shape}")

# Save the features dataset
features_df.to_csv('dataset/phishing_features.csv', index=False)
print("Features dataset saved to dataset/phishing_features.csv")
print(f"Feature columns: {list(features_df.columns)}")
