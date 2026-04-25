import pandas as pd
import joblib
from scipy.sparse import hstack
import numpy as np

# Load phishing URLs to classify (from Level 1 output)
df = pd.read_csv('models/phishing_urls.csv', names=['url'])

# Load saved Level 2 models
vectorizer = joblib.load('models/tfidf_vectorizer_level2.pkl')
scaler = joblib.load('models/numeric_scaler_level2.pkl')
kmeans = joblib.load('models/kmeans_level2.pkl')

print(f"Loaded models: Vectorizer, Scaler, KMeans with {kmeans.n_clusters} clusters")
print(f"Loaded {len(df)} URLs for testing")

# Numeric features extraction function
def extract_numeric_features(urls):
    features = []
    for url in urls:
        length = len(url)
        digits = sum(c.isdigit() for c in url)
        special = sum(c in "-_./?=&" for c in url)
        ext = 1 if any(url.lower().endswith(e) for e in ['.exe', '.zip', '.scr', '.bat', '.dll']) else 0
        features.append([length, digits, special, ext])
    return np.array(features)

# Extract and scale numeric features
numeric_features = extract_numeric_features(df['url'])
numeric_features_scaled = scaler.transform(numeric_features)

# Transform URLs with TF-IDF vectorizer
X_text = vectorizer.transform(df['url'])

# Combine text and numeric features
X_combined = hstack([X_text, numeric_features_scaled])

# Predict cluster assignments for each URL
df['cluster'] = kmeans.predict(X_combined)

# Load terms and centroids for mapping
terms = vectorizer.get_feature_names_out()
centroids = kmeans.cluster_centers_[:, :len(terms)]  # only TF-IDF portion

# Subtype keyword definitions
subtypes = {
    'freebie': ['free', 'gift', 'bonus', 'reward', 'win', 'prize'],
    'redirect': ['redirect', 'goto', 'login', 'secure'],
    'malware': ['download', 'exe', 'zip', 'patch', 'update', 'alert', 'file', 'virus'],
    'IDN': [chr(i) for i in range(128, 256)]  # non-ASCII chars for IDN detection
}

cluster_mapping = {}

num_clusters = kmeans.n_clusters
for i in range(num_clusters):
    centroid = centroids[i]
    scores = {subtype: 0.0 for subtype in subtypes}
    
    # Weighted keyword scoring
    for idx, weight in enumerate(centroid):
        term = terms[idx]
        for subtype, keywords in subtypes.items():
            if any(keyword in term for keyword in keywords):
                scores[subtype] += weight
    
    # IDN detection from top 20 weighted terms
    top20_idx = centroid.argsort()[-20:][::-1]
    top20_terms = [terms[idx] for idx in top20_idx]
    if any(ord(c) > 127 for c in ''.join(top20_terms)):
        cluster_mapping[i] = 'IDN'
    elif max(scores.values()) > 0:
        cluster_mapping[i] = max(scores, key=scores.get)
    else:
        cluster_mapping[i] = 'suspicious'

# Map cluster indices to phishing subtypes
df['phishing_subtype'] = df['cluster'].map(cluster_mapping)

# Save results to CSV
df.to_csv('models/phishing_level2_test_results.csv', index=False)

print("Level 2 testing complete with improved cluster mapping.")