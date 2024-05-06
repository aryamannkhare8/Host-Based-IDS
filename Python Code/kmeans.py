from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import matplotlib.pyplot as plt

file_path = 'datafram2toCSV.csv'

df = pd.read_csv(file_path)

label_encoder = LabelEncoder()
df['Source IP'] = label_encoder.fit_transform(df['Source IP'])
df['Destination IP'] = label_encoder.fit_transform(df['Destination IP'])
df['Source MAC'] = label_encoder.fit_transform(df['Source MAC'])
df['Destination MAC'] = label_encoder.fit_transform(df['Destination MAC'])
df['DNS Query'] = label_encoder.fit_transform(df['DNS Query'])
df['Protocol Used'] = label_encoder.fit_transform(df['Protocol Used'])
df['Protocol'] = label_encoder.fit_transform(df['Protocol'])

# Drop rows with NaN values
df = df.dropna()

# Select features for clustering
features = [
    'Packet Size',  # Change X-axis feature
    'Source Port'   # Change Y-axis feature
]

# Normalize the features
scaler = StandardScaler()
scaled_features = scaler.fit_transform(df[features])

# Specify the number of clusters (you can adjust this based on your problem)
num_clusters = 9

# Apply K-means clustering
kmeans = KMeans(n_clusters=num_clusters, random_state=42)
kmeans.fit(scaled_features)

# Add cluster labels to the original DataFrame
df['Cluster'] = kmeans.labels_

# Print the cluster assignments
print("Cluster Assignments:")
print(df[['Packet Size', 'Source Port', 'Cluster']])

# To get cluster centers (centroids)
print("Cluster Centers:")
print(scaler.inverse_transform(kmeans.cluster_centers_))

# Plot the clusters based on original features
plt.figure(figsize=(8, 6))

# Scatter plot for each cluster based on original features
for cluster_label in range(num_clusters):
    cluster_data = df[df['Cluster'] == cluster_label]
    plt.scatter(cluster_data['Packet Size'], cluster_data['Source Port'], label=f'Cluster {cluster_label}', alpha=0.7)

plt.scatter(scaler.inverse_transform(kmeans.cluster_centers_)[:, 0], scaler.inverse_transform(kmeans.cluster_centers_)[:, 1], marker='X', s=200, color='red', label='Centroids')
plt.xlabel('Packet Size')
plt.ylabel('Source Port')
plt.title('KMeans Clustering based on Custom Features')
plt.legend()
plt.show()
