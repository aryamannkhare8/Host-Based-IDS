import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

file_path = 'UpdatedDataFile.csv'

# Read data from CSV file
df = pd.read_csv(file_path)

label_encoder = LabelEncoder()
df['Source IP'] = label_encoder.fit_transform(df['Source IP'])
df['Destination IP'] = label_encoder.fit_transform(df['Destination IP'])
df['Source MAC'] = label_encoder.fit_transform(df['Source MAC'])
df['Destination MAC'] = label_encoder.fit_transform(df['Destination MAC'])
df['DNS Query'] = label_encoder.fit_transform(df['DNS Query'])
df['Protocol Used'] = label_encoder.fit_transform(df['Protocol Used'])
df['Intrusion Status'] = label_encoder.fit_transform(df['Intrusion Status'])

# Drop rows with NaN values
# df = df.dropna()

# Select relevant features for LOF (Packet Size and Protocol Used)
features = df[['Protocol Used','Protocol'] ]

# Apply Local Outlier Factor algorithm
lof = LocalOutlierFactor(n_neighbors=12, contamination=0.1)
outliers = lof.fit_predict(features)

# Add outlier labels to the DataFrame
df['Outlier'] = outliers

# Create a 3D scatter plot
fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(111, projection='3d')
ax.scatter(df['Packet Size'], df['Protocol Used'], df['Outlier'], c=df['Outlier'], cmap='coolwarm')
ax.set_xlabel('Packet Size')
ax.set_ylabel('Protocol Used')
ax.set_zlabel('Outlier')
ax.set_title('Outliers Detected by LOF Algorithm')
plt.show()

# Print or analyze outliers
print("Outliers:")
print(df[df['Outlier'] == -1])
