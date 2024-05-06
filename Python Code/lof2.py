import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import accuracy_score

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
df['Destination Port'] = label_encoder.fit_transform(df['Destination Port'])
# Drop rows with NaN values

df = df.dropna()

# Select relevant features for LOF (Packet Size and Protocol)
features = df[['Protocol Used','Protocol'] ]


# Apply Local Outlier Factor algorithm
lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
outliers = lof.fit_predict(features)

# Add outlier labels to the DataFrame
df['Outlier'] = outliers

print("Outliers:")
print(df[df['Outlier'] == -1])



# Plot outliers using a scatter plot
plt.figure(figsize=(10, 7))
plt.scatter(df['Packet Size'], df['Destination Port'], c=df['Outlier'], cmap='coolwarm')
plt.xlabel('Packet Size')
plt.ylabel('Destination Port')  # Change this line to set the y-axis label to Destination Port
plt.title('Outliers Detected by LOF Algorithm')
plt.colorbar(label='Outlier Score')
plt.show()

# Print or analyze outliers



