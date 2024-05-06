from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import plot_tree
import matplotlib.pyplot as plt
import pandas as pd

# Load data from UpdatedDataFile.csv
file_path = 'UpdatedDataFile.csv'
df = pd.read_csv(file_path)

# Label encoding for categorical columns
label_encoder = LabelEncoder()
df['Source IP'] = label_encoder.fit_transform(df['Source IP'])
df['Destination IP'] = label_encoder.fit_transform(df['Destination IP'])
df['Source MAC'] = label_encoder.fit_transform(df['Source MAC'])
df['Destination MAC'] = label_encoder.fit_transform(df['Destination MAC'])
df['DNS Query'] = label_encoder.fit_transform(df['DNS Query'])
df['Protocol Used'] = label_encoder.fit_transform(df['Protocol Used'])
# df['Intrusion Status'] = label_encoder.fit_transform(df['Intrusion Status'])
df = pd.get_dummies(df, columns=['Intrusion Status'], prefix=['Intrusion Status'])

# Features and target variable
features = [
    'Protocol',
    'Source Port',
    'Packet Size',
    'Protocol Used',
]

target = 'Intrusion Status_Normal'


# Extract features and target variable
X = df[features]
y = df[target]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.8, random_state=42)

# Initialize the decision tree classifier
clf = DecisionTreeClassifier(random_state=42)

# Train the classifier
clf.fit(X_train, y_train)

# Make predictions on the test set
predictions = clf.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, predictions)
print("Accuracy:", accuracy)

# Custom function to annotate decision tree plot
def annotate_tree_plot(tree, feature_names, ax=None):
    if ax is None:
        ax = plt.gca()

    n_nodes = tree.tree_.node_count
    children_left = tree.tree_.children_left
    children_right = tree.tree_.children_right
    feature = tree.tree_.feature
    threshold = tree.tree_.threshold

    for node in range(n_nodes):
        if children_left[node] != children_right[node]:  # if not a leaf node
            ax.annotate(f'{feature_names[feature[node]]} <= {threshold[node]:.2f}', 
                        (threshold[node], node), 
                        xytext=(20, -20), 
                        textcoords='offset points',
                        va='center', 
                        ha='center')
        else:
            class_label = tree.classes_[tree.tree_.value[node].argmax()]
            ax.annotate(f'Class: {class_label}', 
                        (threshold[node], node), 
                        xytext=(20, -20), 
                        textcoords='offset points',
                        va='center', 
                        ha='center')

# Plot the decision tree with annotated nodes
plt.figure(figsize=(20, 10))
plot_tree(clf, feature_names=features, class_names=True, filled=True, rounded=True)
annotate_tree_plot(clf, features)
plt.show()
