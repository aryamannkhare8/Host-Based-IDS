import pandas as pd

# Read data from the existing CSV file into a DataFrame
input_file_path = 'datafram2toCSV.csv'
output_file_path = 'UpdatedDataFile.csv'

df = pd.read_csv(input_file_path)

# Define a function to classify packets
def classify_intrusion(row):
    if row['Packet Size'] > 2000 or (row['Destination Port'] in [22, 23, 25, 53, 110, 143, 389, 445, 3389, 3306, 5432, 161, 162, 123, 137, 138, 139] and row['Protocol']==6) or row['Source IP'] in ['192.168.1.1']:
        return 'Intrusion'
    else:
        return 'Normal'

# Apply the function to create the 'Intrusion Status' column
df['Intrusion Status'] = df.apply(classify_intrusion, axis=1)

# Save the updated DataFrame to a new CSV file
df.to_csv(output_file_path, index=False)

print(f'Dataframe with "Intrusion Status" column saved to {output_file_path}')



