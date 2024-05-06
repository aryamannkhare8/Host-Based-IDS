import pandas as pd

# Read data from the text file into a list of strings
with open('packet_log.txt', 'r') as file:
    lines = file.readlines()

# Initialize empty lists for each column
timestamps, source_ips, dest_ips, protocols, packet_sizes, \
source_ports, dest_ports, dns_queries, payload_data, \
source_macs, dest_macs, protocol_used = [], [], [], [], [], [], [], [], [], [], [], []

timestamp, src_ip, dst_ip, protocol, packet_size, source_port, dest_port, dns_query, payload, source_mac, dest_mac, prot_used = '','','','','','','','','','','',''

# Process each line of the log file
for line in lines:
    
    
    colon_index = line.find(":")
    firstpart = line[:colon_index]
    secondpart = line[colon_index+1:]

    if firstpart == 'Timestamp':
        timestamp = secondpart

    elif firstpart == 'Source IP':
        src_ip = secondpart

    elif firstpart == 'Destination IP':
        dst_ip = secondpart

    elif firstpart == 'Protocol':
        protocol = secondpart

    elif firstpart == 'Packet Size':
        packet_size = secondpart

    elif firstpart == 'Source Port':
        source_port = secondpart

    elif firstpart == 'Destination Port':
        dest_port = secondpart

    elif firstpart == 'Protocol Used':
        prot_used = secondpart

    elif firstpart == 'DNS Query':
        dns_query = secondpart

    elif firstpart == 'Payload Data':
        payload = secondpart

    elif firstpart == 'Source MAC':
        source_mac = secondpart

    elif firstpart == 'Destination MAC':
        dest_mac = secondpart   

    if line.strip() == '':
        timestamps.append(timestamp)
        source_ips.append(src_ip)
        dest_ips.append(dst_ip)
        protocols.append(protocol)
        packet_sizes.append(packet_size)
        source_ports.append(source_port)
        dest_ports.append(dest_port)
        protocol_used.append(prot_used)
        dns_queries.append(dns_query)
        payload_data.append(payload)
        source_macs.append(source_mac)
        dest_macs.append(dest_mac)
        timestamp, src_ip, dst_ip, protocol, packet_size, source_port, dest_port, dns_query, payload, source_mac, dest_mac = '','','','','','','','','','',''
        continue
    

# Create a dictionary from the lists
data = {
    'Timestamp': timestamps,
    'Source IP': source_ips,
    'Destination IP': dest_ips,
    'Protocol': protocols,
    'Packet Size': packet_sizes,
    'Source Port': source_ports,
    'Destination Port': dest_ports,
    'Protocol Used': protocol_used,
    'DNS Query': dns_queries,
    'Payload Data': payload_data,
    'Source MAC': source_macs,
    'Destination MAC': dest_macs
}

# Create a DataFrame from the dictionary
df = pd.DataFrame(data)

# Fill empty cells with blank values
df.fillna('', inplace=False)

# Print the filtered DataFrame
print(df)

df.to_csv('datafram2toCSV.csv', index=True)
