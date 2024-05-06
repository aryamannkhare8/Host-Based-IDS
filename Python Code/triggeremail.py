# Import required libraries for sending emails
import smtplib
from email.mime.text import MIMEText
import datetime

# List of port numbers that are often targeted or used maliciously
suspicious_ports = [22, 23, 25, 53, 110, 143, 389, 445, 3389, 3306, 5432, 161, 162, 123, 137, 138, 139]

def analysePort(port_number):
    """ Analyze the port number to determine if it's suspicious based on predefined suspicious ports.
    
    Args:
        port_number (int): The port number to analyze.
        
    Returns:
        int: Returns 1 if the port is suspicious, 0 otherwise.
    """
    # Check if the port number is in the list of suspicious ports
    if port_number in suspicious_ports:
        return 1
    return 0

def analyseSize(pacLen):
    """ Analyze the packet length to determine if it's unusually large.
    
    Args:
        pacLen (int): The length of the packet.
        
    Returns:
        int: Returns 1 if the packet is suspiciously large, 0 otherwise.
    """
    # Define a threshold for what is considered a large packet
    if pacLen > 2000:
        return 1
    return 0

def send_email(sus_timestamps):
    """ Send an email alerting of detected intrusions based on suspicious activity timestamps.
    
    Args:
        sus_timestamps (list): List of timestamps when suspicious activity was detected.
    """
    # Starting the message text
    text = "This is an alert from your host-based IDS. An intrusion has been detected.\n\n"
    
    # Adding the time of each detected intrusion to the message
    for timestamp in sus_timestamps:
        formatted_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
        text += f"An intrusion has been detected at {formatted_time}\n"

    # Print the alert message to the console
    print("\n" + text)

    # Create an email message with the text
    msg = MIMEText(text)
    msg['Subject'] = 'Host-based IDS alert'
    msg['From'] = 'test@gmail.com'
    msg['To'] = 'receiver@gmail.com'

    # Set up the SMTP object using Gmail's SMTP server
    smtp_obj = smtplib.SMTP('smtp.gmail.com', 587)
    smtp_obj.starttls()  # Start TLS encryption
    smtp_obj.login('test@gmail.com', 'one time app password')  # Login to the SMTP server
    smtp_obj.sendmail(msg['From'], msg['To'], msg.as_string())  # Send the email
    smtp_obj.quit()  # Quit the SMTP session
