import argparse
from datetime import datetime
import os

# Define the path to the log file
LOG_FILE_PATH = '/opt/rapido_bank/logs/important_logs/security_events.log'

def log_event(event_type, details, log_file=LOG_FILE_PATH):
    """Log security events with their details."""
    event = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_type': event_type,
        'details': details
    }
    with open(log_file, 'a+') as lf:
        lf.write(f"{event['timestamp']} - {event['event_type']} - {event['details']}\n")
    print(f"Logged event: {event_type} - {details}")

def parse_log_file(log_file_path):
    """Parse the log file and return a list of event dictionaries."""
    events = []
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            parts = line.strip().split(' - ')
            if len(parts) != 3:
                continue
            event = {
                'timestamp': parts[0],
                'event_type': parts[1],
                'details': parts[2]
            }
            events.append(event)
    return events

def generate_security_recommendations(events):
    """Generate security recommendations based on logged events."""
    recommendations = []
    for event in events:
        event_type = event['event_type']
        details = event['details']

        if event_type == 'YARA Alert':
            recommendations.append(f"Investigate the file: {details}")
        elif event_type == 'YARA Alert - file non-exist':
            recommendations.append(f"Investigate the file: {details}")
        elif event_type == 'YARA Alert - no matching rules':
            recommendations.append(f"Investigate the file: {details}")
        elif event_type == 'Isolated File':
            recommendations.append(f"Investigate the file: {details}")
        elif event_type == 'Malware Test':
            severity = details.split('Severity: ')[1]
            if severity in ['Severe', 'Extreme']:
                recommendations.append(f"Delete or quarantine the file: {details.split(' tested positive')[0]}")
            else:
                recommendations.append(f"Review and monitor the file: {details.split(' tested positive')[0]}")
        elif event_type == 'Malware Test - Failed':
            recommendations.append(f"Be carefully handling this file: {details}")
        elif event_type == 'File Deletion':
            recommendations.append(f"Ensure the deleted file is not critical to operations: {details}")
        elif event_type == 'File Restoration':
            recommendations.append(f"Verify the integrity and security of the restored file: {details}")
        elif event_type == 'Backup Needed':
            recommendations.append("Key rotation has been deferred. Complete backup as soon as possible")
        elif event_type == 'Key not Found':
            recommendations.append("No existing found, check if it was accidentally deleted.")    
        elif event_type == 'Key Rotation':
            recommendations.append("Ensure all sensitive files have been re-encrypted with the new keys.")
        elif event_type == 'Key Regeneration':
            recommendations.append("Verify that the new keys are stored securely and are accessible only to authorized personnel.")
        elif event_type == 'Hourly Backup':
            recommendations.append("Check the integrity of hourly backups and ensure they are complete.")
        elif event_type == 'Daily Backup':
            recommendations.append("Check the integrity of daily backups and ensure they are complete.")
        elif event_type == 'Hourly Backup Error':
            recommendations.append(f"Investigate the cause of the hourly backup failure: {details}")
        elif event_type == 'Daily Backup Error':
            recommendations.append(f"Investigate the cause of the daily backup failure: {details}")
        elif event_type == 'Key Rotation Error':
            recommendations.append(f"Investigate the cause of the key rotation error: {details}")
        elif event_type == 'Unauthorized User':
            recommendations.append(f"Revoke permissions and investigate activities of unauthorized user: {details}")
        elif event_type == 'Save Key Permission Denied' or event_type == 'Encryption Permission Denied':
            recommendations.append(f"Check current user is logged in: {details}")
        elif event_type == 'Save Key Error' or event_type == 'Encryption Error' or event_type == 'YARA Scanning Error':
            recommendations.append(f"Check file/directory: {details}")
        else:
            recommendations.append(f"{event_type} logged with detail: {details}. Security recommendation unavailable for this event.")



    return recommendations

def main(log_file_path):
    """Main function to parse log file and generate recommendations."""
    events = parse_log_file(log_file_path)
    recommendations = generate_security_recommendations(events)
    print("\nSecurity Recommendations:")
    for recommendation in recommendations:
        print(f"- {recommendation}")
    with open(log_file_path, 'w') as log_file:
        log_file.truncate(0)

if __name__ == "__main__":
    # log_event("test event", "test event details", log_file=LOG_FILE_PATH) 
    parser = argparse.ArgumentParser(description='Generate security recommendations based on MTD log events.')
    parser.add_argument('--log-file', type=str, default=LOG_FILE_PATH, help='Path to the log file')
    args = parser.parse_args()
    main(log_file_path=args.log_file)

