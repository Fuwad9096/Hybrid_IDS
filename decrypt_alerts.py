import mysql.connector
import json
from cryptography.fernet import Fernet

# --- Your Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'cryptosafedb'
}

# --- The Encryption Key (You MUST replace this with the key printed by hybrid_ids.py) ---
ENCRYPTION_KEY = b'YOUR_ENCRYPTION_KEY_HERE'

cipher_suite = Fernet(ENCRYPTION_KEY)

def decrypt_alert_details(alert_id):
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor(dictionary=True)

        query = "SELECT details FROM security_events WHERE id = %s"
        cursor.execute(query, (alert_id,))
        result = cursor.fetchone()

        if result and result['details']:
            encrypted_details = result['details'].encode()
            decrypted_details = cipher_suite.decrypt(encrypted_details).decode()
            return json.loads(decrypted_details)
        else:
            return None

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

if __name__ == '__main__':
    alert_id_to_decrypt = 1 # Replace with the ID of the alert you want to decrypt

    # IMPORTANT: Make sure you've updated ENCRYPTION_KEY above
    if ENCRYPTION_KEY == b'YOUR_ENCRYPTION_KEY_HERE':
        print("ERROR: Please update the ENCRYPTION_KEY in this script with the key from hybrid_ids.py")
    else:
        decrypted_data = decrypt_alert_details(alert_id_to_decrypt)

        if decrypted_data:
            print(f"Decrypted details for alert ID {alert_id_to_decrypt}:")
            print(json.dumps(decrypted_data, indent=4))
        else:
            print(f"Could not find or decrypt details for alert ID {alert_id_to_decrypt}.")
