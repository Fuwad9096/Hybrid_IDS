import logging
import json
from datetime import datetime
import mysql.connector
from cryptography.fernet import Fernet

# --- Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'cryptosafedb'
}

# --- Encryption Key ---
ENCRYPTION_KEY = None
cipher_suite = None

class AlertSystem:
    def __init__(self, db_config):
        global ENCRYPTION_KEY, cipher_suite
        from hybrid_ids import ENCRYPTION_KEY as main_key
        ENCRYPTION_KEY = main_key
        cipher_suite = Fernet(ENCRYPTION_KEY)

        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler("security_events.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.db_config = db_config
        self.cnx = None
        self.cursor = None
        self._connect_db()

    def _connect_db(self):
        try:
            self.cnx = mysql.connector.connect(**self.db_config)
            self.cursor = self.cnx.cursor(dictionary=True)
            print("[AlertSystem] Connected to CryptoSafeDB.")
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error connecting to CryptoSafeDB: {err}")
            self.cnx = None
            self.cursor = None

    def _disconnect_db(self):
        if self.cursor:
            self.cursor.close()
        if self.cnx and self.cnx.is_connected():
            self.cnx.close()
            print("[AlertSystem] Disconnected from CryptoSafeDB.")

    async def _execute_query(self, query, data=None):
        try:
            if self.cnx and self.cnx.is_connected():
                self.cursor.execute(query, data)
            else:
                self._connect_db()
                if self.cnx and self.cnx.is_connected():
                    self.cursor.execute(query, data)
                else:
                    self.logger.error("Database connection failed.")
        except mysql.connector.Error as err:
            self.logger.error(f"Database query error: {err} - Query: {query} - Data: {data}")
            self._connect_db() # Try to reconnect

    def _execute_sync_query(self, query, data=None):
        try:
            if self.cnx and self.cnx.is_connected():
                self.cursor.execute(query, data)
            else:
                self._connect_db()
                if self.cnx and self.cnx.is_connected():
                    self.cursor.execute(query, data)
                else:
                    self.logger.error("Database connection failed (sync).")
        except mysql.connector.Error as err:
            self.logger.error(f"Database query error (sync): {err} - Query: {query} - Data: {data}")
            self._connect_db() # Try to reconnect

    async def insert_host(self, ip_address, mac_address=None, hostname=None, timestamp=None):
        try:
            query = "INSERT INTO network_hosts (ip_address, mac_address, hostname, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE last_seen = %s"
            data = (ip_address, mac_address, hostname, timestamp, timestamp, timestamp)
            await self._execute_query(query, data)
            return self.cnx.insert_id()
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error inserting host: {err}")
            return None

    async def fetch_host_by_ip(self, ip_address):
        try:
            query = "SELECT id, ip_address, mac_address, hostname, first_seen, last_seen FROM network_hosts WHERE ip_address = %s"
            await self._execute_query(query, (ip_address,))
            result = self.cursor.fetchone()
            return result
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error fetching host: {err}")
            return None

    async def insert_protocol(self, name, number=None):
        try:
            query = "INSERT INTO protocols (name, number) VALUES (%s, %s) ON DUPLICATE KEY UPDATE number = %s"
            data = (name, number, number)
            await self._execute_query(query, data)
            # Need to fetch the ID after insert/update
            query_fetch = "SELECT id FROM protocols WHERE name = %s"
            await self._execute_query(query_fetch, (name,))
            result = self.cursor.fetchone()
            return result['id'] if result else None
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error inserting protocol: {err}")
            return None

    def fetch_protocols(self):
        try:
            query = "SELECT id, name, number FROM protocols"
            self._execute_sync_query(query)
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error fetching protocols: {err}")
            return []

    def fetch_severities(self):
        try:
            query = "SELECT id, level, score FROM severities"
            self._execute_sync_query(query)
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error fetching severities: {err}")
            return []

    def fetch_event_types(self):
        try:
            query = "SELECT id, name FROM event_types"
            self._execute_sync_query(query)
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error fetching event types: {err}")
            return []

    async def fetch_alert_rule_by_name(self, name):
        try:
            query = "SELECT id, name, description, condition, severity_level_id, category, created_at FROM alert_rules WHERE name = %s"
            await self._execute_query(query, (name,))
            result = self.cursor.fetchone()
            return result
        except mysql.connector.Error as err:
            print(f"[AlertSystem] Error fetching alert rule: {err}")
            return None

    async def process_alert(self, threat, packet_info, src_host_id, dst_host_id, protocol_id, severity_id, event_type_id, alert_rule_id, detection_method):
        timestamp = datetime.now()
        description = threat.get('details', threat['rule']) if threat['type'] == 'signature' else f"Anomaly detected (score: {threat.get('score'):.2f})"
        details_json = json.dumps(threat)
        encrypted_details = cipher_suite.encrypt(details_json.encode()).decode()

        if self.cnx and self.cnx.is_connected():
            try:
                add_event = ("INSERT INTO security_events "
                             "(event_time, event_type_id, severity_id, description, src_host_id, dst_host_id, src_port, dst_port, protocol_id, alert_rule_id, details, detection_method) "
                             "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
                data_event = (timestamp, event_type_id, severity_id, description, src_host_id, dst_host_id, packet_info.get('sport'), packet_info.get('dport'), protocol_id, alert_rule_id, encrypted_details, detection_method)
                await self._execute_query(add_event, data_event)
                await self.cnx.commit()
                self.logger.info(f"Security event stored (details encrypted) in CryptoSafeDB: {self._format_log(threat, packet_info)}")

                severity_level = next((item['level'] for item in self.fetch_severities() if item['id'] == severity_id), 'unknown')
                if severity_level in ['high', 'critical']:
                    self.logger.critical(f"High severity event (details encrypted) in CryptoSafeDB: {self._format_log(threat, packet_info)}")

            except mysql.connector.Error as err:
                self.logger.error(f"Error storing security event in CryptoSafeDB: {err}")
                self._connect_db()
        else:
            self.logger.warning(f"Database not connected, logging to file: {self._format_log(threat, packet_info)}")

        log_message = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Severity ID: {severity_id}, Type: {threat['type']}, Source Host ID: {src_host_id}, Dest Host ID: {dst_host_id}, Details (Encrypted): {encrypted_details[:50]}..."
        print("[ALERT] " + log_message)

    def _map_confidence_to_severity(self, confidence):
        if confidence < 0.4:
            return 'low'
        elif confidence < 0.7:
            return 'medium'
        elif confidence < 0.9:
            return 'high'
        else:
            return 'critical'

    def _format_log(self, threat, packet_info):
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'intrusion_detection',
            'severity': self._map_confidence_to_severity(threat.get('confidence', 0.5)),
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'source_port': packet_info.get('sport'),
            'destination_port': packet_info.get('dport'),
            'protocol': packet_info.get('protocol_name'),
            'details': "(Encrypted)"
        }

    def __del__(self):
        self._disconnect_db()

if __name__ == '__main__':
    # Example usage would typically be from hybrid_ids.py
    pass
