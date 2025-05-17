-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS cryptosafedb;

-- Switch to the cryptosafedb database
USE cryptosafedb;

-- Table: event_types
CREATE TABLE IF NOT EXISTS event_types (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    INDEX (name)
);

-- Table: severities
CREATE TABLE IF NOT EXISTS severities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    level VARCHAR(50) UNIQUE NOT NULL,
    score INT,
    INDEX (level),
    INDEX (score)
);

-- Table: protocols
CREATE TABLE IF NOT EXISTS protocols (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(10) UNIQUE NOT NULL,
    number INT UNIQUE,
    INDEX (name),
    INDEX (number)
);

-- Table: network_hosts
CREATE TABLE IF NOT EXISTS network_hosts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50) UNIQUE NOT NULL,
    mac_address VARCHAR(50) UNIQUE,
    hostname VARCHAR(255),
    first_seen DATETIME,
    last_seen DATETIME,
    INDEX (ip_address),
    INDEX (mac_address),
    INDEX (hostname)
);

-- Table: alert_rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    condition TEXT,
    severity_level_id INT,
    category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (name),
    INDEX (severity_level_id),
    INDEX (category),
    FOREIGN KEY (severity_level_id) REFERENCES severities(id)
);

-- Table: security_events
CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time DATETIME NOT NULL,
    event_type_id INT NOT NULL,
    severity_id INT NOT NULL,
    description TEXT,
    src_host_id BIGINT NOT NULL,
    dst_host_id BIGINT NOT NULL,
    src_port INT,
    dst_port INT,
    protocol_id INT NOT NULL,
    alert_rule_id BIGINT,
    details TEXT, -- Encrypted JSON
    detection_method VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (event_time),
    INDEX (event_type_id),
    INDEX (severity_id),
    INDEX (src_host_id),
    INDEX (dst_host_id),
    INDEX (src_port),
    INDEX (dst_port),
    INDEX (protocol_id),
    INDEX (alert_rule_id),
    INDEX (detection_method),
    INDEX (created_at),
    FOREIGN KEY (event_type_id) REFERENCES event_types(id),
    FOREIGN KEY (severity_id) REFERENCES severities(id),
    FOREIGN KEY (src_host_id) REFERENCES network_hosts(id),
    FOREIGN KEY (dst_host_id) REFERENCES network_hosts(id),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id),
    FOREIGN KEY (alert_rule_id) REFERENCES alert_rules(id)
);

-- SQL to populate lookup tables (optional, but recommended)
USE cryptosafedb;

-- Populate event_types
INSERT INTO event_types (name) VALUES
('intrusion_detection'),
('policy_violation'),
('system_anomaly');

-- Populate severities
INSERT INTO severities (level, score) VALUES
('low', 1),
('medium', 2),
('high', 3),
('critical', 4);

-- Populate protocols (common ones)
INSERT INTO protocols (name, number) VALUES
('TCP', 6),
('UDP', 17),
('ICMP', 1),
('HTTP', NULL),
('HTTPS', NULL),
('DNS', 53);

-- Example of populating alert_rules
INSERT INTO alert_rules (name, description, condition, severity_level_id, category) VALUES
('syn_flood', 'Possible SYN flood attack', 'tcp_flags == "S" and packet_rate > 10', (SELECT id FROM severities WHERE level = 'high'), 'denial_of_service'),
('port_scan', 'Possible port scanning activity', 'packet_size < 100 and packet_rate > 5', (SELECT id FROM severities WHERE level = 'medium'), 'reconnaissance');
