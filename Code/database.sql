-- MySQL schema for Network IDS application

CREATE DATABASE IF NOT EXISTS `network_ids`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `network_ids`;

-- Users table: authentication and roles
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(120) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `full_name` VARCHAR(120) DEFAULT NULL,
  `profile_image` VARCHAR(255) DEFAULT NULL,
  `role` ENUM('user','admin') NOT NULL DEFAULT 'user',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- PCAP uploads metadata
CREATE TABLE IF NOT EXISTS `pcap_uploads` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` INT UNSIGNED NOT NULL,
  `original_filename` VARCHAR(255) NOT NULL,
  `stored_path` VARCHAR(255) NOT NULL,
  `filesize_bytes` BIGINT UNSIGNED NOT NULL,
  `status` ENUM('pending','analyzing','completed','failed') NOT NULL DEFAULT 'pending',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed_at` TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  CONSTRAINT `fk_upload_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IDS rules: simple rule-based signatures
CREATE TABLE IF NOT EXISTS `ids_rules` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `description` TEXT,
  `severity` ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
  `enabled` TINYINT(1) NOT NULL DEFAULT 1,
  -- rule_type: which field to match on (e.g. src_ip, dst_ip, dst_port, protocol, payload_contains)
  `rule_type` ENUM('src_ip','dst_ip','src_port','dst_port','protocol','payload_contains') NOT NULL,
  `match_value` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Analysis results: one record per triggered alert
CREATE TABLE IF NOT EXISTS `analysis_results` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `upload_id` INT UNSIGNED NOT NULL,
  `rule_id` INT UNSIGNED NULL,
  `severity` ENUM('info','warning','critical') NOT NULL,
  `summary` VARCHAR(255) NOT NULL,
  `src_ip` VARCHAR(45) DEFAULT NULL,
  `dst_ip` VARCHAR(45) DEFAULT NULL,
  `src_port` INT UNSIGNED DEFAULT NULL,
  `dst_port` INT UNSIGNED DEFAULT NULL,
  `protocol` VARCHAR(16) DEFAULT NULL,
  `packet_timestamp` DATETIME DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_upload` (`upload_id`),
  KEY `idx_rule` (`rule_id`),
  CONSTRAINT `fk_result_upload` FOREIGN KEY (`upload_id`) REFERENCES `pcap_uploads`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_result_rule` FOREIGN KEY (`rule_id`) REFERENCES `ids_rules`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed an initial admin user (change password after first login)
INSERT INTO `users` (`username`, `email`, `password_hash`, `full_name`, `role`)
VALUES (
  'admin',
  'admin@example.com',
  -- password: Admin@123 (bcrypt)
  '$2y$10$k2aC54Cn3V7o/6B7dbZ0fO6dKDju8wPDbjjoGmVDHfbVyW0L/p93C',
  'Administrator',
  'admin'
)
ON DUPLICATE KEY UPDATE email = VALUES(email);

-- Seed some example IDS rules
INSERT INTO `ids_rules` (`name`, `description`, `severity`, `enabled`, `rule_type`, `match_value`) VALUES
('Suspicious destination port 23', 'Detects traffic to Telnet (often abused)', 'warning', 1, 'dst_port', '23'),
('Critical port 3389', 'Detects RDP exposure attempts', 'critical', 1, 'dst_port', '3389'),
('Possible malware C2 IP', 'Matches known malicious IP address', 'critical', 1, 'dst_ip', '203.0.113.50'),
('Cleartext password keyword', 'Detects payloads containing password keyword', 'warning', 1, 'payload_contains', 'password');

