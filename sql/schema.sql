CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `recent_login_failures_cnt` INTEGER NOT NULL DEFAULT 0,
  `last_ip` VARCHAR(20) NOT NULL DEFAULT '',
  `last_logged_in_at` DATETIME NULL,
  `current_ip` VARCHAR(20) NOT NULL DEFAULT '',
  `current_logged_in_at` DATETIME NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `login_log` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime NOT NULL,
  `user_id` int,
  `login` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `succeeded` tinyint NOT NULL,
  KEY (login),
  KEY (ip),
  KEY (user_id,succeeded,id)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `ip_login_failure` (
  `ip` varchar(255) NOT NULL PRIMARY KEY,
  `cnt` INT UNSIGNED NOT NULL
) DEFAULT CHARSET=utf8;
