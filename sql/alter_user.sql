ALTER TABLE `users`
  ADD `last_ip` VARCHAR(20) NOT NULL DEFAULT '',
  ADD `last_logged_in_at` DATETIME NULL,
  ADD `current_ip` VARCHAR(20) NOT NULL DEFAULT '',
  ADD `current_logged_in_at` DATETIME NULL;
