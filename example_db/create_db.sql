-- Zahájení transakce
START TRANSACTION;

-- Vytvoření uživatelů (nebo rolí)
CREATE USER IF NOT EXISTS 'public_user'@'%' IDENTIFIED BY 'password';
CREATE USER IF NOT EXISTS 'private_user'@'%' IDENTIFIED BY 'password';
CREATE USER IF NOT EXISTS 'admin_user'@'localhost' IDENTIFIED BY 'password';

-- Omezení připojení
ALTER USER 'public_user'@'%' WITH MAX_USER_CONNECTIONS 10;
ALTER USER 'private_user'@'%' WITH MAX_USER_CONNECTIONS 10;
ALTER USER 'admin_user'@'localhost' WITH MAX_USER_CONNECTIONS 20;

-- Vytvoření schématu
CREATE DATABASE IF NOT EXISTS my_schema;

-- Přepnutí do schématu
USE my_schema;

-- Vytvoření tabulek
CREATE TABLE IF NOT EXISTS public_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

CREATE TABLE IF NOT EXISTS private_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

CREATE TABLE IF NOT EXISTS secret_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

-- Nastavení oprávnění
GRANT SELECT ON my_schema.public_info TO 'public_user'@'%';
GRANT SELECT ON my_schema.public_info TO 'private_user'@'%';
GRANT SELECT ON my_schema.private_info TO 'private_user'@'%';

GRANT ALL PRIVILEGES ON my_schema.public_info TO 'admin_user'@'localhost';
GRANT ALL PRIVILEGES ON my_schema.private_info TO 'admin_user'@'localhost';
GRANT ALL PRIVILEGES ON my_schema.secret_info TO 'admin_user'@'localhost';

-- Dokončení transakce
COMMIT;