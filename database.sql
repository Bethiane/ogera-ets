-- Create database
CREATE DATABASE IF NOT EXISTS expense_tracker;
USE expense_tracker;
SHOW TABLES;

-- Users table (for authentication)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
);

-- Expenses table
CREATE TABLE IF NOT EXISTS expenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    amount DECIMAL(10, 2) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description VARCHAR(100),
    date DATE NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CREATE TABLE budgets (
--     id INT AUTO_INCREMENT PRIMARY KEY,
--     user_id INT NOT NULL,
--     category_id INT,
--     amount DECIMAL(10,2) NOT NULL,
--     period ENUM('weekly', 'monthly', 'yearly') NOT NULL,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     FOREIGN KEY (user_id) REFERENCES users(id),
--     FOREIGN KEY (category_id) REFERENCES categories(id)
-- );

INSERT INTO users (username, email, password, is_admin)
VALUES ('admin', 'admin@example.com', '123456', TRUE);

INSERT INTO categories (name) VALUES 
('Food'), ('Transport'), ('Entertainment'), 
('Utilities'), ('Other');

SELECT id, password, is_admin FROM users WHERE username = 'admin';
SELECT * FROM users;
SELECT * FROM expenses;

ALTER TABLE users 
MODIFY COLUMN password VARCHAR(255) NOT NULL;

ALTER TABLE expenses ADD COLUMN category_id INT;

ALTER TABLE expenses 
ADD CONSTRAINT fk_category
FOREIGN KEY (category_id) REFERENCES categories(id);

INSERT IGNORE INTO categories (name) VALUES 
('Food'), ('Transport'), ('Entertainment'), ('Utilities'), ('Other');

SELECT * FROM categories;
DELETE FROM users where id =4;

DESC expenses;

-- COMMENTS ---
-- ALTER TABLE expenses DROP COLUMN category;
-- ALTER TABLE budgets DROP COLUMN category_id;
-- ALTER TABLE budgets DROP COLUMN period;
-- First remove the foreign key constraint
-- ALTER TABLE budgets DROP FOREIGN KEY budgets_ibfk_2;
-- Then drop the column
-- ALTER TABLE budgets DROP COLUMN category_id;
-- ALTER TABLE budgets DROP COLUMN period;
-- DROP TABLE budgets;

CREATE TABLE user_budgets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);



