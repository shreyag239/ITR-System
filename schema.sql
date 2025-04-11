DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS itr_records;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS admin_notifications;
DROP TABLE IF EXISTS referrals;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    address TEXT,
    pan_number TEXT UNIQUE,
    referral_code TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE itr_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    itr_type TEXT NOT NULL,
    year TEXT NOT NULL,
    status TEXT NOT NULL,
    filing_date TIMESTAMP,
    document_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id)
);

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id)
);

CREATE TABLE admin_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    type TEXT NOT NULL,
    related_id INTEGER,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    referred_name TEXT NOT NULL,
    referred_email TEXT NOT NULL,
    referred_phone TEXT,
    referred_client_id INTEGER,
    is_reviewed BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id),
    FOREIGN KEY (referred_client_id) REFERENCES clients (id)
);

-- Insert admin user with plain text password
INSERT INTO users (username, password, is_admin) 
VALUES ('admin', 'admin123', 1);

-- Insert sample client user with plain text password
INSERT INTO users (username, password, is_admin) 
VALUES ('client1', 'client123', 0);

-- Insert sample client data with referral code
INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code) 
VALUES (2, 'John Doe', 'john@example.com', '9876543210', '123 Main St, City', 'ABCDE1234F', 'abc12345');

-- Insert sample ITR records
INSERT INTO itr_records (client_id, itr_type, year, status, filing_date) 
VALUES (1, 'ITR-1', '2022-2023', 'Completed', '2023-07-15');
INSERT INTO itr_records (client_id, itr_type, year, status) 
VALUES (1, 'ITR-1', '2023-2024', 'Pending');

-- Insert sample notifications
INSERT INTO notifications (client_id, message) 
VALUES (1, 'Your ITR for 2022-2023 has been successfully filed.');
INSERT INTO notifications (client_id, message) 
VALUES (1, 'Please submit your Form 16 for the financial year 2023-2024.');

-- Insert sample referrals
INSERT INTO referrals (client_id, referred_name, referred_email, referred_phone, is_reviewed) 
VALUES (1, 'Jane Smith', 'jane@example.com', '8765432109', 0);

-- Insert sample admin notifications
INSERT INTO admin_notifications (message, type, related_id) 
VALUES ('John Doe has referred Jane Smith (jane@example.com)', 'referral', 1);
