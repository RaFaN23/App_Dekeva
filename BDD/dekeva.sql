CREATE TABLE scans (
id SERIAL PRIMARY KEY,
url TEXT,
status_code INT,
server TEXT,
created_at TIMESTAMP DEFAULT NOW()
);
SELECT * FROM scans;
SELECT * FROM scans ORDER BY id DESC;