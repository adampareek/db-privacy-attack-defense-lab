CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_salt CHAR(32) NOT NULL,
    password_hash CHAR(64) NOT NULL,
    password_plain TEXT NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('analyst', 'admin')),
    recovery_answer VARCHAR(255) NOT NULL
);

CREATE TABLE sessions (
    token_hash CHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE employee_facts (
    id SERIAL PRIMARY KEY,
    department VARCHAR(64) NOT NULL,
    state CHAR(2) NOT NULL,
    age_band VARCHAR(16) NOT NULL,
    salary INTEGER NOT NULL,
    security_training_complete BOOLEAN NOT NULL
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO users
(email, password_salt, password_hash, password_plain, role, recovery_answer)
VALUES
('analyst@example.test', 'fe7a2798376a2ad0ae59f67a186ae884', 'fcc60a09b395dc6ca5fdd4d8a883226ede472bee85e3b02f21d0abd13a22bf60', 'analyst-demo-password', 'analyst', 'Falcon'),
('admin@example.test', 'd2fb4cd964660277170c7eedf5912a7e', 'ec9220ac5d9a874dc20eba07ab61cc9b8c159c7b8a67e2fe359341118829d464', 'admin-demo-password', 'admin', 'Lion');

INSERT INTO employee_facts
(department, state, age_band, salary, security_training_complete)
VALUES
('Research','NY','30-39',118000,true),
('Research','NY','30-39',124000,true),
('Research','NY','30-39',121000,false),
('Research','NY','40-49',132000,true),
('Research','NY','40-49',128000,true),
('Research','NJ','30-39',115000,true),
('Research','NJ','30-39',117000,true),
('Research','NJ','30-39',119000,true),
('Research','NJ','30-39',116000,false),
('Research','NJ','30-39',123000,true),
('Security','NY','20-29',96000,true),
('Security','NY','20-29',101000,true),
('Security','NY','20-29',99000,true),
('Security','NY','20-29',103000,true),
('Security','NY','20-29',105000,true),
('Security','NY','30-39',127000,true),
('Security','NY','30-39',131000,true),
('Security','NY','30-39',129000,true),
('Security','NY','30-39',135000,true),
('Security','NY','30-39',133000,true),
('Finance','NY','30-39',110000,true),
('Finance','NY','30-39',108000,true),
('Finance','NY','30-39',114000,false),
('Finance','NY','30-39',112000,true),
('Finance','NY','30-39',109000,true),
('Finance','NJ','40-49',125000,true),
('Finance','NJ','40-49',127000,true),
('Finance','NJ','40-49',126000,true),
('Finance','NJ','40-49',129000,true),
('Finance','NJ','40-49',128000,true);
