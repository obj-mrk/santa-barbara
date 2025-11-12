CREATE TABLE users
(
    id            UUID PRIMARY KEY,
    email         VARCHAR(100) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password      VARCHAR(255)        NOT NULL,
    name          VARCHAR(100),
    role          VARCHAR(20) DEFAULT 'USER',
    created_at    TIMESTAMP   DEFAULT NOW()
);