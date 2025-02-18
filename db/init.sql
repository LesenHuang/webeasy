\c postgres;

CREATE USER root WITH ENCRYPTED PASSWORD 'root';

CREATE DATABASE project;

ALTER DATABASE project OWNER TO root;

-- GRANT ALL PRIVILEGES ON DATABASE project TO root;

\c project;

SET ROLE root;

CREATE SCHEMA users AUTHORIZATION root;

CREATE TABLE users.roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE users.base (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role_id INT REFERENCES users.roles(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CREATE TABLE jwt_tokens (
--     token_id SERIAL PRIMARY KEY,
--     user_id INT REFERENCES users.base(id),
--     jwt_token TEXT NOT NULL,  -- 存储 JWT 令牌
--     expires_in INT,  -- JWT 的有效期（单位：秒）
--     obtained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- JWT 令牌获取时间
--     expires_at TIMESTAMP,  -- JWT 令牌的过期时间
--     is_revoked BOOLEAN DEFAULT FALSE,  -- 是否已失效
--     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- ALTER TABLE users OWNER TO root;

-- GRANT ALL PRIVILEGES ON TABLE project.users TO root;
