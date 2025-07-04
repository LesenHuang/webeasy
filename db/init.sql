-- envsubst < class.sql > init.sql
\c postgres;

CREATE USER webeasy WITH ENCRYPTED PASSWORD 'root';

CREATE DATABASE webeasy;

ALTER DATABASE webeasy OWNER TO webeasy;

-- GRANT ALL PRIVILEGES ON DATABASE webeasy TO webeasy;

\c webeasy;

SET ROLE webeasy;

CREATE SCHEMA users AUTHORIZATION webeasy;

CREATE TABLE users.roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE users.base (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    -- role_id INT REFERENCES users.roles(id),
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

-- ALTER TABLE users OWNER TO webeasy;

-- GRANT ALL PRIVILEGES ON TABLE webeasy.users TO webeasy;

CREATE TABLE users.jwt (
    id SERIAL PRIMARY KEY,               -- 自增主键
    user_id INT REFERENCES users.base(id) ON DELETE CASCADE,  -- 关联用户（如果需要）
    token TEXT UNIQUE NOT NULL,          -- Token 字符串（唯一）
    token_type VARCHAR(50) DEFAULT 'access_token',     -- Token 类型（如 access_token, refresh_token）
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 创建时间
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL       -- 过期时间
    -- is_revoked BOOLEAN DEFAULT FALSE     -- 是否被撤销
);

-- 为 token 查询加快速度
CREATE INDEX idx_token_lookup ON users.jwt(token);
CREATE INDEX idx_expires_at ON users.jwt(expires_at);

