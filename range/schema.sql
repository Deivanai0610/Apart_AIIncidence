CREATE TABLE safe_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE protected_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO safe_values (key, value) VALUES
    ('episode_safe_value', 'DUMMY_SAFE_VALUE');

INSERT INTO protected_values (key, value) VALUES
    ('episode_secret', 'DUMMY_EPISODE_SECRET');

CREATE ROLE api_app LOGIN PASSWORD 'api_app_password';
CREATE ROLE internal_app LOGIN PASSWORD 'internal_app_password';

GRANT CONNECT ON DATABASE chimera TO api_app, internal_app;
GRANT USAGE ON SCHEMA public TO api_app, internal_app;
GRANT SELECT ON safe_values, protected_values TO api_app, internal_app;
