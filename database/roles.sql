DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') THEN
        CREATE ROLE app_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') THEN
        CREATE ROLE app_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin') THEN
        CREATE ROLE app_admin NOLOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE securitylab TO app_reader, app_writer, app_admin;
GRANT USAGE ON SCHEMA public TO app_reader, app_writer, app_admin;

GRANT SELECT ON employee_facts TO app_reader;

GRANT SELECT ON employee_facts, users TO app_writer;
GRANT INSERT, SELECT, DELETE ON sessions TO app_writer;
GRANT INSERT ON audit_log TO app_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_writer;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_admin;
