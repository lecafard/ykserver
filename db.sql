CREATE TABLE admin_users (
    uname     VARCHAR(20) UNIQUE PRIMARY KEY,
    tid       CHAR(12)
);

CREATE TABLE admin_logs (
    uname     VARCHAR(20),
    ts        INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE otp_tokens (
    tid       CHAR(12) UNIQUE,
    pid       BLOB(6),
    key       BLOB(16),
    octr      INTEGER,
    ctr       INTEGER
);

CREATE TABLE otp_logs (
    tid       CHAR(12),
    ts        INTEGER DEFAULT (strftime('%s', 'now')),
    ctr       INTEGER
);

CREATE INDEX idx_otp_logs_ts ON otp_logs(ts);
INSERT INTO admin_users (uname) VALUES ("admin");
