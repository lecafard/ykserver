CREATE TABLE admin_users (
    uname     VARCHAR(20) UNIQUE PRIMARY KEY,
    tid       BLOB(6)
);

CREATE TABLE admin_logs (
    uname     VARCHAR(20),
    ts        INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE otp_tokens (
    tid       BLOB(6) UNIQUE,
    pid       BLOB(6),
    key       BLOB(16)
);

CREATE TABLE otp_logs (
    tid       BLOB(6),
    ts        INTEGER DEFAULT (strftime('%s', 'now')),
    nonce     BLOB(2),
    ctr       INTEGER
);

CREATE INDEX idx_otp_logs_ts ON otp_logs(ts);
INSERT INTO admin_users (uname) VALUES ("admin");
