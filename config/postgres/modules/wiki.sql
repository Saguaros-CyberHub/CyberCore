INSERT INTO cybercore_module (key, name, active)
VALUES ('wiki', 'The Wiki', TRUE)
ON CONFLICT (key) DO NOTHING;
