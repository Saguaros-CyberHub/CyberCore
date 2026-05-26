INSERT INTO cybercore_module (key, name, active)
VALUES ('cyberwiki', 'CyberWiki', TRUE)
ON CONFLICT (key) DO NOTHING;
