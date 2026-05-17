INSERT INTO cybercore_module (key, name, active)
VALUES ('archive', 'The Archive', TRUE)
ON CONFLICT (key) DO NOTHING;
