-- ============================================================================
-- CyberSaguaros Research Portal — seed data
-- ============================================================================
-- Passwords are stored as plain SHA-256 (no salt) — deliberately weak so the
-- sqlmap-dumped `users` table is crackable. Every password is a word from the
-- rockyou wordlist, so `hashcat -m 1400` / `john` with rockyou.txt cracks them:
--   dr.prickle / arizona    (admin)
--   rgreen     / cactus     (researcher)
--   dvalmont   / sunshine   (researcher; also the dvalmont Linux user on the box)
-- ============================================================================

INSERT INTO users (username, password_hash, display_name, email, role) VALUES
  ('dr.prickle', '054da1e8bc1cb20b4504d603ca6154d353cedb698909503733343bb3f22161c1',
     'Dr. Patricia Prickle', 'p.prickle@cybersaguaros.local', 'admin'),
  ('rgreen', 'caaeac3184e90c7f8587d692f03105bfe111982ab663ed6c6e1d0237eb3420f2',
     'Reggie Green', 'r.green@cybersaguaros.local', 'researcher'),
  ('dvalmont', 'a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223',
     'Desmond Valmont', 'd.valmont@cybersaguaros.local', 'researcher');

INSERT INTO datasets (name, description, owner_id, dataset_url, verified) VALUES
  ('Saguaro Bloom Telemetry 2025',
     'Hourly bloom-stage telemetry from 240 instrumented saguaros across the Sonoran study grid.',
     1, 'https://data.cybersaguaros.local/sets/bloom-2025.csv', 1),
  ('Spine Density Survey',
     'Spine-density model training data for the SaguaroNet classifier.',
     2, 'https://data.cybersaguaros.local/sets/spine-density.csv', 1),
  ('Cyber-Algorithmic Growth Curves',
     'Growth-curve fits produced by the cyber-algorithmic regression pipeline.',
     1, 'https://data.cybersaguaros.local/sets/growth-curves.json', 0),
  ('Frost Stress Imaging',
     'Thermal imagery of saguaro frost stress events, winter 2024-2025.',
     3, 'https://data.cybersaguaros.local/sets/frost-imaging.zip', 0);
