-- ============================================================================
-- CyberSaguaros Research Portal — seed data
-- ============================================================================
-- Passwords are stored as plain SHA-256 (no salt) — deliberately weak so the
-- sqlmap-dumped `users` table is crackable (the "Password Crack" lesson).
--   dr.prickle / Sunset-Saguaro-2026   (admin)
--   rgreen     / cactus123             (researcher)
--   dvalmont   / Desert-Bloom-77       (researcher; also a Linux user on the box)
-- ============================================================================

INSERT INTO users (username, password_hash, display_name, email, role) VALUES
  ('dr.prickle', 'f7c6f7656143553a7faf08aa883a3ba997038893d2ec709c67cfc1e94d6c8a31',
     'Dr. Patricia Prickle', 'p.prickle@cybersaguaros.local', 'admin'),
  ('rgreen', 'fbf9f17a2a5027ac6c9b6f4fcf1c0a69a4354fa73ccad9340ad0338206bd83c3',
     'Reggie Green', 'r.green@cybersaguaros.local', 'researcher'),
  ('dvalmont', '790d9738afc1701c0df0626259c36d725054cfbe337cb497791a9692f3dffd54',
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
