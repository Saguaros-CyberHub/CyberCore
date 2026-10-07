-- ============================================================================
-- CyberSaguaros Research Portal — seed data
-- ============================================================================
-- Passwords are stored as plain SHA-256 (no salt) — deliberately weak so the
-- sqlmap-dumped `users` table is crackable. Every password is a word from the
-- rockyou wordlist, so `hashcat -m 1400` / `john` with rockyou.txt cracks them:
--   dr.wagner  / arizona    (admin)
--   rgreen     / cactus     (researcher)
--   dvalmont   / sunshine   (researcher; also the dvalmont Linux user on the box)
-- ============================================================================

INSERT INTO users (username, password_hash, display_name, email, role) VALUES
  ('dr.wagner', '054da1e8bc1cb20b4504d603ca6154d353cedb698909503733343bb3f22161c1',
     'Dr. Paul Wagner', 'p.wagner@cybersaguaros.local', 'admin'),
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

-- ============================================================================
-- Articles
-- ============================================================================
-- author_id 1/2/3 = dr.wagner / rgreen / dvalmont, the same hardcoded-ordinal
-- convention `datasets` above already uses.
--
-- EVERY author has at least one PUBLISHED piece. That is deliberate on two
-- counts: no author.php page is ever empty, and @dr.wagner -- the admin -- is
-- readable by an anonymous visitor. If Wagner only ever appeared on drafts,
-- the credential route would be undiscoverable without first having a login,
-- which is circular.
--
-- co_authors is display-only free text, matching how the group credits work.
--
-- DRAFT CONTENT RULE: hints, never credentials. No password, hash or token
-- appears in a draft body. The provisioning draft explains WHY /api/internal/
-- was left unauthenticated -- a path robots.txt already discloses -- so a
-- researcher login accelerates SSRF recon without shortcutting it. The intake
-- draft grumbles about the Cloud Storage extension filter in the same spirit.
--
-- hrivera is NOT an author and must never become one: she is deliberately
-- absent from `users` so the SQLi cannot shortcut the SSH / lateral-movement
-- stage, and a byline would send students spraying an account that does not
-- exist. Keep her out of this table.
INSERT INTO articles (slug, title, abstract, body, author_id, co_authors, published_on, status) VALUES
  ('cyber-algorithmic-growth-curves',
   'Cyber-Algorithmic Growth Curves for Carnegiea gigantea',
   'A regression pipeline that fits multi-decade saguaro growth from sparse, irregular telemetry.',
   'Carnegiea gigantea grows slowly enough that a single career covers perhaps a fifth of one plant''s life. The literature reflects that: growth models for the species are built from a handful of long-baseline plots, each measured on whatever schedule its funding allowed, and each stopping when its principal investigator retired.\n\nOur study grid inherits the same problem in a different shape. Two hundred and forty instrumented saguaros report height, circumference and areole count on a nominal quarterly cadence, but the real series is ragged. Sensors fail in the summer heat, the monsoon takes out the relay for weeks at a time, and three of the original plots were lost to a 2019 fire.\n\nThe pipeline described here treats that raggedness as the primary modelling problem rather than a preprocessing nuisance. We fit a hierarchical growth model in which each plant carries its own latent trajectory, pooled toward a site-level curve, and the observation schedule is modelled explicitly rather than assumed uniform. Missing quarters are not imputed; they simply contribute no likelihood.\n\nThe practical result is that a plant with eleven good measurements over nineteen years contributes usefully to the site curve instead of being dropped for insufficient data. Across the grid that recovers roughly a third of our historical record.\n\nWe release the fitted curves as an open dataset. The regression code is not yet public, since it depends on an internal telemetry schema we are still normalising, but the model specification is given in full in the appendix. We would rather someone reimplemented it cleanly than inherited our first attempt.',
   1, 'Green, R.', '2025-06-12', 'published'),
  ('saguaronet-spine-density',
   'SaguaroNet: Spine-Density Classification from Field Imagery',
   'A convolutional classifier that estimates spine density, and through it plant age, from ordinary field photographs.',
   'Spine density is one of the few saguaro traits that can be assessed from a photograph taken by a person who is not a botanist. It also correlates usefully with age, which makes it attractive as a proxy in surveys where coring or repeated measurement is impractical.\n\nSaguaroNet is a small convolutional classifier trained on 4,100 field photographs from the CyberSaguaros archive, each labelled by hand into six density bands. The architecture is unremarkable. That is the point: the interesting work was in the labelling protocol and in what the model does when it is wrong.\n\nInter-rater agreement on the six-band scheme was initially poor, at kappa 0.51. Restricting labelling to the mid-rib region of the plant, at a fixed distance band, brought that to 0.79, which is where the published model is trained. Photographs that cannot be cropped to that region are rejected at intake rather than labelled badly.\n\nThe model reaches 84 percent band accuracy on held-out plots and, more usefully, 97 percent within-one-band accuracy. Its errors are almost always neighbouring bands rather than wild misses. That failure mode is acceptable for survey work, where the question is usually whether a stand is young, established or senescent.\n\nWhere it fails badly is frost damage. A plant that has lost surface tissue reads as much older than it is. We flag those cases with a separate detector and exclude them; the frost imagery work described elsewhere in this series grew directly out of that exclusion list.',
   3, NULL, '2025-03-04', 'published'),
  ('frost-stress-signatures',
   'Frost-Stress Signatures in Thermal Saguaro Imagery',
   'Detecting and grading winter frost-stress events across the Sonoran study grid using paired thermal and visible imagery.',
   'The Sonoran Desert freezes more often than its reputation suggests, and saguaros sit close to their cold tolerance at the northern edge of their range. A hard freeze does not usually kill a mature plant outright. It damages tissue that then fails months later, which makes attribution difficult after the fact.\n\nThis paper describes a thermal-imaging protocol for catching the damage while it is still legible. Paired thermal and visible images are captured at dawn on the mornings following any night below -2C at the station, and the two are registered to each other so that thermal anomalies can be localised on the plant.\n\nDamaged tissue holds heat differently from healthy tissue for several weeks after the event. The signature is subtle in absolute terms, typically under a degree, but it is spatially coherent, forming patches on the north and west aspects where radiative loss is highest. Coherence, not magnitude, is what the grading scheme keys on.\n\nWe graded 312 plants across the winter of 2024-2025, which included two significant freeze events in January. Sixty-one plants showed gradeable damage and nine were graded severe. Follow-up in June confirmed visible tissue failure on eight of those nine, which is the closest thing to ground truth this method is likely to get.\n\nThe imagery is released with the paper. It is large, and it is the single most requested dataset we hold, mostly by people building the classifier we deliberately did not build.',
   2, 'Wagner, P.', '2024-11-19', 'published'),
  ('bloom-timing-monsoon-variability',
   'Bloom-Timing Prediction under Monsoon Variability',
   'Forecasting bloom onset from soil-moisture and temperature telemetry, and a frank account of why the 2023 forecast failed.',
   'Saguaro bloom onset has historically been predicted from accumulated growing-degree days, which works acceptably in a stable precipitation regime and poorly in the one we now have. The monsoon has become less reliable in its timing without becoming much less reliable in its total, and bloom timing tracks the timing rather than the total.\n\nThe model presented here adds soil moisture at 30cm depth as a second driver, with a lag term fitted per site. On the 2019-2022 record it reduces mean onset error from 11.4 days to 4.6 days, which is the difference between a forecast that is useful for scheduling field crews and one that is not.\n\nIt then failed badly in 2023, predicting onset nine days early across the entire grid. The failure is instructive and we describe it at length rather than burying it. An unusually warm February drove the degree-day term hard while soil moisture stayed low. The fitted lag term, estimated on years where those two moved together, had no way to represent their divergence.\n\nThe 2024 revision decouples the two terms and constrains the model to a plausible physiological range rather than letting the fit run free. It is less accurate on the training years and more accurate on 2023, which we take as the correct trade.\n\nWe would caution anyone using this model outside the Sonoran grid that the lag terms are site-fitted and almost certainly not transferable. Refit them.',
   1, NULL, '2024-07-30', 'published'),
  ('provisioning-the-dataset-reviewer',
   'Provisioning the Dataset Reviewer',
   'Internal working note: how the nightly dataset reviewer authenticates against the portal, and why it carries no password.',
   'Working note, not for publication. -- PW\n\nThe nightly dataset reviewer runs on the station box and needs an authenticated portal session to mark submissions verified. For most of last year it did that by logging in as me, with my password in a config file, which was obviously not a durable arrangement and which broke every time I rotated it.\n\nThe replacement is a small provisioning endpoint under /api/internal/. The reviewer calls it from the host itself, gets back a session token, and sets that token as its admin_session cookie for the rest of the run. No password is stored anywhere on the box.\n\nThe endpoint itself is unauthenticated, which looked wrong to me until I worked through it. It is bound behind an allow-from-loopback rule in the site config, so nothing outside the host can reach the path at all. The network is the authentication. Adding a second credential to a path only reachable from localhost would mean storing that credential on the box, which is the exact problem we were trying to remove.\n\nOpen question I want to revisit before this becomes permanent. The loopback rule assumes nothing else on this host will make outbound requests on behalf of a caller. That is true today. It will stop being true the moment we give SaguaroBot anything that fetches a URL, and I note we are already discussing exactly that for dataset integrity checks. Flagging it here so it is written down somewhere.\n\n-- PW',
   1, NULL, NULL, 'draft'),
  ('field-imagery-intake-notes',
   'Field Imagery Intake: Notes and Complaints',
   'Internal working note: what the Cloud Storage intake path actually accepts, and why that is rather more than it should.',
   'Notes from cleaning up the imagery archive this month. Mostly complaints. -- RG\n\nWe now have 14 gigabytes of field imagery in the gallery archive and no consistent naming, which is as much my fault as anyone else''s. I have started renaming on intake but there is a long tail of contributed files from before that.\n\nThe part that bothers me more is the intake filter itself. Cloud Storage looks for an image extension somewhere in the filename and then keeps the filename exactly as uploaded. Those two behaviours are fine on their own and not fine together. It never checks what a name actually ends in, only that something like .png or .jpg turns up in it somewhere, and we are storing the result verbatim into a directory the web server serves.\n\nI raised this and was told the directory only holds images so it does not matter what they are called. I do not think that follows. What the directory holds is whatever we put in it, and what we put in it is whatever happened to have the letters .png somewhere in its name.\n\nProposed, in rough order of how much I expect each to be argued with. Generate our own filenames on intake and discard the uploaded one. Validate the actual file contents rather than the name. Stop serving that directory as anything other than static bytes.\n\nNone of this is urgent. It is also not hard, and I would rather do it before we open contributions beyond station staff.\n\n-- RG',
   2, NULL, NULL, 'draft');

-- Ambient SaguaroBot transcripts so /admin/chat.php is not empty on a fresh
-- lane. The second pair is the useful one: it shows an admin, in the app''s
-- own words, that the bot fetches whatever URL it is handed.
INSERT INTO chat_logs (session_id, speaker, message) VALUES
  ('a1c4e2f0d3b59687', 'user', 'do you have the bloom telemetry set for 2025?'),
  ('a1c4e2f0d3b59687', 'bot',  'Bloom telemetry is one of our flagship datasets - see Research for the latest Saguaro Bloom Telemetry set.'),
  ('7b2f08d641ae3c95', 'user', 'checking this one: https://data.cybersaguaros.local/sets/frost-imaging.zip'),
  ('7b2f08d641ae3c95', 'bot',  'Fetching that dataset to verify its integrity...');
