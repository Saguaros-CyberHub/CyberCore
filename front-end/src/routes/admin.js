/*
 * ============================================================================
 * Admin Routes Aggregator
 * Mounts all admin sub-routers without a path prefix so every URL path is
 * identical to the original monolithic admin.js — no API contract changes.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();

router.use(require('./admin/guac'));
router.use(require('./admin/cluster'));
router.use(require('./admin/lanes'));
router.use(require('./admin/groups'));
router.use(require('./admin/lab-networks'));
router.use(require('./admin/settings'));

module.exports = router;
