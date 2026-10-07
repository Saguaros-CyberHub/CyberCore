'use strict';

const express = require('express');
const { createService } = require('../utils/caldera-lane-agents');

function createRouter(service = createService()) {
  const router = express.Router();
  // Caddy supplies the original URI. This endpoint never grants console access.
  router.get('/authorize', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const access = await service.authorize(req.get('X-Forwarded-Uri'));
      if (!access) return res.status(403).end();
      res.set('X-Caldera-Paw', access.paw);
      res.set('X-Caldera-Group', access.group);
      res.status(204).end();
    } catch (_) { res.status(503).end(); }
  });
  return router;
}

module.exports = createRouter();
module.exports.createRouter = createRouter;
