const express = require('express');
const router = express.Router();
const Redis = require('ioredis');
const config = require('../config');

// Lazy Redis client for reading pipeline.stats key (separate from subscriber)
let _redis = null;
function getRedis() {
  if (!_redis) {
    _redis = new Redis(config.redisUrl, {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      lazyConnect: true,
      connectTimeout: 1000,
      commandTimeout: 1500,
    });
    _redis.connect().catch(() => {});
    _redis.on('error', () => {});
  }
  return _redis;
}

/**
 * @route   GET /api/stats
 * @desc    Live pipeline throughput and health metrics published by the
 *          Agent 2 worker into Redis key pipeline.stats.
 *          Returns the last-known stats snapshot, or sensible defaults when
 *          the ML engine hasn't published yet (e.g. during startup).
 */
router.get('/', async (req, res) => {
  try {
    const r = getRedis();
    let stats = null;

    try {
      const raw = await r.get('pipeline.stats');
      if (raw) {
        stats = JSON.parse(raw);
      }
    } catch (_) {
      // Redis unavailable or key missing — return defaults rather than failing
    }

    if (!stats) {
      stats = {
        flows_per_sec: 0,
        alerts_per_min: 0,
        processed_total: 0,
        alerts_total: 0,
        errors_total: 0,
        uptime_s: 0,
        tracked_src_ips: 0,
        tracked_dst_ips: 0,
        throughput_window_s: 10,
        source: 'waiting_for_agent2',
      };
    } else {
      stats.source = stats.source || (Object.hasOwn(stats, 'model_profile') ? 'agent2_detection_product' : 'live_ensemble');
      if (stats.source === 'agent2_detection_product') stats.throughput_window_s = null;
    }

    res.json({ status: 'success', data: stats });
  } catch (err) {
    console.error('[API] Error in GET /api/stats:', err.message);
    res.status(500).json({ status: 'error', message: 'Failed to fetch pipeline stats' });
  }
});

module.exports = router;
