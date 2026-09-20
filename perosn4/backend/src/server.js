const http = require('http');
const express = require('express');
const cors = require('cors');
const config = require('./config');
const { connectDatabase } = require('./db/connection');
const { initSubscriber } = require('./redis/subscriber');
const { initBroadcaster } = require('./websocket/broadcaster');
const alertRoutes = require('./routes/alerts');
const healthRoutes = require('./routes/health');
const statsRoutes  = require('./routes/stats');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  if (config.nodeEnv !== 'test') {
    console.log(`[HTTP] ${req.method} ${req.url}`);
  }
  next();
});

// API Routes
app.use('/api/alerts', alertRoutes);
app.use('/api/health', healthRoutes);
app.use('/api/stats',  statsRoutes);
app.use('/api/v2', require('./routes/v2'));
app.use('/api/simulation', require('./routes/simulation').router);

// Root route welcome
app.get('/', (req, res) => {
  res.json({
    name: 'SIH26145 Unidirectional Threat Detector API',
    role: 'Person 4 Express API & Real-Time Streaming Backend',
    version: '2.0.0',
    documentation: {
      health: '/api/health',
      alerts: '/api/alerts',
      stats: '/api/stats',
      decisions: '/api/v2/decisions',
      incidents: '/api/v2/incidents',
      simulation: '/api/simulation',
      websocket: '/ws'
    }
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ status: 'error', message: 'Endpoint not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Error]:', err);
  res.status(500).json({ status: 'error', message: 'Internal server error' });
});

// Create HTTP server
const server = http.createServer(app);

// Initialize WebSocket Broadcaster
initBroadcaster(server);

// Start server if executed directly
if (require.main === module) {
  async function startServer() {
    try {
      await connectDatabase();
      initSubscriber();

      server.listen(config.port, () => {
        console.log(`=======================================================`);
        console.log(`  Person 4 Backend Server Running on Port ${config.port}`);
        console.log(`  - REST API:     http://localhost:${config.port}/api/alerts`);
        console.log(`  - Health Check: http://localhost:${config.port}/api/health`);
        console.log(`  - WebSocket:    ws://localhost:${config.port}/ws`);
        console.log(`=======================================================`);
      });
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  }

  startServer();
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
    require('./routes/simulation').stopSimulation();
    require('./redis/subscriber').closeSubscriber();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}

module.exports = { app, server };
