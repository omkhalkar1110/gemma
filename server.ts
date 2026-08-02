import http from 'http';
import path from 'path';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';
import express from 'express';
import { createExpressApp } from './src/expressApp';

async function startServer() {
  let broadcastWSFn: ((msg: any) => void) | undefined;

  const app = createExpressApp((msg) => {
    if (broadcastWSFn) broadcastWSFn(msg);
  });

  const server = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });

  const activeSockets = new Set<WebSocket>();

  wss.on('connection', (ws) => {
    activeSockets.add(ws);
    ws.on('close', () => activeSockets.delete(ws));
  });

  broadcastWSFn = (message: { type: string; payload: any }) => {
    const data = JSON.stringify(message);
    for (const ws of activeSockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    }
  };

  // Handle WS upgrade for /ws/live-feed safely
  server.on('upgrade', (request, socket, head) => {
    try {
      const { pathname } = new URL(request.url || '', `http://${request.headers.host}`);
      if (pathname.startsWith('/ws/live-feed')) {
        wss.handleUpgrade(request, socket, head, (ws) => {
          wss.emit('connection', ws, request);
        });
      }
    } catch (_) {
      // Ignore non-WS or malformed upgrades
    }
  });

  // Vite middleware for dev / static for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Aegis Gateway] Proxy Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[Aegis Gateway] Fatal server error:', err);
});
