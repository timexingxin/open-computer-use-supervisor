import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Sends a structured request to the Session Supervisor Broker over a Unix domain socket.
 *
 * @param {string} socketPath - Absolute path to broker.sock
 * @param {Object} request - Request payload
 * @param {number} [timeoutMs=3000] - Request timeout in milliseconds
 * @returns {Promise<Object>} Response from broker or error object
 */
export function sendBrokerRequest(socketPath, request, timeoutMs = 3000) {
  return new Promise((resolve) => {
    if (!socketPath || !fs.existsSync(path.dirname(socketPath))) {
      return resolve({
        success: false,
        error: 'BROKER_SOCKET_DIRECTORY_NOT_FOUND',
        available: false
      });
    }

    let responseData = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        client.destroy();
        resolve({
          success: false,
          error: 'BROKER_REQUEST_TIMEOUT',
          available: false
        });
      }
    }, timeoutMs);

    const client = net.createConnection({ path: socketPath }, () => {
      try {
        client.write(JSON.stringify(request) + '\n');
      } catch (_) {}
    });

    client.on('data', (chunk) => {
      responseData += chunk.toString('utf8');
      if (responseData.includes('\n')) {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          client.end();
          try {
            const parsed = JSON.parse(responseData.trim());
            resolve(parsed);
          } catch (err) {
            resolve({
              success: false,
              error: `BROKER_MALFORMED_RESPONSE: ${err.message}`,
              available: true
            });
          }
        }
      }
    });

    client.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({
          success: false,
          error: `BROKER_UNAVAILABLE: ${err.code || err.message}`,
          available: false
        });
      }
    });
  });
}

/**
 * Creates and starts a Unix Domain Socket server for the Broker with strict 0600 permissions.
 *
 * @param {string} socketPath - Path where the socket file will be created
 * @param {Function} requestHandler - async (req) => responseObj
 * @returns {Promise<{ server: net.Server, close: Function }>}
 */
export function createBrokerServer(socketPath, requestHandler) {
  return new Promise((resolve, reject) => {
    // If socket file already exists, verify if an active broker is listening or remove stale file
    if (fs.existsSync(socketPath)) {
      try {
        fs.unlinkSync(socketPath);
      } catch (err) {
        return reject(new Error(`Failed to remove existing socket file ${socketPath}: ${err.message}`));
      }
    }

    const server = net.createServer((socket) => {
      let buffer = '';

      socket.on('data', async (chunk) => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split('\n');
        buffer = lines.pop(); // Keep partial line in buffer

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          let response;
          try {
            const request = JSON.parse(trimmed);
            response = await requestHandler(request);
          } catch (err) {
            response = {
              success: false,
              error: `BROKER_PROTOCOL_ERROR: ${err.message}`
            };
          }

          try {
            socket.write(JSON.stringify(response) + '\n');
          } catch (writeErr) {
            // Client closed connection early
          }
        }
      });

      socket.on('error', () => {
        // Handle socket error gracefully
      });
    });

    server.listen(socketPath, () => {
      try {
        // Enforce strict 0600 file permissions: only owning user can connect
        fs.chmodSync(socketPath, 0o600);
      } catch (chmodErr) {
        // Best effort chmod
      }

      resolve({
        server,
        close: () => new Promise((res) => {
          server.close(() => {
            if (fs.existsSync(socketPath)) {
              try {
                fs.unlinkSync(socketPath);
              } catch (_) {}
            }
            res();
          });
        })
      });
    });

    server.on('error', (err) => {
      reject(err);
    });
  });
}
