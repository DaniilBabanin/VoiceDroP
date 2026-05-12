import { Signal, PeerState } from './types';

export interface Env {
  SIGNALING_ROOM: DurableObjectNamespace;
  RELAY_STORE: KVNamespace;
}

const RELAY_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Upgrade',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Relay store: POST /relay/{senderFp}/{recipientFp}
    // Routes through the shared DO room so an already-connected recipient
    // gets an immediate outbox_ping rather than waiting for its next hello.
    const relayMatch = url.pathname.match(/^\/relay\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    if (relayMatch && request.method === 'POST') {
      const senderFp = relayMatch[1];
      const recipientFp = relayMatch[2];
      const body = await request.arrayBuffer();
      if (body.byteLength === 0) {
        return new Response('Empty body', { status: 400, headers: corsHeaders });
      }
      const roomKey = [senderFp, recipientFp].sort().join('');
      const roomId = env.SIGNALING_ROOM.idFromName(roomKey);
      const room = env.SIGNALING_ROOM.get(roomId);
      const doResp = await room.fetch(
        new Request(`https://internal/relay/${recipientFp}`, { method: 'POST', body })
      );
      return new Response(doResp.ok ? 'OK' : 'Error', {
        status: doResp.status,
        headers: corsHeaders,
      });
    }

    // Signaling WebSocket: GET /signal/{roomKey}
    const signalMatch = url.pathname.match(/^\/signal\/([a-f0-9]+)$/);
    if (!signalMatch) {
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    }

    const roomKey = signalMatch[1];
    const roomId = env.SIGNALING_ROOM.idFromName(roomKey);
    const room = env.SIGNALING_ROOM.get(roomId);
    return room.fetch(request);
  },
};

export class SignalingRoom implements DurableObject {
  private peers: Map<string, PeerState> = new Map();

  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Relay frame storage forwarded from the main Worker fetch handler.
    // Stores the frame in KV and immediately notifies the recipient if connected.
    const relayMatch = url.pathname.match(/^\/relay\/([a-f0-9]{64})$/);
    if (relayMatch && request.method === 'POST') {
      const recipientFp = relayMatch[1];
      const body = await request.arrayBuffer();
      const uuid = crypto.randomUUID();
      await this.env.RELAY_STORE.put(`frame:${recipientFp}:${uuid}`, body, {
        expirationTtl: RELAY_TTL_SECONDS,
      });
      const recipient = this.peers.get(recipientFp);
      if (recipient) {
        try {
          const list = await this.env.RELAY_STORE.list({ prefix: `frame:${recipientFp}:` });
          recipient.ws.send(JSON.stringify({ type: 'outbox_ping', count: list.keys.length }));
        } catch {
          // recipient ws already closed
        }
      }
      return new Response('OK', { status: 200 });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    server.accept();

    server.addEventListener('message', async (event) => {
      await this.handleMessage(server, event.data as string);
    });

    server.addEventListener('close', () => {
      this.handleClose(server);
    });

    server.addEventListener('error', () => {
      this.handleClose(server);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleMessage(ws: WebSocket, text: string): Promise<void> {
    let signal: Signal;
    try {
      signal = JSON.parse(text) as Signal;
    } catch {
      return;
    }

    if (signal.type === 'hello') {
      const { fingerprint, stunAddr } = signal;
      this.peers.set(fingerprint, { ws, fingerprint, stunAddr });

      this.broadcastPresence(fingerprint, true);

      for (const [fp, peer] of this.peers) {
        if (fp !== fingerprint && peer.ws !== ws) {
          ws.send(JSON.stringify({ type: 'peer_hello', fingerprint: fp, stunAddr: peer.stunAddr }));
          try {
            peer.ws.send(JSON.stringify({ type: 'peer_hello', fingerprint, stunAddr }));
          } catch {
            // peer socket already closed
          }
        }
      }

      // Notify peer of any queued relay frames
      try {
        const list = await this.env.RELAY_STORE.list({ prefix: `frame:${fingerprint}:` });
        if (list.keys.length > 0) {
          ws.send(JSON.stringify({ type: 'outbox_ping', count: list.keys.length }));
        }
      } catch {
        // KV unavailable — skip
      }
      return;
    }

    if (signal.type === 'outbox_ready') {
      let senderFp: string | undefined;
      for (const [fp, peer] of this.peers) {
        if (peer.ws === ws) { senderFp = fp; break; }
      }
      if (!senderFp) return;

      try {
        const list = await this.env.RELAY_STORE.list({ prefix: `frame:${senderFp}:` });
        for (const key of list.keys) {
          const data = await this.env.RELAY_STORE.get(key.name, 'arrayBuffer');
          if (!data) continue;
          const bytes = new Uint8Array(data);
          let binary = '';
          for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          ws.send(JSON.stringify({ type: 'relay_frame', data: btoa(binary) }));
          await this.env.RELAY_STORE.delete(key.name);
        }
      } catch {
        // KV error — ignore
      }
      return;
    }
  }

  private handleClose(ws: WebSocket): void {
    let closedFp: string | undefined;
    for (const [fp, peer] of this.peers) {
      if (peer.ws === ws) {
        closedFp = fp;
        break;
      }
    }

    if (closedFp) {
      this.peers.delete(closedFp);
      this.broadcastPresence(closedFp, false);
    }
  }

  private broadcastPresence(excludeFp: string, online: boolean): void {
    const msg = JSON.stringify({ type: 'presence', online });
    for (const [fp, peer] of this.peers) {
      if (fp !== excludeFp) {
        try {
          peer.ws.send(msg);
        } catch {
          // ignore closed sockets
        }
      }
    }
  }
}
