import { Signal, PeerState } from './types';

export interface Env {
  SIGNALING_ROOM: DurableObjectNamespace;
  RELAY_STORE: KVNamespace; // kept for binding compatibility; relay now uses DO storage
}

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
  // peers: primary WS per fingerprint (for peer_hello broadcasts and outbox_ping)
  private peers: Map<string, PeerState> = new Map();
  // wsToFp: every connected WS → its fingerprint (survives peer overwrites)
  private wsToFp: Map<WebSocket, string> = new Map();

  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Relay frame storage: stores frame in DO durable storage (strongly consistent)
    // and immediately notifies the recipient if connected.
    const relayMatch = url.pathname.match(/^\/relay\/([a-f0-9]{64})$/);
    if (relayMatch && request.method === 'POST') {
      const recipientFp = relayMatch[1];
      const body = await request.arrayBuffer();
      const bytes = new Uint8Array(body);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);
      const uuid = crypto.randomUUID();
      const storageKey = `relay:${recipientFp}:${uuid}`;
      await this.state.storage.put(storageKey, base64);
      console.log(`relay stored: key=${storageKey} bytes=${body.byteLength}`);

      const recipient = this.peers.get(recipientFp);
      if (recipient) {
        try {
          const pending = await this.state.storage.list({ prefix: `relay:${recipientFp}:` });
          console.log(`relay outbox_ping: fp=${recipientFp.slice(0, 8)} count=${pending.size}`);
          recipient.ws.send(JSON.stringify({ type: 'outbox_ping', count: pending.size }));
        } catch (e) {
          console.log(`relay outbox_ping error: ${e}`);
        }
      } else {
        console.log(`relay stored but recipient fp=${recipientFp.slice(0, 8)} not connected`);
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

      // Track every WS connection, keyed by WS object (survives fingerprint overwrites)
      this.wsToFp.set(ws, fingerprint);

      // Only update peers if no primary exists for this fingerprint yet
      // (keeps the first/presence connection as primary; path3 send WS is secondary)
      if (!this.peers.has(fingerprint)) {
        this.peers.set(fingerprint, { ws, fingerprint, stunAddr });
      } else if (this.peers.get(fingerprint)!.ws === ws) {
        // Same WS reconnecting (e.g. stunAddr changed) — update
        this.peers.get(fingerprint)!.stunAddr = stunAddr;
      }
      // else: secondary connection from same device — don't overwrite primary

      this.broadcastPresence(fingerprint, true);

      // Send peer_hello to this WS for all OTHER peers currently in the room
      for (const [fp, peer] of this.peers) {
        if (fp !== fingerprint && peer.ws !== ws) {
          ws.send(JSON.stringify({ type: 'peer_hello', fingerprint: fp, stunAddr: peer.stunAddr }));
          // Also notify that peer about this new connection
          try {
            peer.ws.send(JSON.stringify({ type: 'peer_hello', fingerprint, stunAddr }));
          } catch {
            // peer socket already closed
          }
        }
      }

      // Notify this peer of any queued relay frames (uses DO storage — strongly consistent)
      try {
        const pending = await this.state.storage.list({ prefix: `relay:${fingerprint}:` });
        if (pending.size > 0) {
          console.log(`hello outbox_ping: fp=${fingerprint.slice(0, 8)} count=${pending.size}`);
          ws.send(JSON.stringify({ type: 'outbox_ping', count: pending.size }));
        }
      } catch (e) {
        console.log(`hello outbox_ping error: ${e}`);
      }
      return;
    }

    if (signal.type === 'outbox_ready') {
      // Look up fingerprint by WebSocket identity (handles secondary/path3 connections)
      const senderFp = this.wsToFp.get(ws);
      console.log(`outbox_ready: senderFp=${senderFp?.slice(0, 8) ?? 'unknown'} peers=[${[...this.peers.keys()].map(k => k.slice(0, 8)).join(',')}] wsToFp size=${this.wsToFp.size}`);
      if (!senderFp) return;

      try {
        const pending = await this.state.storage.list({ prefix: `relay:${senderFp}:` });
        console.log(`outbox_ready: found ${pending.size} frame(s) for fp=${senderFp.slice(0, 8)}`);
        for (const [key, data] of pending) {
          ws.send(JSON.stringify({ type: 'relay_frame', data: data as string }));
          await this.state.storage.delete(key);
          console.log(`relay_frame sent and deleted: key=${key}`);
        }
      } catch (e) {
        console.log(`outbox_ready error: ${e}`);
      }
      return;
    }
  }

  private handleClose(ws: WebSocket): void {
    const closedFp = this.wsToFp.get(ws);
    this.wsToFp.delete(ws);

    if (closedFp) {
      const primary = this.peers.get(closedFp);
      if (primary && primary.ws === ws) {
        // Primary connection closed — remove from peers
        this.peers.delete(closedFp);
        this.broadcastPresence(closedFp, false);
      }
      // If secondary (path3) WS closed, peers entry unchanged — presence stays alive
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
