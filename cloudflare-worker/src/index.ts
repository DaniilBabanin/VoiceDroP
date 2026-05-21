import { Signal } from './types';

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

    // Relay pull: GET /pull/{roomKey}/{recipientFp}
    const pullMatch = url.pathname.match(/^\/pull\/([a-f0-9]+)\/([a-f0-9]{64})$/);
    if (pullMatch && request.method === 'GET') {
      const [, pullRoomKey, recipientFp] = pullMatch;
      const pullRoomId = env.SIGNALING_ROOM.idFromName(pullRoomKey);
      const pullRoom = env.SIGNALING_ROOM.get(pullRoomId);
      const doResp = await pullRoom.fetch(
        new Request(`https://internal/pull/${recipientFp}`, { method: 'GET' })
      );
      const body = await doResp.text();
      return new Response(body, {
        status: doResp.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
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

// Per-WebSocket attachment. Survives DO hibernation; the runtime persists it
// next to the WebSocket and re-supplies it on wake via deserializeAttachment().
// `primary` = first WS that hello'd with this fingerprint owns the presence /
// outbox_ping role; secondary connections (e.g. path3 send WS) attach but stay
// out of broadcasts.
type WsAttach = { fingerprint: string; stunAddr: string; primary: boolean };

export class SignalingRoom implements DurableObject {
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

      const recipient = this.primaryFor(recipientFp);
      if (recipient) {
        try {
          const pending = await this.state.storage.list({ prefix: `relay:${recipientFp}:` });
          console.log(`relay outbox_ping: fp=${recipientFp.slice(0, 8)} count=${pending.size}`);
          recipient.send(JSON.stringify({ type: 'outbox_ping', count: pending.size }));
        } catch (e) {
          console.log(`relay outbox_ping error: ${e}`);
        }
      } else {
        console.log(`relay stored but recipient fp=${recipientFp.slice(0, 8)} not connected`);
      }
      return new Response('OK', { status: 200 });
    }

    // Relay pull: return and delete all pending frames for this recipient.
    const pullMatch = url.pathname.match(/^\/pull\/([a-f0-9]{64})$/);
    if (pullMatch && request.method === 'GET') {
      const recipientFp = pullMatch[1];
      try {
        const pending = await this.state.storage.list({ prefix: `relay:${recipientFp}:` });
        const frames: string[] = [];
        for (const [key, data] of pending) {
          frames.push(data as string);
          await this.state.storage.delete(key);
        }
        console.log(`pull: delivered ${frames.length} frame(s) for fp=${recipientFp.slice(0, 8)}`);
        return new Response(JSON.stringify({ frames }), { status: 200 });
      } catch (e) {
        console.log(`pull error: ${e}`);
        return new Response('Error', { status: 500 });
      }
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    // Hibernation accept: DO can evict from memory between events; we are billed
    // for duration only while a handler (webSocketMessage / fetch / alarm) runs,
    // not while the WS sits idle.
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text = typeof message === 'string' ? message : new TextDecoder().decode(message);
    let signal: Signal;
    try {
      signal = JSON.parse(text) as Signal;
    } catch {
      return;
    }

    if (signal.type === 'hello') {
      const { fingerprint, stunAddr } = signal;
      const becomePrimary = !this.primaryFor(fingerprint);
      ws.serializeAttachment({ fingerprint, stunAddr, primary: becomePrimary } as WsAttach);

      this.broadcastPresence(fingerprint, true);

      // Exchange peer_hello with every other primary in the room
      for (const peer of this.allPrimaries()) {
        const a = this.attach(peer);
        if (!a || a.fingerprint === fingerprint || peer === ws) continue;
        try {
          ws.send(JSON.stringify({ type: 'peer_hello', fingerprint: a.fingerprint, stunAddr: a.stunAddr }));
        } catch {
          // ignore
        }
        try {
          peer.send(JSON.stringify({ type: 'peer_hello', fingerprint, stunAddr }));
        } catch {
          // peer socket already closed
        }
      }

      // Notify this peer of any queued relay frames
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
      const a = this.attach(ws);
      const senderFp = a?.fingerprint;
      console.log(`outbox_ready: senderFp=${senderFp?.slice(0, 8) ?? 'unknown'}`);
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

  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    this.handleClose(ws);
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    this.handleClose(ws);
  }

  private handleClose(ws: WebSocket): void {
    const a = this.attach(ws);
    if (!a) return;
    // Only the primary closing flips presence offline. Secondary (path3 send WS)
    // closes leave presence intact — matching the pre-hibernation behaviour.
    if (a.primary) {
      this.broadcastPresence(a.fingerprint, false);
    }
  }

  private attach(ws: WebSocket): WsAttach | null {
    try {
      return (ws.deserializeAttachment() as WsAttach) ?? null;
    } catch {
      return null;
    }
  }

  private allPrimaries(): WebSocket[] {
    return this.state.getWebSockets().filter((ws) => this.attach(ws)?.primary === true);
  }

  private primaryFor(fingerprint: string): WebSocket | undefined {
    return this.allPrimaries().find((ws) => this.attach(ws)?.fingerprint === fingerprint);
  }

  private broadcastPresence(excludeFp: string, online: boolean): void {
    const msg = JSON.stringify({ type: 'presence', online });
    for (const ws of this.allPrimaries()) {
      const a = this.attach(ws);
      if (a && a.fingerprint !== excludeFp) {
        try {
          ws.send(msg);
        } catch {
          // ignore closed sockets
        }
      }
    }
  }
}
