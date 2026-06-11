import { Signal } from './types';
import {
  getAuthSecret, getServerKeyPair, serverPublicRaw, verifyProof, mintToken,
  b64encode, b64decode, toHex, verifyToken,
} from './auth';

export interface Env {
  SIGNALING_ROOM: DurableObjectNamespace;
}

// Largest frame the app will ever send (PeerConnection.MAX_FRAME_SIZE).
const MAX_RELAY_BODY = 10 * 1024 * 1024;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // No CORS: every client is the native app over OkHttp (CORS is a
    // browser-only mechanism). Emitting `Access-Control-Allow-Origin: *` only
    // served to make this unauthenticated relay reachable from any web origin,
    // so we drop it entirely rather than scope it. Preflight gets a bare 204
    // with no allow-origin, which blocks browsers by design.
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204 });
    }

    // Relay store: POST /relay/{senderFp}/{recipientFp}
    // Requires a Bearer token bound to senderFp (minted by the same room's DO
    // via the WS DH proof) — writes were previously unauthenticated.
    const relayMatch = url.pathname.match(/^\/relay\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    if (relayMatch && request.method === 'POST') {
      const senderFp = relayMatch[1];
      const recipientFp = relayMatch[2];
      const declaredLen = Number(request.headers.get('Content-Length') ?? '0');
      if (declaredLen > MAX_RELAY_BODY) {
        return new Response('Payload Too Large', { status: 413 });
      }
      const body = await request.arrayBuffer();
      if (body.byteLength === 0) {
        return new Response('Empty body', { status: 400 });
      }
      if (body.byteLength > MAX_RELAY_BODY) {
        return new Response('Payload Too Large', { status: 413 });
      }
      const roomKey = [senderFp, recipientFp].sort().join('');
      const roomId = env.SIGNALING_ROOM.idFromName(roomKey);
      const room = env.SIGNALING_ROOM.get(roomId);
      const doResp = await room.fetch(
        new Request(`https://internal/relay/${senderFp}/${recipientFp}`, {
          method: 'POST',
          body,
          headers: { Authorization: request.headers.get('Authorization') ?? '' },
        })
      );
      return new Response(doResp.ok ? 'OK' : 'Error', {
        status: doResp.status,
      });
    }

    // Relay pull (non-destructive): GET /pull/{roomKey}/{recipientFp}
    const pullMatch = url.pathname.match(/^\/pull\/([a-f0-9]{128})\/([a-f0-9]{64})$/);
    if (pullMatch && request.method === 'GET') {
      const [, pullRoomKey, recipientFp] = pullMatch;
      const pullRoomId = env.SIGNALING_ROOM.idFromName(pullRoomKey);
      const pullRoom = env.SIGNALING_ROOM.get(pullRoomId);
      const doResp = await pullRoom.fetch(
        new Request(`https://internal/pull/${recipientFp}`, {
          method: 'GET',
          headers: { Authorization: request.headers.get('Authorization') ?? '' },
        })
      );
      const body = await doResp.text();
      return new Response(body, {
        status: doResp.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Relay ack: POST /ack/{roomKey}/{recipientFp} with JSON {ids:[...]}.
    // Deletes the named frames after the client confirms it persisted them —
    // pull alone no longer deletes (delete-before-ack lost messages on a
    // connection reset between DO delete and client persist).
    const ackMatch = url.pathname.match(/^\/ack\/([a-f0-9]{128})\/([a-f0-9]{64})$/);
    if (ackMatch && request.method === 'POST') {
      const [, ackRoomKey, recipientFp] = ackMatch;
      const ackRoomId = env.SIGNALING_ROOM.idFromName(ackRoomKey);
      const ackRoom = env.SIGNALING_ROOM.get(ackRoomId);
      return ackRoom.fetch(
        new Request(`https://internal/ack/${recipientFp}`, {
          method: 'POST',
          body: await request.text(),
          headers: { Authorization: request.headers.get('Authorization') ?? '' },
        })
      );
    }

    // Signaling WebSocket: GET /signal/{roomKey}. roomKey is the concat of two
    // sorted 64-hex fingerprints — exactly 128 hex chars; anything else would
    // spawn an unbounded number of junk DOs.
    const signalMatch = url.pathname.match(/^\/signal\/([a-f0-9]{128})$/);
    if (!signalMatch) {
      return new Response('Not Found', { status: 404 });
    }

    const roomKey = signalMatch[1];
    const roomId = env.SIGNALING_ROOM.idFromName(roomKey);
    const room = env.SIGNALING_ROOM.get(roomId);
    return room.fetch(request);
  },
};

// Per-WebSocket attachment. Survives DO hibernation; the runtime persists it
// next to the WebSocket and re-supplies it on wake via deserializeAttachment().
// Auth-first handshake: auth_request/auth_response run with no presence state;
// `authedFp` is set only after the DH proof verifies, and `hello` is accepted
// only for that fingerprint. `primary` = first authed WS that hello'd with this
// fingerprint owns the presence / outbox_ping role; secondary connections
// (e.g. path3 send WS) attach but stay out of broadcasts.
type WsAttach = {
  fingerprint?: string; stunAddr?: string; primary?: boolean;
  authNonce?: string; authIdentityPub?: string; // b64
  authedFp?: string; // hex; set after proof verification
};

// Pending relay frames live at relay:{recipientFp}:{uuid} as {d: base64, t: ms}.
type RelayEntry = { d: string; t: number };

const RELAY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RELAY_SWEEP_INTERVAL_MS = 6 * 60 * 60 * 1000;
const MAX_PENDING_PER_RECIPIENT = 200;
const MAX_SOCKETS_PER_ROOM = 32;

export class SignalingRoom implements DurableObject {
  constructor(private state: DurableObjectState, _env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Relay frame storage: stores frame in DO durable storage (strongly consistent)
    // and immediately notifies the recipient if connected. Write side is gated on a
    // token bound to the SENDER fingerprint (the read side was always gated).
    const relayMatch = url.pathname.match(/^\/relay\/([a-f0-9]{64})\/([a-f0-9]{64})$/);
    if (relayMatch && request.method === 'POST') {
      const senderFp = relayMatch[1];
      const recipientFp = relayMatch[2];
      if (!(await this.bearerTokenValid(request, senderFp))) {
        return new Response('Unauthorized', { status: 401 });
      }
      const body = await request.arrayBuffer();
      if (body.byteLength > MAX_RELAY_BODY) {
        return new Response('Payload Too Large', { status: 413 });
      }
      const pending = await this.state.storage.list({ prefix: `relay:${recipientFp}:` });
      if (pending.size >= MAX_PENDING_PER_RECIPIENT) {
        return new Response('Too Many Pending Frames', { status: 429 });
      }
      const base64 = toBase64(new Uint8Array(body));
      const uuid = crypto.randomUUID();
      const storageKey = `relay:${recipientFp}:${uuid}`;
      const entry: RelayEntry = { d: base64, t: Date.now() };
      await this.state.storage.put(storageKey, entry);
      // Expire undelivered frames instead of storing them (billed) forever.
      if ((await this.state.storage.getAlarm()) === null) {
        await this.state.storage.setAlarm(Date.now() + RELAY_SWEEP_INTERVAL_MS);
      }

      const recipient = this.primaryFor(recipientFp);
      if (recipient) {
        try {
          recipient.send(JSON.stringify({ type: 'outbox_ping', count: pending.size + 1 }));
        } catch (e) {
          console.log(`relay outbox_ping error: ${e}`);
        }
      }
      return new Response('OK', { status: 200 });
    }

    // Relay pull: return (NOT delete) all pending frames for this recipient.
    // `ids` parallels `frames`; the client acks the ids it has persisted and
    // only then are they deleted. Unacked frames re-deliver on the next pull;
    // the ratchet's duplicate handling makes re-delivery a no-op.
    const pullMatch = url.pathname.match(/^\/pull\/([a-f0-9]{64})$/);
    if (pullMatch && request.method === 'GET') {
      const recipientFp = pullMatch[1];
      if (!(await this.bearerTokenValid(request, recipientFp))) {
        return new Response('Unauthorized', { status: 401 });
      }
      try {
        const pending = await this.state.storage.list({ prefix: `relay:${recipientFp}:` });
        const frames: string[] = [];
        const ids: string[] = [];
        for (const [key, data] of pending) {
          frames.push(relayData(data));
          ids.push(key.slice(`relay:${recipientFp}:`.length));
        }
        return new Response(JSON.stringify({ frames, ids }), { status: 200 });
      } catch (e) {
        console.log(`pull error: ${e}`);
        return new Response('Error', { status: 500 });
      }
    }

    // Relay ack: delete the named frames once the client confirms persistence.
    const ackMatch = url.pathname.match(/^\/ack\/([a-f0-9]{64})$/);
    if (ackMatch && request.method === 'POST') {
      const recipientFp = ackMatch[1];
      if (!(await this.bearerTokenValid(request, recipientFp))) {
        return new Response('Unauthorized', { status: 401 });
      }
      let ids: unknown;
      try {
        ids = (JSON.parse(await request.text()) as { ids?: unknown }).ids;
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
      if (!Array.isArray(ids)) {
        return new Response('Bad Request', { status: 400 });
      }
      for (const id of ids) {
        if (typeof id !== 'string' || !/^[0-9a-f-]{1,64}$/.test(id)) continue;
        await this.state.storage.delete(`relay:${recipientFp}:${id}`);
      }
      return new Response('OK', { status: 200 });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }
    // Bound sockets per room: peer_hello/presence fan-out is O(n²) under churn
    // and each socket holds DO resources.
    if (this.state.getWebSockets().length >= MAX_SOCKETS_PER_ROOM) {
      return new Response('Too Many Connections', { status: 429 });
    }

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    // Hibernation accept: DO can evict from memory between events; we are billed
    // for duration only while a handler (webSocketMessage / fetch / alarm) runs,
    // not while the WS sits idle.
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  // Expire relay frames older than RELAY_TTL_MS; re-arm while any remain.
  async alarm(): Promise<void> {
    const now = Date.now();
    const all = await this.state.storage.list({ prefix: 'relay:' });
    let remaining = 0;
    for (const [key, value] of all) {
      const entry = value as Partial<RelayEntry> | string;
      if (typeof entry === 'string') {
        // Legacy pre-TTL format (bare base64 string): stamp it now so it
        // expires one TTL from this sweep instead of living forever.
        await this.state.storage.put(key, { d: entry, t: now } as RelayEntry);
        remaining++;
      } else if ((entry.t ?? 0) + RELAY_TTL_MS <= now) {
        await this.state.storage.delete(key);
      } else {
        remaining++;
      }
    }
    if (remaining > 0) {
      await this.state.storage.setAlarm(now + RELAY_SWEEP_INTERVAL_MS);
    }
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
      const a = this.attach(ws) ?? {};
      // hello is accepted only AFTER the DH proof bound this socket to the
      // fingerprint it claims. Pre-auth hello previously let anyone knowing the
      // (derivable) room key spoof presence, harvest peers' stunAddr (public
      // IP:port), and steal the primary/outbox_ping role for a victim fp.
      if (a.authedFp !== fingerprint) {
        return;
      }
      const becomePrimary = !this.primaryFor(fingerprint);
      ws.serializeAttachment({ ...a, fingerprint, stunAddr, primary: becomePrimary } as WsAttach);

      this.broadcastPresence(fingerprint, true);

      // Exchange peer_hello with every other primary in the room
      for (const peer of this.allPrimaries()) {
        const pa = this.attach(peer);
        if (!pa || pa.fingerprint === fingerprint || peer === ws) continue;
        try {
          ws.send(JSON.stringify({ type: 'peer_hello', fingerprint: pa.fingerprint, stunAddr: pa.stunAddr }));
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
          ws.send(JSON.stringify({ type: 'outbox_ping', count: pending.size }));
        }
      } catch (e) {
        console.log(`hello outbox_ping error: ${e}`);
      }
      return;
    }

    if (signal.type === 'auth_request') {
      // Auth-first: runs with no prior attachment. The fingerprint is DERIVED
      // from the presented identity pub, never taken from a self-claim.
      let identityPubRaw: Uint8Array;
      try {
        identityPubRaw = b64decode(signal.identityPub);
      } catch {
        return;
      }
      if (identityPubRaw.length !== 32) return; // X25519 pub is exactly 32 bytes

      const nonce = new Uint8Array(16); crypto.getRandomValues(nonce);
      const a = this.attach(ws) ?? {};
      // persist nonce + identity pub on the attachment (survives hibernation), keep other fields
      ws.serializeAttachment({ ...a, authNonce: b64encode(nonce), authIdentityPub: signal.identityPub } as WsAttach);

      const kp = await getServerKeyPair(this.state.storage);
      const serverPub = await serverPublicRaw(kp);
      ws.send(JSON.stringify({ type: 'auth_challenge', serverPub: b64encode(serverPub), nonce: b64encode(nonce) }));
      return;
    }

    if (signal.type === 'auth_response') {
      const a = this.attach(ws);
      if (!a || !a.authNonce || !a.authIdentityPub) return;
      const identityPubRaw = b64decode(a.authIdentityPub);
      if (identityPubRaw.length !== 32) return;
      const fpBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', identityPubRaw));
      const nonce = b64decode(a.authNonce);
      const kp = await getServerKeyPair(this.state.storage);
      const ok = await verifyProof(kp.privateKey, identityPubRaw, nonce, fpBytes, signal.mac);
      if (!ok) return;
      ws.serializeAttachment({ ...a, authedFp: toHex(fpBytes) } as WsAttach);
      const secret = await getAuthSecret(this.state.storage);
      const { token, expiresAt } = await mintToken(secret, fpBytes, Date.now());
      ws.send(JSON.stringify({ type: 'auth_token', token, expiresAt }));
      return;
    }
  }

  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    this.handleClose(ws);
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    this.handleClose(ws);
  }

  private async bearerTokenValid(request: Request, fpHex: string): Promise<boolean> {
    const auth = request.headers.get('Authorization') ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token) return false;
    const secret = await getAuthSecret(this.state.storage);
    return verifyToken(secret, token, fpHex, Date.now());
  }

  private handleClose(ws: WebSocket): void {
    const a = this.attach(ws);
    if (!a || !a.fingerprint) return;
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

// Chunked bytes→base64 (a single per-byte string concat loop is O(n) string
// churn on a 10 MB body).
function toBase64(bytes: Uint8Array): string {
  let binary = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// Pending entries are {d, t}; tolerate the legacy bare-string format.
function relayData(value: unknown): string {
  if (typeof value === 'string') return value;
  return (value as RelayEntry).d;
}
