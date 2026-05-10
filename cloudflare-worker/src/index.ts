import { Signal, PeerState } from './types';

export interface Env {
  SIGNALING_ROOM: DurableObjectNamespace;
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

    const match = url.pathname.match(/^\/signal\/([a-f0-9]+)$/);
    if (!match) {
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    }

    const roomKey = match[1];
    const roomId = env.SIGNALING_ROOM.idFromName(roomKey);
    const room = env.SIGNALING_ROOM.get(roomId);
    return room.fetch(request);
  },
};

export class SignalingRoom implements DurableObject {
  private peers: Map<string, PeerState> = new Map();

  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    this.state.acceptWebSocket(server);

    server.addEventListener('message', (event) => {
      this.handleMessage(server, event.data as string);
    });

    server.addEventListener('close', () => {
      this.handleClose(server);
    });

    server.addEventListener('error', () => {
      this.handleClose(server);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  private handleMessage(ws: WebSocket, text: string): void {
    let signal: Signal;
    try {
      signal = JSON.parse(text) as Signal;
    } catch {
      return;
    }

    if (signal.type !== 'hello') return;

    const { fingerprint, stunAddr } = signal;
    const peerState: PeerState = { ws, fingerprint, stunAddr };
    this.peers.set(fingerprint, peerState);

    this.broadcastPresence(fingerprint, true);

    for (const [fp, peer] of this.peers) {
      if (fp !== fingerprint && peer.ws !== ws) {
        const peerHelloToNew: Signal = {
          type: 'peer_hello',
          fingerprint: fp,
          stunAddr: peer.stunAddr,
        };
        ws.send(JSON.stringify(peerHelloToNew));

        const peerHelloToExisting: Signal = {
          type: 'peer_hello',
          fingerprint,
          stunAddr,
        };
        peer.ws.send(JSON.stringify(peerHelloToExisting));
      }
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
    const presence: Signal = { type: 'presence', online };
    const msg = JSON.stringify(presence);
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
