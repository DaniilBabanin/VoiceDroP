export type Signal =
  | { type: 'hello'; fingerprint: string; stunAddr: string }
  | { type: 'peer_hello'; fingerprint: string; stunAddr: string }
  | { type: 'presence'; online: boolean }
  | { type: 'outbox_ping'; count: number }
  | { type: 'outbox_ready' }
  | { type: 'relay_frame'; data: string };

export interface PeerState {
  ws: WebSocket;
  fingerprint: string;
  stunAddr: string;
}

export interface RoomState {
  peers: Map<string, PeerState>;
}
