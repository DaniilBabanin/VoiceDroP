export type Signal =
  | { type: 'hello'; fingerprint: string; stunAddr: string }
  | { type: 'peer_hello'; fingerprint: string; stunAddr: string }
  | { type: 'presence'; online: boolean }
  | { type: 'outbox_ping'; count: number }
  | { type: 'outbox_ready' }
  | { type: 'relay_frame'; data: string };
