export type Signal =
  | { type: 'hello'; fingerprint: string; stunAddr: string }
  | { type: 'peer_hello'; fingerprint: string; stunAddr: string }
  | { type: 'presence'; online: boolean }
  | { type: 'outbox_ping'; count: number }
  | { type: 'outbox_ready' }
  | { type: 'relay_frame'; data: string }
  | { type: 'auth_request'; identityPub: string }
  | { type: 'auth_challenge'; serverPub: string; nonce: string }
  | { type: 'auth_response'; mac: string }
  | { type: 'auth_token'; token: string; expiresAt: number };
