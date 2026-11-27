import protobuf from "protobufjs";

export const ClientWireOp = {
  Unspecified: 0,
  Login: 1,
  Register: 2,
  SsoLogin: 3,
  RecoverPassword: 4,
  GetState: 5,
  SearchDirectory: 6,
  SendChatMessage: 7,
  FetchChatHistory: 8,
  MarkChatRead: 9,
  CloudSyncNewDevice: 10,
  CheckUsername: 11,
  EditChatMessage: 12,
  DeleteChatMessage: 13,
} as const;

export type ClientWireOpCode = (typeof ClientWireOp)[keyof typeof ClientWireOp];

export interface ClientWireRequest {
  op: ClientWireOpCode;
  caller_username?: string;
  peer_username?: string;
  email?: string;
  display_name?: string;
  password?: string;
  recovery_key?: string;
  domain?: string;
  search_query?: string;
  plaintext_message?: string;
  target_message_id_short?: string;
  reply_to_message_id_short?: string;
  reply_to_sender?: string;
  reply_to_text?: string;
}

export interface ClientDirectoryPeer {
  username: string;
  display_name: string;
  key_version: number;
  transparency_seq: number;
  ed25519_pub_hex_short: string;
  x25519_pub_hex_short: string;
  device_number: number;
  vault_version: number;
  is_online: boolean;
  last_seen_ms: number;
}

export interface ClientDecryptedMessageItem {
  sender_username: string;
  ratchet_step: number;
  message_id_short: string;
  timestamp_ms: number;
  is_read_by_peer: boolean;
  decrypted_text: string;
  wire_bytes_len: number;
  nonce_hex: string;
  ciphertext_hex: string;
  signature_hex_short: string;
  reply_to_message_id_short: string;
  reply_to_sender: string;
  reply_to_text: string;
  is_edited: boolean;
}

export interface ClientWireResponse {
  ok: boolean;
  error_message: string;
  username: string;
  display_name: string;
  recovery_key: string;
  channel_id_hex: string;
  wire_bytes_len: number;
  ratchet_step: number;
  device_number: number;
  vault_version: number;
  storage_l1_hits: number;
  storage_l2_reads: number;
  storage_disk_commits: number;
  storage_records_written: number;
  absorbed_sidecar_failures: number;
  peers: ClientDirectoryPeer[];
  messages: ClientDecryptedMessageItem[];
}

export interface ClientWireWsEvent {
  event_type: string;
  sender: string;
  recipient: string;
  wire_bytes_len: number;
  timestamp_ms: number;
}

// Инициализируем схему Protobuf v3 (совпадает 1-в-1 по тегам 1..17 с `crates/cryptox-proto/src/lib.rs`)
const root = new protobuf.Root();

const ClientWireRequestProtoType = new protobuf.Type("ClientWireRequestProto")
  .add(new protobuf.Field("op", 1, "int32"))
  .add(new protobuf.Field("caller_username", 2, "string"))
  .add(new protobuf.Field("peer_username", 3, "string"))
  .add(new protobuf.Field("email", 4, "string"))
  .add(new protobuf.Field("display_name", 5, "string"))
  .add(new protobuf.Field("password", 6, "string"))
  .add(new protobuf.Field("recovery_key", 7, "string"))
  .add(new protobuf.Field("domain", 8, "string"))
  .add(new protobuf.Field("search_query", 9, "string"))
  .add(new protobuf.Field("plaintext_message", 10, "string"))
  .add(new protobuf.Field("target_message_id_short", 11, "string"))
  .add(new protobuf.Field("reply_to_message_id_short", 12, "string"))
  .add(new protobuf.Field("reply_to_sender", 13, "string"))
  .add(new protobuf.Field("reply_to_text", 14, "string"));

const ClientDirectoryPeerProtoType = new protobuf.Type("ClientDirectoryPeerProto")
  .add(new protobuf.Field("username", 1, "string"))
  .add(new protobuf.Field("display_name", 2, "string"))
  .add(new protobuf.Field("key_version", 3, "uint64"))
  .add(new protobuf.Field("transparency_seq", 4, "uint64"))
  .add(new protobuf.Field("ed25519_pub_hex_short", 5, "string"))
  .add(new protobuf.Field("x25519_pub_hex_short", 6, "string"))
  .add(new protobuf.Field("device_number", 7, "uint32"))
  .add(new protobuf.Field("vault_version", 8, "uint64"))
  .add(new protobuf.Field("is_online", 9, "bool"))
  .add(new protobuf.Field("last_seen_ms", 10, "uint64"));

const ClientDecryptedMessageItemProtoType = new protobuf.Type("ClientDecryptedMessageItemProto")
  .add(new protobuf.Field("sender_username", 1, "string"))
  .add(new protobuf.Field("ratchet_step", 2, "uint64"))
  .add(new protobuf.Field("message_id_short", 3, "string"))
  .add(new protobuf.Field("timestamp_ms", 4, "uint64"))
  .add(new protobuf.Field("is_read_by_peer", 5, "bool"))
  .add(new protobuf.Field("decrypted_text", 6, "string"))
  .add(new protobuf.Field("wire_bytes_len", 7, "uint32"))
  .add(new protobuf.Field("nonce_hex", 8, "string"))
  .add(new protobuf.Field("ciphertext_hex", 9, "string"))
  .add(new protobuf.Field("signature_hex_short", 10, "string"))
  .add(new protobuf.Field("reply_to_message_id_short", 11, "string"))
  .add(new protobuf.Field("reply_to_sender", 12, "string"))
  .add(new protobuf.Field("reply_to_text", 13, "string"))
  .add(new protobuf.Field("is_edited", 14, "bool"));

const ClientWireResponseProtoType = new protobuf.Type("ClientWireResponseProto")
  .add(new protobuf.Field("ok", 1, "bool"))
  .add(new protobuf.Field("error_message", 2, "string"))
  .add(new protobuf.Field("username", 3, "string"))
  .add(new protobuf.Field("display_name", 4, "string"))
  .add(new protobuf.Field("recovery_key", 5, "string"))
  .add(new protobuf.Field("channel_id_hex", 6, "string"))
  .add(new protobuf.Field("wire_bytes_len", 7, "uint32"))
  .add(new protobuf.Field("ratchet_step", 8, "uint64"))
  .add(new protobuf.Field("device_number", 9, "uint32"))
  .add(new protobuf.Field("vault_version", 10, "uint64"))
  .add(new protobuf.Field("storage_l1_hits", 11, "uint64"))
  .add(new protobuf.Field("storage_l2_reads", 12, "uint64"))
  .add(new protobuf.Field("storage_disk_commits", 13, "uint64"))
  .add(new protobuf.Field("storage_records_written", 14, "uint64"))
  .add(new protobuf.Field("absorbed_sidecar_failures", 15, "uint64"))
  .add(new protobuf.Field("peers", 16, "ClientDirectoryPeerProto", "repeated"))
  .add(new protobuf.Field("messages", 17, "ClientDecryptedMessageItemProto", "repeated"));

const ClientWireWsEventProtoType = new protobuf.Type("ClientWireWsEventProto")
  .add(new protobuf.Field("event_type", 1, "string"))
  .add(new protobuf.Field("sender", 2, "string"))
  .add(new protobuf.Field("recipient", 3, "string"))
  .add(new protobuf.Field("wire_bytes_len", 4, "uint32"))
  .add(new protobuf.Field("timestamp_ms", 5, "uint64"));

root.add(ClientWireRequestProtoType);
root.add(ClientDirectoryPeerProtoType);
root.add(ClientDecryptedMessageItemProtoType);
root.add(ClientWireResponseProtoType);
root.add(ClientWireWsEventProtoType);

function toNum(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") return Number(v) || 0;
  if (v && typeof (v as { toNumber?: () => number }).toNumber === "function") {
    return (v as { toNumber: () => number }).toNumber();
  }
  return 0;
}

export function encodeClientWireRequest(req: ClientWireRequest): Uint8Array {
  const msg = ClientWireRequestProtoType.create({
    op: req.op,
    caller_username: req.caller_username ?? "",
    peer_username: req.peer_username ?? "",
    email: req.email ?? "",
    display_name: req.display_name ?? "",
    password: req.password ?? "",
    recovery_key: req.recovery_key ?? "",
    domain: req.domain ?? "",
    search_query: req.search_query ?? "",
    plaintext_message: req.plaintext_message ?? "",
    target_message_id_short: req.target_message_id_short ?? "",
    reply_to_message_id_short: req.reply_to_message_id_short ?? "",
    reply_to_sender: req.reply_to_sender ?? "",
    reply_to_text: req.reply_to_text ?? "",
  });
  return ClientWireRequestProtoType.encode(msg).finish();
}

export function decodeClientWireResponse(bytes: Uint8Array): ClientWireResponse {
  const decoded = ClientWireResponseProtoType.decode(bytes);
  const raw = ClientWireResponseProtoType.toObject(decoded, {
    defaults: true,
    arrays: true,
    longs: Number,
  }) as Record<string, unknown>;

  const rawPeers = Array.isArray(raw.peers) ? raw.peers : [];
  const rawMsgs = Array.isArray(raw.messages) ? raw.messages : [];

  return {
    ok: Boolean(raw.ok),
    error_message: String(raw.error_message ?? ""),
    username: String(raw.username ?? ""),
    display_name: String(raw.display_name ?? ""),
    recovery_key: String(raw.recovery_key ?? ""),
    channel_id_hex: String(raw.channel_id_hex ?? ""),
    wire_bytes_len: toNum(raw.wire_bytes_len),
    ratchet_step: toNum(raw.ratchet_step),
    device_number: toNum(raw.device_number),
    vault_version: toNum(raw.vault_version),
    storage_l1_hits: toNum(raw.storage_l1_hits),
    storage_l2_reads: toNum(raw.storage_l2_reads),
    storage_disk_commits: toNum(raw.storage_disk_commits),
    storage_records_written: toNum(raw.storage_records_written),
    absorbed_sidecar_failures: toNum(raw.absorbed_sidecar_failures),
    peers: rawPeers.map((p: Record<string, unknown>) => ({
      username: String(p.username ?? ""),
      display_name: String(p.display_name ?? ""),
      key_version: toNum(p.key_version),
      transparency_seq: toNum(p.transparency_seq),
      ed25519_pub_hex_short: String(p.ed25519_pub_hex_short ?? ""),
      x25519_pub_hex_short: String(p.x25519_pub_hex_short ?? ""),
      device_number: toNum(p.device_number),
      vault_version: toNum(p.vault_version),
      is_online: Boolean(p.is_online),
      last_seen_ms: toNum(p.last_seen_ms),
    })),
    messages: rawMsgs.map((m: Record<string, unknown>) => ({
      sender_username: String(m.sender_username ?? ""),
      ratchet_step: toNum(m.ratchet_step),
      message_id_short: String(m.message_id_short ?? ""),
      timestamp_ms: toNum(m.timestamp_ms),
      is_read_by_peer: Boolean(m.is_read_by_peer),
      decrypted_text: String(m.decrypted_text ?? ""),
      wire_bytes_len: toNum(m.wire_bytes_len),
      nonce_hex: String(m.nonce_hex ?? ""),
      ciphertext_hex: String(m.ciphertext_hex ?? ""),
      signature_hex_short: String(m.signature_hex_short ?? ""),
      reply_to_message_id_short: String(m.reply_to_message_id_short ?? ""),
      reply_to_sender: String(m.reply_to_sender ?? ""),
      reply_to_text: String(m.reply_to_text ?? ""),
      is_edited: Boolean(m.is_edited),
    })),
  };
}

export async function callClientWireProtobuf(req: ClientWireRequest): Promise<ClientWireResponse> {
  const wirePayload = encodeClientWireRequest(req);
  const res = await fetch("/rpc/v1/client-wire", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-protobuf",
      Accept: "application/x-protobuf",
    },
    body: wirePayload,
  });
  const arrayBuf = await res.arrayBuffer();
  return decodeClientWireResponse(new Uint8Array(arrayBuf));
}

export function encodeWsProtoEvent(ev: ClientWireWsEvent): Uint8Array {
  const msg = ClientWireWsEventProtoType.create({
    event_type: ev.event_type,
    sender: ev.sender,
    recipient: ev.recipient,
    wire_bytes_len: ev.wire_bytes_len,
    timestamp_ms: ev.timestamp_ms,
  });
  return ClientWireWsEventProtoType.encode(msg).finish();
}

export function decodeWsProtoEvent(buf: ArrayBuffer): ClientWireWsEvent | null {
  try {
    const decoded = ClientWireWsEventProtoType.decode(new Uint8Array(buf));
    const raw = ClientWireWsEventProtoType.toObject(decoded, {
      defaults: true,
      longs: Number,
    }) as Record<string, unknown>;
    return {
      event_type: String(raw.event_type ?? ""),
      sender: String(raw.sender ?? ""),
      recipient: String(raw.recipient ?? ""),
      wire_bytes_len: toNum(raw.wire_bytes_len),
      timestamp_ms: toNum(raw.timestamp_ms),
    };
  } catch {
    return null;
  }
}
