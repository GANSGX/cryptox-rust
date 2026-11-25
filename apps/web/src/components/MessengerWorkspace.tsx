import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  Check,
  CheckCheck,
  Code2,
  Database,
  HardDrive,
  Info,
  KeyRound,
  Laptop,
  Loader2,
  LogOut,
  MessageCircle,
  Moon,
  Plus,
  Search,
  Send,
  ShieldCheck,
  SquarePen,
  Sun,
  UserCheck,
  X,
} from "lucide-react";
import {
  type WallpaperVariant,
} from "./TelegramPatternWallpapers";
import {
  callClientWireProtobuf,
  ClientWireOp,
  decodeWsProtoEvent,
  encodeWsProtoEvent,
  type ClientDecryptedMessageItem,
  type ClientDirectoryPeer,
} from "../lib/protoWire";
import { cn } from "../lib/utils";
import emptyChatsMascotUrl from "../assets/empty-chats-mascot.jpg";
import chatWallpaperMutedUrl from "../assets/chat-wallpaper-muted.jpg";

interface MessengerWorkspaceProps {
  activeUsername: string;
  theme: "dark" | "light";
  wallpaper?: WallpaperVariant;
  onChangeWallpaper?: (w: WallpaperVariant) => void;
  onToggleTheme: (e: React.MouseEvent<HTMLButtonElement>) => void;
  onSwitchAccount: (username: string) => void;
  onLogout: () => void;
}

interface PeerChatSummary {
  lastText: string;
  timestampMs: number;
  isMine: boolean;
  isReadByPeer: boolean;
  count: number;
}

const AVATAR_GRADIENTS = [
  "from-sky-500 to-blue-600",
  "from-violet-500 to-purple-600",
  "from-emerald-500 to-teal-600",
  "from-rose-500 to-pink-600",
  "from-amber-500 to-orange-600",
  "from-indigo-500 to-blue-700",
];

function avatarGradientFor(username: string): string {
  let hash = 0;
  for (let i = 0; i < username.length; i++) {
    hash = (hash * 31 + username.charCodeAt(i)) | 0;
  }
  return AVATAR_GRADIENTS[Math.abs(hash) % AVATAR_GRADIENTS.length];
}

export const MessengerWorkspace: React.FC<MessengerWorkspaceProps> = ({
  activeUsername,
  theme,
  onToggleTheme,
  onSwitchAccount,
  onLogout,
}) => {
  const isDark = theme === "dark";

  const [allProfiles, setAllProfiles] = useState<ClientDirectoryPeer[]>([]);
  const [directoryPeers, setDirectoryPeers] = useState<ClientDirectoryPeer[]>([]);
  const [selectedPeer, setSelectedPeer] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Список открытых личных чатов и превью последних сообщений
  const [activeChatPeers, setActiveChatPeers] = useState<string[]>([]);
  const [chatSummaries, setChatSummaries] = useState<Record<string, PeerChatSummary>>({});
  const [showContactPicker, setShowContactPicker] = useState<boolean>(false);
  const [showAccountSwitcher, setShowAccountSwitcher] = useState<boolean>(false);

  const [messages, setMessages] = useState<ClientDecryptedMessageItem[]>([]);
  const [channelIdHex, setChannelIdHex] = useState<string>("");
  const [messageInput, setMessageInput] = useState<string>("");
  const [sending, setSending] = useState<boolean>(false);

  const [expandedMsgId, setExpandedMsgId] = useState<string | null>(null);
  const [showInspector, setShowInspector] = useState<boolean>(false);
  const [syncingDevice, setSyncingDevice] = useState<boolean>(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  // Метрики хранилища и протокола (Protobuf)
  const [metrics, setMetrics] = useState({
    l1Hits: 0,
    l2Reads: 0,
    diskCommits: 0,
    recordsWritten: 0,
    absorbedFailures: 0,
    lastWireBytes: 0,
  });

  // Индикатор набора текста и непрочитанных сообщений (бинарный WebSocket)
  const [peerTyping, setPeerTyping] = useState<Record<string, number>>({});
  const [unreadByPeer, setUnreadByPeer] = useState<Record<string, number>>({});
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);
  const selectedPeerRef = useRef<string>("");
  const activeUserRef = useRef<string>(activeUsername);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const lastTypingSentRef = useRef<number>(0);

  selectedPeerRef.current = selectedPeer;
  activeUserRef.current = activeUsername;

  const showToast = useCallback((text: string) => {
    setToastMsg(text);
    window.setTimeout(() => {
      setToastMsg((prev) => (prev === text ? null : prev));
    }, 3500);
  }, []);

  // 1. Загрузка состояния узла по бинарному Protobuf
  const refreshState = useCallback(async () => {
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.GetState,
        caller_username: activeUserRef.current,
      });
      if (resp.ok) {
        setAllProfiles(resp.peers);
        setMetrics((prev) => ({
          ...prev,
          l1Hits: resp.storage_l1_hits,
          l2Reads: resp.storage_l2_reads,
          diskCommits: resp.storage_disk_commits,
          recordsWritten: resp.storage_records_written,
          absorbedFailures: resp.absorbed_sidecar_failures,
        }));
      }
    } catch {
      // Игнорируем временную сетевую ошибку
    }
  }, []);

  // Подгрузка превью истории для списка личных чатов
  const syncPeerSummaries = useCallback(async (peers: ClientDirectoryPeer[]) => {
    const caller = activeUserRef.current;
    if (!caller) return;
    const nextSummaries: Record<string, PeerChatSummary> = {};
    const peersWithHistory: string[] = [];

    for (const p of peers) {
      if (p.username === caller) continue;
      try {
        const hist = await callClientWireProtobuf({
          op: ClientWireOp.FetchChatHistory,
          caller_username: caller,
          peer_username: p.username,
        });
        if (hist.ok && hist.messages.length > 0) {
          const last = hist.messages[hist.messages.length - 1];
          nextSummaries[p.username] = {
            lastText: last.decrypted_text,
            timestampMs: last.timestamp_ms,
            isMine: last.sender_username === caller,
            isReadByPeer: last.is_read_by_peer,
            count: hist.messages.length,
          };
          peersWithHistory.push(p.username);
        }
      } catch {
        // Пропускаем
      }
    }

    setChatSummaries((prev) => ({ ...prev, ...nextSummaries }));
    if (peersWithHistory.length > 0) {
      setActiveChatPeers((prev) => {
        const merged = new Set([...prev, ...peersWithHistory]);
        return Array.from(merged);
      });
    }
  }, []);

  // 2. Поиск сотрудников в каталоге `user-directory-svc` по бинарному Protobuf
  const loadDirectoryPeers = useCallback(
    async (query: string) => {
      try {
        const resp = await callClientWireProtobuf({
          op: ClientWireOp.SearchDirectory,
          caller_username: activeUserRef.current,
          search_query: query,
        });
        if (resp.ok) {
          const others = resp.peers.filter((p) => p.username !== activeUserRef.current);
          setDirectoryPeers(others);
          void syncPeerSummaries(others);
        }
      } catch {
        // Fallback
      }
    },
    [syncPeerSummaries]
  );

  // 3. Загрузка и локальная E2EE-расшифровка истории выбранного личного чата
  const loadChatHistory = useCallback(async (peerUsername: string) => {
    if (!peerUsername || !activeUserRef.current) return;
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.FetchChatHistory,
        caller_username: activeUserRef.current,
        peer_username: peerUsername,
      });
      if (resp.ok) {
        setMessages(resp.messages);
        if (resp.channel_id_hex) {
          setChannelIdHex(resp.channel_id_hex);
        }
        if (resp.messages.length > 0) {
          const last = resp.messages[resp.messages.length - 1];
          setChatSummaries((prev) => ({
            ...prev,
            [peerUsername]: {
              lastText: last.decrypted_text,
              timestampMs: last.timestamp_ms,
              isMine: last.sender_username === activeUserRef.current,
              isReadByPeer: last.is_read_by_peer,
              count: resp.messages.length,
            },
          }));
        }
        await callClientWireProtobuf({
          op: ClientWireOp.MarkChatRead,
          caller_username: activeUserRef.current,
          peer_username: peerUsername,
        });
        setUnreadByPeer((prev) => {
          if (!prev[peerUsername]) return prev;
          const next = { ...prev };
          delete next[peerUsername];
          return next;
        });
      }
    } catch {
      // Игнорируем
    }
  }, []);

  // Сброс при смене активного пользователя
  useEffect(() => {
    setSelectedPeer("");
    setActiveChatPeers([]);
    setChatSummaries({});
    setMessages([]);
    setShowContactPicker(false);
    void refreshState();
    void loadDirectoryPeers(searchQuery);
  }, [activeUsername, refreshState, loadDirectoryPeers, searchQuery]);

  // Загрузка истории при выборе собеседника
  useEffect(() => {
    if (selectedPeer) {
      void loadChatHistory(selectedPeer);
    }
  }, [selectedPeer, activeUsername, loadChatHistory]);

  // Автопрокрутка к последнему сообщению
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length, selectedPeer]);

  // 4. Подключение бинарного WebSocket (`/ws`, `binaryType = "arraybuffer"`)
  useEffect(() => {
    let alive = true;
    let reconnectTimer: number | undefined;

    const connectWs = () => {
      if (!alive) return;
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${proto}//${window.location.host}/ws`);
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      ws.onopen = () => {
        if (!alive) return;
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        if (!alive) return;
        if (event.data instanceof ArrayBuffer) {
          const ev = decodeWsProtoEvent(event.data);
          if (!ev) return;

          if (ev.event_type === "new_message") {
            void refreshState();
            const currentActive = activeUserRef.current;
            const currentPeer = selectedPeerRef.current;
            const otherParty =
              ev.sender === currentActive ? ev.recipient : ev.sender;

            if (
              ev.sender === currentActive ||
              ev.recipient === currentActive
            ) {
              setActiveChatPeers((prev) =>
                prev.includes(otherParty) ? prev : [otherParty, ...prev]
              );
              void loadDirectoryPeers("");
            }

            if (
              (ev.sender === currentPeer && ev.recipient === currentActive) ||
              (ev.sender === currentActive && ev.recipient === currentPeer)
            ) {
              void loadChatHistory(currentPeer);
            } else if (ev.recipient === currentActive) {
              setUnreadByPeer((prev) => ({
                ...prev,
                [ev.sender]: (prev[ev.sender] ?? 0) + 1,
              }));
            }
          } else if (ev.event_type === "read_receipt") {
            const currentPeer = selectedPeerRef.current;
            if (ev.sender === currentPeer || ev.recipient === currentPeer) {
              void loadChatHistory(currentPeer);
            }
          } else if (
            ev.event_type === "user_registered" ||
            ev.event_type === "directory_updated"
          ) {
            void refreshState();
            void loadDirectoryPeers(searchQuery);
          } else if (ev.event_type === "typing") {
            if (ev.recipient === activeUserRef.current) {
              setPeerTyping((prev) => ({
                ...prev,
                [ev.sender]: Date.now(),
              }));
            }
          }
        }
      };

      ws.onclose = () => {
        if (!alive) return;
        setWsConnected(false);
        reconnectTimer = window.setTimeout(connectWs, 1800);
      };
    };

    connectWs();

    const typingCleanup = window.setInterval(() => {
      const now = Date.now();
      setPeerTyping((prev) => {
        let changed = false;
        const next: Record<string, number> = {};
        for (const [k, ts] of Object.entries(prev)) {
          if (now - ts < 3000) {
            next[k] = ts;
          } else {
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    }, 1000);

    return () => {
      alive = false;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      window.clearInterval(typingCleanup);
      wsRef.current?.close();
    };
  }, [loadChatHistory, loadDirectoryPeers, refreshState, searchQuery]);

  // Выбор или создание личного чата
  const handleSelectOrStartChat = (peerUsername: string) => {
    setActiveChatPeers((prev) =>
      prev.includes(peerUsername) ? prev : [peerUsername, ...prev]
    );
    setSelectedPeer(peerUsername);
    setShowContactPicker(false);
  };

  // Отправка E2EE сообщения через бинарный Protobuf
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = messageInput.trim();
    if (!text || !selectedPeer || sending) return;

    setSending(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.SendChatMessage,
        caller_username: activeUsername,
        peer_username: selectedPeer,
        plaintext_message: text,
      });
      if (resp.ok) {
        setMessageInput("");
        setActiveChatPeers((prev) =>
          prev.includes(selectedPeer) ? prev : [selectedPeer, ...prev]
        );
        setMetrics((prev) => ({
          ...prev,
          lastWireBytes: resp.wire_bytes_len,
        }));
        await loadChatHistory(selectedPeer);
        await refreshState();
      } else {
        showToast(resp.error_message || "Не удалось отправить сообщение");
      }
    } catch {
      showToast("Ошибка бинарного канала Protobuf");
    } finally {
      setSending(false);
    }
  };

  // Отправка бинарного кадра typing по WebSocket
  const handleInputTyping = (val: string) => {
    setMessageInput(val);
    const now = Date.now();
    if (
      wsRef.current &&
      wsRef.current.readyState === WebSocket.OPEN &&
      selectedPeer &&
      now - lastTypingSentRef.current > 1200
    ) {
      lastTypingSentRef.current = now;
      const frame = encodeWsProtoEvent({
        event_type: "typing",
        sender: activeUsername,
        recipient: selectedPeer,
        wire_bytes_len: val.length,
        timestamp_ms: now,
      });
      wsRef.current.send(frame);
    }
  };

  // Синхронизация нового устройства через CloudKeyVault по бинарному Protobuf
  const handleCloudSyncDevice = async () => {
    if (syncingDevice) return;
    setSyncingDevice(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.CloudSyncNewDevice,
        caller_username: activeUsername,
      });
      if (resp.ok) {
        await refreshState();
        showToast(
          `Устройство #${resp.device_number} синхронизировано (${resp.wire_bytes_len} B Protobuf)`
        );
      } else {
        showToast(resp.error_message || "Ошибка синхронизации сейфа");
      }
    } catch {
      showToast("Сетевая ошибка синхронизации CloudKeyVault");
    } finally {
      setSyncingDevice(false);
    }
  };

  const currentProfile = allProfiles.find((p) => p.username === activeUsername) ?? {
    username: activeUsername,
    display_name: activeUsername,
    device_number: 1,
    vault_version: 1,
    key_version: 1,
    transparency_seq: 1,
    ed25519_pub_hex_short: "",
    x25519_pub_hex_short: "",
  };

  const activePeerObj =
    directoryPeers.find((p) => p.username === selectedPeer) ??
    allProfiles.find((p) => p.username === selectedPeer);

  const initials = (name: string) => {
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  };

  const formatShortTime = (ms: number) => {
    if (!ms) return "";
    const d = new Date(ms);
    return d.toLocaleTimeString("ru-RU", {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Фильтрация списка личных чатов
  const visibleChats = directoryPeers.filter((p) => {
    if (searchQuery.trim() || showContactPicker) {
      return true;
    }
    return activeChatPeers.includes(p.username);
  });

  return (
    <div
      className={cn(
        "relative flex h-screen w-screen overflow-hidden select-none",
        isDark ? "bg-[#09090b] text-zinc-100" : "bg-[#f2f2f7] text-zinc-900"
      )}
    >
      {/* Всплывающее уведомление */}
      <AnimatePresence>
        {toastMsg && (
          <motion.div
            initial={{ opacity: 0, y: -16, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -16, scale: 0.96 }}
            className={cn(
              "fixed top-4 left-1/2 z-50 -translate-x-1/2 flex items-center gap-2.5 rounded-2xl border px-4 py-2.5 text-xs font-medium shadow-2xl backdrop-blur-md",
              isDark
                ? "border-zinc-800 bg-zinc-900/95 text-zinc-100"
                : "border-zinc-200 bg-white/95 text-zinc-900"
            )}
          >
            <ShieldCheck className="h-4 w-4 text-emerald-500 shrink-0" />
            <span>{toastMsg}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* =====================================================================
          ЛЕВАЯ КОЛОНКА ЛИЧНЫХ ЧАТОВ (в стиле macOS Telegram, без папок и архива)
          ===================================================================== */}
      <aside
        className={cn(
          "relative z-20 flex w-[360px] shrink-0 flex-col border-r",
          isDark
            ? "border-zinc-800/80 bg-[#0d0d11]"
            : "border-zinc-200/90 bg-white"
        )}
      >
        {/* Верхняя шапка: Аватар профиля слева — «Чаты» по центру — Кнопка нового чата справа */}
        <div className="flex h-13 shrink-0 items-center justify-between px-4 pt-2">
          <button
            type="button"
            onClick={() => setShowAccountSwitcher((v) => !v)}
            title={`Профиль @${currentProfile.username} (Устр. #${currentProfile.device_number || 1})`}
            className="relative flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 text-[11px] font-bold text-white shadow-xs transition-transform active:scale-95 cursor-pointer"
          >
            {initials(currentProfile.display_name || currentProfile.username)}
            <span
              className={cn(
                "absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2",
                isDark ? "border-[#0d0d11]" : "border-white",
                wsConnected ? "bg-emerald-500" : "bg-amber-500"
              )}
            />
          </button>

          <span className="text-[15px] font-semibold tracking-tight">
            {showContactPicker ? "Новый чат" : "Чаты"}
          </span>

          <button
            type="button"
            onClick={() => {
              setShowContactPicker((v) => !v);
              setTimeout(() => searchInputRef.current?.focus(), 50);
            }}
            title={showContactPicker ? "Вернуться к чатам" : "Начать новый личный чат"}
            className={cn(
              "flex h-8 w-8 items-center justify-center rounded-lg transition-colors cursor-pointer",
              showContactPicker
                ? "text-sky-400 bg-sky-500/10"
                : isDark
                  ? "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100"
                  : "text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900"
            )}
          >
            <SquarePen className="h-4 w-4" />
          </button>
        </div>

        {/* Выпадающее меню быстрой смены активного анклава (при клике на свой аватар) */}
        <AnimatePresence>
          {showAccountSwitcher && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden px-3"
            >
              <div
                className={cn(
                  "mt-1.5 mb-1 rounded-2xl border p-2.5 text-xs",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/90"
                    : "border-zinc-200 bg-zinc-50"
                )}
              >
                <div className="mb-2 flex items-center justify-between text-[11px] text-zinc-400">
                  <span className="font-medium">
                    @{currentProfile.username} • Устр. #{currentProfile.device_number || 1}
                  </span>
                  <span className="font-mono text-[10px] text-emerald-500">
                    Сейф v{currentProfile.vault_version || 1}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {allProfiles.map((u) => {
                    const active = u.username === activeUsername;
                    return (
                      <button
                        key={u.username}
                        type="button"
                        onClick={() => {
                          setShowAccountSwitcher(false);
                          onSwitchAccount(u.username);
                        }}
                        className={cn(
                          "rounded-lg px-2 py-1 font-mono text-[10px] font-medium transition-colors cursor-pointer",
                          active
                            ? "bg-sky-500 text-white"
                            : isDark
                              ? "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
                              : "bg-zinc-200/80 text-zinc-700 hover:bg-zinc-300"
                        )}
                      >
                        @{u.username}
                      </button>
                    );
                  })}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Строка поиска как в macOS Telegram (`Поиск`) */}
        <div className="px-3 py-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-3.5 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Поиск"
              aria-label="Поиск"
              className={cn(
                "h-8 w-full rounded-full border pr-8 pl-9 text-xs outline-none transition-colors",
                isDark
                  ? "border-zinc-800/80 bg-[#18181f] text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-700"
                  : "border-zinc-200/80 bg-zinc-100 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-300 focus:bg-white"
              )}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className="absolute top-1/2 right-2.5 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* СПИСОК ЛИЧНЫХ ЧАТОВ ИЛИ СОСТОЯНИЕ «НЕТ СООБЩЕНИЙ» С МАСКОТОМ V1 */}
        <div className="flex-1 overflow-y-auto px-2 pb-20">
          {visibleChats.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center px-6 text-center">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ type: "spring", stiffness: 320, damping: 28 }}
                className="flex flex-col items-center"
              >
                <div className="relative mb-2 h-44 w-44 overflow-hidden rounded-3xl">
                  <img
                    src={emptyChatsMascotUrl}
                    alt="Нет сообщений"
                    draggable={false}
                    className={cn(
                      "h-full w-full object-contain",
                      isDark ? "mix-blend-lighten" : "rounded-3xl"
                    )}
                  />
                </div>
                <h3
                  className={cn(
                    "text-[15px] font-semibold",
                    isDark ? "text-zinc-200" : "text-zinc-800"
                  )}
                >
                  Нет сообщений
                </h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Начните переписку первым
                </p>

                <button
                  type="button"
                  onClick={() => setShowContactPicker(true)}
                  className={cn(
                    "mt-5 inline-flex items-center gap-1.5 rounded-full px-4 py-2 text-xs font-semibold transition-transform active:scale-95 cursor-pointer",
                    isDark
                      ? "bg-zinc-800/90 text-zinc-100 hover:bg-zinc-700"
                      : "bg-zinc-900 text-white hover:bg-zinc-800"
                  )}
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>Начать чат</span>
                </button>
              </motion.div>
            </div>
          ) : (
            <div className="space-y-0.5 pt-0.5">
              {showContactPicker && (
                <div className="px-3 py-1.5 text-[11px] font-medium text-zinc-500">
                  Выберите собеседника для личного чата
                </div>
              )}

              {visibleChats.map((peer) => {
                const isSelected = peer.username === selectedPeer;
                const unread = unreadByPeer[peer.username] ?? 0;
                const isTyping = Boolean(peerTyping[peer.username]);
                const summary = chatSummaries[peer.username];

                return (
                  <button
                    key={peer.username}
                    type="button"
                    onClick={() => handleSelectOrStartChat(peer.username)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-2xl px-2.5 py-2 text-left transition-colors cursor-pointer",
                      isSelected
                        ? "bg-[#2b5278] text-white"
                        : isDark
                          ? "text-zinc-200 hover:bg-zinc-800/45"
                          : "text-zinc-800 hover:bg-zinc-100"
                    )}
                  >
                    {/* Круглый аватар 48x48 как в macOS Telegram */}
                    <div
                      className={cn(
                        "relative flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-gradient-to-br text-sm font-bold text-white shadow-xs",
                        avatarGradientFor(peer.username)
                      )}
                    >
                      {initials(peer.display_name || peer.username)}
                      <span
                        className={cn(
                          "absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 bg-emerald-500",
                          isSelected
                            ? "border-[#2b5278]"
                            : isDark
                              ? "border-[#0d0d11]"
                              : "border-white"
                        )}
                      />
                    </div>

                    {/* Имя, время, галочки и превью последнего сообщения */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[14px] font-semibold">
                          {peer.display_name}
                        </span>

                        <div className="flex shrink-0 items-center gap-1 text-[11px]">
                          {summary?.isMine &&
                            (summary.isReadByPeer ? (
                              <CheckCheck
                                className={cn(
                                  "h-3.5 w-3.5",
                                  isSelected ? "text-sky-200" : "text-sky-400"
                                )}
                              />
                            ) : (
                              <Check
                                className={cn(
                                  "h-3.5 w-3.5",
                                  isSelected ? "text-sky-200" : "text-zinc-500"
                                )}
                              />
                            ))}
                          {summary?.timestampMs ? (
                            <span
                              className={
                                isSelected ? "text-sky-100/80" : "text-zinc-500"
                              }
                            >
                              {formatShortTime(summary.timestampMs)}
                            </span>
                          ) : null}
                        </div>
                      </div>

                      <div className="mt-0.5 flex items-center justify-between gap-2">
                        {isTyping ? (
                          <span
                            className={cn(
                              "truncate text-[13px] font-medium",
                              isSelected ? "text-sky-200" : "text-sky-400"
                            )}
                          >
                            печатает...
                          </span>
                        ) : (
                          <span
                            className={cn(
                              "truncate text-[13px]",
                              isSelected ? "text-sky-100/85" : "text-zinc-500"
                            )}
                          >
                            {summary?.lastText
                              ? summary.lastText
                              : `@${peer.username}`}
                          </span>
                        )}

                        {unread > 0 && (
                          <span
                            className={cn(
                              "flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full px-1.5 text-[11px] font-bold",
                              isSelected
                                ? "bg-white text-[#2b5278]"
                                : "bg-sky-500 text-white"
                            )}
                          >
                            {unread}
                          </span>
                        )}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Нижний плавающий док в стиле macOS Telegram (Скриншот 1) */}
        <div className="pointer-events-none absolute right-0 bottom-3 left-0 z-30 flex justify-center px-4">
          <div
            className={cn(
              "pointer-events-auto flex items-center gap-1.5 rounded-full border px-2.5 py-1.5 shadow-xl backdrop-blur-xl",
              isDark
                ? "border-zinc-800/90 bg-[#16161d]/90"
                : "border-zinc-200/90 bg-white/90"
            )}
          >
            <button
              type="button"
              onClick={() => setShowAccountSwitcher((v) => !v)}
              title="Сменить активный профиль"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full transition-colors cursor-pointer",
                showAccountSwitcher
                  ? "bg-sky-500/20 text-sky-400"
                  : isDark
                    ? "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                    : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900"
              )}
            >
              <UserCheck className="h-4 w-4" />
            </button>

            <button
              type="button"
              onClick={handleCloudSyncDevice}
              disabled={syncingDevice}
              title="Синхронизировать новое устройство (CloudKeyVault)"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full transition-colors cursor-pointer",
                isDark
                  ? "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                  : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900"
              )}
            >
              {syncingDevice ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Laptop className="h-4 w-4" />
              )}
            </button>

            {/* Активная центральная пилюля «Чаты» */}
            <button
              type="button"
              onClick={() => {
                setShowContactPicker(false);
                setSearchQuery("");
              }}
              title="Личные чаты"
              className="flex h-9 items-center justify-center rounded-full bg-sky-500 px-4 text-white shadow-sm cursor-pointer"
            >
              <MessageCircle className="h-4 w-4 fill-current" />
            </button>

            <a
              href="/status"
              target="_blank"
              rel="noreferrer"
              title="Статус микросервисов и Circuit Breakers (/status)"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full transition-colors",
                isDark
                  ? "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
                  : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900"
              )}
            >
              <Activity className="h-4 w-4" />
            </a>

            <button
              type="button"
              onClick={onLogout}
              title="Выйти на экран авторизации"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full transition-colors cursor-pointer",
                isDark
                  ? "text-zinc-400 hover:bg-rose-500/15 hover:text-rose-400"
                  : "text-zinc-600 hover:bg-rose-50 hover:text-rose-600"
              )}
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* =====================================================================
          ПРАВАЯ ОБЛАСТЬ ЧАТА С УТВЕРЖДЁННЫМ ПРИГЛУШЁННЫМ ПАТТЕРН-ФОНОМ
          ===================================================================== */}
      <main className="relative flex flex-1 flex-col overflow-hidden">
        {/* Утверждённый приглушённый паттерн-фон с мелкими маскотами (как на Скриншоте 3) */}
        <div
          className="pointer-events-none absolute inset-0 z-0"
          style={{
            backgroundImage: `url(${chatWallpaperMutedUrl})`,
            backgroundSize: "460px 460px",
            backgroundRepeat: "repeat",
            backgroundPosition: "center",
            opacity: isDark ? 0.88 : 0.12,
            filter: isDark ? "none" : "invert(1)",
          }}
        />
        {/* Лёгкая матовая вуаль для идеальной читаемости текста */}
        <div
          className={cn(
            "pointer-events-none absolute inset-0 z-0",
            isDark ? "bg-black/25" : "bg-white/60"
          )}
        />

        {/* Кнопки в правом верхнем углу (Смена темы с волной + Инфо/Инспектор как на Скриншоте 1) */}
        <div className="fixed top-3.5 right-4 z-30 flex items-center gap-2">
          <button
            type="button"
            onClick={onToggleTheme}
            title={isDark ? "Светлая тема" : "Тёмная тема"}
            aria-label="Переключить тему оформления"
            className={cn(
              "flex h-9 w-9 items-center justify-center rounded-full border backdrop-blur-xl transition-transform active:scale-95 cursor-pointer",
              isDark
                ? "border-zinc-800/90 bg-[#16161d]/85 text-zinc-200 hover:bg-zinc-800"
                : "border-zinc-200/90 bg-white/85 text-zinc-700 hover:bg-zinc-100"
            )}
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          <button
            type="button"
            onClick={() => setShowInspector((v) => !v)}
            title="Инспектор пакетов Protobuf и хранилища redb"
            className={cn(
              "flex h-9 w-9 items-center justify-center rounded-full border backdrop-blur-xl transition-colors cursor-pointer",
              showInspector
                ? "border-sky-500/50 bg-sky-500/20 text-sky-300"
                : isDark
                  ? "border-zinc-800/90 bg-[#16161d]/85 text-zinc-300 hover:bg-zinc-800"
                  : "border-zinc-200/90 bg-white/85 text-zinc-700 hover:bg-zinc-100"
            )}
          >
            <Info className="h-4 w-4" />
          </button>
        </div>

        {/* Если чат ещё не выбран — центрированная плашка как в macOS Telegram (Скриншот 1) */}
        {!activePeerObj ? (
          <div className="relative z-10 flex flex-1 items-center justify-center p-6">
            <div
              className={cn(
                "rounded-full border px-5 py-2 text-xs font-medium shadow-lg backdrop-blur-xl",
                isDark
                  ? "border-zinc-800/80 bg-[#14141b]/85 text-zinc-300"
                  : "border-zinc-200/90 bg-white/90 text-zinc-700"
              )}
            >
              Выберите, кому хотели бы написать
            </div>
          </div>
        ) : (
          <>
            {/* Плавающая шапка открытого чата по центру (в стиле Скриншота 3) */}
            <header className="relative z-10 flex h-16 shrink-0 items-center justify-center px-6 pt-2">
              <div
                className={cn(
                  "flex min-w-[200px] flex-col items-center justify-center rounded-full border px-6 py-1.5 shadow-lg backdrop-blur-xl",
                  isDark
                    ? "border-zinc-800/80 bg-[#17171f]/85"
                    : "border-zinc-200/80 bg-white/90"
                )}
              >
                <span className="text-[14px] font-semibold leading-tight">
                  {activePeerObj.display_name}
                </span>
                <span className="text-[11px] text-zinc-400">
                  {peerTyping[activePeerObj.username] ? (
                    <span className="font-medium text-sky-400">печатает...</span>
                  ) : (
                    "был(а) недавно"
                  )}
                </span>
              </div>
            </header>

            {/* Поток сообщений */}
            <div className="relative z-10 flex-1 overflow-y-auto px-8 py-4 space-y-2.5">
              {messages.length === 0 ? (
                <div className="flex h-full items-center justify-center">
                  <div
                    className={cn(
                      "rounded-full border px-4 py-1.5 text-xs backdrop-blur-xl",
                      isDark
                        ? "border-zinc-800/80 bg-[#14141b]/80 text-zinc-400"
                        : "border-zinc-200/80 bg-white/85 text-zinc-600"
                    )}
                  >
                    Сообщений пока нет — напишите первым
                  </div>
                </div>
              ) : (
                messages.map((m) => {
                  const isMine = m.sender_username === activeUsername;
                  const isExpanded = expandedMsgId === m.message_id_short;

                  return (
                    <motion.div
                      key={`${m.message_id_short}-${m.ratchet_step}`}
                      initial={{ opacity: 0, y: 8, scale: 0.98 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
                      className={cn(
                        "flex flex-col",
                        isMine ? "items-end" : "items-start"
                      )}
                    >
                      <div
                        className={cn(
                          "max-w-lg rounded-2xl px-4 py-2 shadow-md backdrop-blur-md",
                          isMine
                            ? "bg-[#2b5278] text-white rounded-br-sm"
                            : isDark
                              ? "border border-zinc-800/80 bg-[#181820]/95 text-zinc-100 rounded-bl-sm"
                              : "border border-zinc-200/90 bg-white/95 text-zinc-900 rounded-bl-sm"
                        )}
                      >
                        <p className="text-[13.5px] leading-relaxed whitespace-pre-wrap break-words">
                          {m.decrypted_text}
                        </p>

                        <div
                          className={cn(
                            "mt-1 flex items-center justify-end gap-1.5 text-[10px]",
                            isMine ? "text-sky-100/75" : "text-zinc-400"
                          )}
                        >
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedMsgId(
                                isExpanded ? null : m.message_id_short
                              )
                            }
                            title="Показать бинарный конверт EncryptedEnvelope (Protobuf)"
                            className="inline-flex items-center gap-1 rounded px-1 py-0.5 font-mono hover:bg-black/15 cursor-pointer"
                          >
                            <Code2 className="h-2.5 w-2.5" />
                            <span>#{m.ratchet_step}</span>
                          </button>

                          <span>{formatShortTime(m.timestamp_ms)}</span>

                          {isMine &&
                            (m.is_read_by_peer ? (
                              <span
                                title="Прочитано собеседником"
                                className="inline-flex"
                              >
                                <CheckCheck className="h-3.5 w-3.5 text-sky-300" />
                              </span>
                            ) : (
                              <span title="Доставлено" className="inline-flex">
                                <Check className="h-3.5 w-3.5 opacity-75" />
                              </span>
                            ))}
                        </div>

                        {/* Раскрывающийся дамп бинарного Protobuf-конверта */}
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              className="overflow-hidden"
                            >
                              <div className="mt-2 space-y-1 rounded-xl bg-black/35 p-2.5 font-mono text-[10px] text-zinc-200">
                                <div>
                                  <span className="text-zinc-400">UUIDv7:</span>{" "}
                                  {m.message_id_short} ({m.wire_bytes_len} B)
                                </div>
                                <div>
                                  <span className="text-zinc-400">Nonce:</span>{" "}
                                  {m.nonce_hex}
                                </div>
                                <div className="truncate">
                                  <span className="text-zinc-400">
                                    Ciphertext:
                                  </span>{" "}
                                  {m.ciphertext_hex}
                                </div>
                                <div className="truncate">
                                  <span className="text-zinc-400">
                                    Ed25519 Sig:
                                  </span>{" "}
                                  {m.signature_hex_short}
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    </motion.div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Нижняя плавающая капсула ввода сообщения (в стиле Скриншота 3) */}
            <footer className="relative z-10 px-8 pb-5 pt-2">
              <form
                onSubmit={handleSendMessage}
                className="mx-auto flex max-w-2xl items-center gap-2.5"
              >
                <div
                  className={cn(
                    "flex h-11 flex-1 items-center rounded-full border px-5 shadow-lg backdrop-blur-xl",
                    isDark
                      ? "border-zinc-800/90 bg-[#17171f]/90"
                      : "border-zinc-200/90 bg-white/95"
                  )}
                >
                  <input
                    type="text"
                    value={messageInput}
                    onChange={(e) => handleInputTyping(e.target.value)}
                    placeholder="Сообщение"
                    aria-label="Сообщение"
                    disabled={sending}
                    className={cn(
                      "h-full w-full bg-transparent text-sm outline-none",
                      isDark
                        ? "text-zinc-100 placeholder:text-zinc-500"
                        : "text-zinc-900 placeholder:text-zinc-400"
                    )}
                  />
                </div>

                <button
                  type="submit"
                  disabled={!messageInput.trim() || sending}
                  aria-label="Отправить сообщение"
                  className={cn(
                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-full border shadow-lg backdrop-blur-xl transition-all active:scale-95 cursor-pointer disabled:opacity-40",
                    messageInput.trim()
                      ? "border-sky-500 bg-sky-500 text-white"
                      : isDark
                        ? "border-zinc-800/90 bg-[#17171f]/90 text-zinc-400"
                        : "border-zinc-200/90 bg-white/95 text-zinc-500"
                  )}
                >
                  {sending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Send className="h-4 w-4" />
                  )}
                </button>
              </form>
            </footer>
          </>
        )}
      </main>

      {/* ПРАВАЯ ВЫДВИЖНАЯ ПАНЕЛЬ ИНСПЕКТОРА PROTOBUF И ДИСКОВОГО B+TREE */}
      <AnimatePresence>
        {showInspector && (
          <motion.aside
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 320, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className={cn(
              "z-20 flex shrink-0 flex-col overflow-hidden border-l",
              isDark
                ? "border-zinc-800/80 bg-[#0d0d11]/95"
                : "border-zinc-200/90 bg-white/95"
            )}
          >
            <div
              className={cn(
                "flex items-center justify-between border-b p-4",
                isDark ? "border-zinc-800/80" : "border-zinc-200/80"
              )}
            >
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-500" />
                <span className="text-xs font-semibold">
                  Инспектор Protobuf & Хранилища
                </span>
              </div>
              <button
                type="button"
                onClick={() => setShowInspector(false)}
                className="text-zinc-500 hover:text-zinc-300 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
              <div
                className={cn(
                  "rounded-xl border p-3 space-y-2",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/60"
                    : "border-zinc-200 bg-zinc-50"
                )}
              >
                <div className="flex items-center gap-1.5 font-semibold text-emerald-500">
                  <KeyRound className="h-3.5 w-3.5" />
                  <span>Транспортный уровень</span>
                </div>
                <div className="space-y-1 text-[11px] text-zinc-400">
                  <div className="flex justify-between">
                    <span>RPC эндпоинт:</span>
                    <span className="font-mono text-zinc-200">
                      POST /rpc/v1/client-wire
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>MIME-тип:</span>
                    <span className="font-mono text-emerald-400">
                      application/x-protobuf
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>WebSocket /ws:</span>
                    <span className="font-mono text-emerald-400">
                      Binary ArrayBuffer
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Канал UUIDv7:</span>
                    <span className="font-mono text-zinc-200">
                      {channelIdHex ? `${channelIdHex.slice(0, 12)}…` : "—"}
                    </span>
                  </div>
                </div>
              </div>

              <div
                className={cn(
                  "rounded-xl border p-3 space-y-2",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/60"
                    : "border-zinc-200 bg-zinc-50"
                )}
              >
                <div className="flex items-center gap-1.5 font-semibold text-sky-400">
                  <Database className="h-3.5 w-3.5" />
                  <span>Движок cryptox-storage (redb)</span>
                </div>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div
                    className={cn(
                      "rounded-lg border p-2",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/60"
                        : "border-zinc-200 bg-white"
                    )}
                  >
                    <div className="text-[10px] text-zinc-500">L1 RAM Hits</div>
                    <div className="mt-0.5 font-mono text-sm font-bold">
                      {metrics.l1Hits}
                    </div>
                  </div>
                  <div
                    className={cn(
                      "rounded-lg border p-2",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/60"
                        : "border-zinc-200 bg-white"
                    )}
                  >
                    <div className="text-[10px] text-zinc-500">L2 SSD Reads</div>
                    <div className="mt-0.5 font-mono text-sm font-bold">
                      {metrics.l2Reads}
                    </div>
                  </div>
                  <div
                    className={cn(
                      "rounded-lg border p-2",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/60"
                        : "border-zinc-200 bg-white"
                    )}
                  >
                    <div className="text-[10px] text-zinc-500">Group Commits</div>
                    <div className="mt-0.5 font-mono text-sm font-bold">
                      {metrics.diskCommits}
                    </div>
                  </div>
                  <div
                    className={cn(
                      "rounded-lg border p-2",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/60"
                        : "border-zinc-200 bg-white"
                    )}
                  >
                    <div className="text-[10px] text-zinc-500">B+Tree Записей</div>
                    <div className="mt-0.5 font-mono text-sm font-bold">
                      {metrics.recordsWritten}
                    </div>
                  </div>
                </div>
              </div>

              {activePeerObj && (
                <div
                  className={cn(
                    "rounded-xl border p-3 space-y-1.5",
                    isDark
                      ? "border-zinc-800 bg-zinc-900/60"
                      : "border-zinc-200 bg-zinc-50"
                  )}
                >
                  <div className="flex items-center gap-1.5 font-semibold">
                    <HardDrive className="h-3.5 w-3.5 text-emerald-500" />
                    <span>Крипто-ключи @{activePeerObj.username}</span>
                  </div>
                  <div className="font-mono text-[10px] text-zinc-400 space-y-1">
                    <div>
                      Key Transparency: #{activePeerObj.transparency_seq || 1}
                    </div>
                    <div className="truncate">
                      Ed25519: {activePeerObj.ed25519_pub_hex_short || "verified"}
                    </div>
                    <div className="truncate">
                      X25519: {activePeerObj.x25519_pub_hex_short || "verified"}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </div>
  );
};
