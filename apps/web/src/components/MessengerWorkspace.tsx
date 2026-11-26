import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Check,
  CheckCheck,
  Loader2,
  Search,
  Send,
  X,
} from "lucide-react";
import { type WallpaperVariant } from "./TelegramPatternWallpapers";
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
  onToggleTheme?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  onSwitchAccount?: (username: string) => void;
  onLogout?: () => void;
}

interface PeerChatSummary {
  lastText: string;
  timestampMs: number;
  isMine: boolean;
  isReadByPeer: boolean;
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
    hash = Math.trunc(hash * 31 + (username.codePointAt(i) ?? 0)) % 1000003;
  }
  return AVATAR_GRADIENTS[Math.abs(hash) % AVATAR_GRADIENTS.length];
}

export const MessengerWorkspace: React.FC<MessengerWorkspaceProps> = ({
  activeUsername,
  theme,
  onLogout,
}) => {
  const isDark = theme === "dark";

  const [directoryPeers, setDirectoryPeers] = useState<ClientDirectoryPeer[]>([]);
  const [selectedPeer, setSelectedPeer] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Список личных чатов, в которых уже есть переписка или которые открыл пользователь
  const [activeChatPeers, setActiveChatPeers] = useState<string[]>([]);
  const [chatSummaries, setChatSummaries] = useState<Record<string, PeerChatSummary>>({});

  const [messages, setMessages] = useState<ClientDecryptedMessageItem[]>([]);
  const [messageInput, setMessageInput] = useState<string>("");
  const [sending, setSending] = useState<boolean>(false);

  // Индикатор набора текста и непрочитанных сообщений (бинарный WebSocket)
  const [peerTyping, setPeerTyping] = useState<Record<string, number>>({});
  const [unreadByPeer, setUnreadByPeer] = useState<Record<string, number>>({});

  const wsRef = useRef<WebSocket | null>(null);
  const selectedPeerRef = useRef<string>("");
  const activeUserRef = useRef<string>(activeUsername);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const lastTypingSentRef = useRef<number>(0);

  selectedPeerRef.current = selectedPeer;
  activeUserRef.current = activeUsername;

  // Подгрузка существующих переписок для формирования списка личных чатов
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

  // Поиск пользователей в каталоге `user-directory-svc` по бинарному Protobuf
  const loadDirectoryPeers = useCallback(
    async (query: string) => {
      try {
        const resp = await callClientWireProtobuf({
          op: ClientWireOp.SearchDirectory,
          caller_username: activeUserRef.current,
          search_query: query,
        });
        if (resp.ok) {
          const others = resp.peers.filter(
            (p) => p.username !== activeUserRef.current
          );
          setDirectoryPeers(others);
          void syncPeerSummaries(others);
        } else if (resp.error_message.includes("не найден")) {
          onLogout?.();
        }
      } catch {
        // Игнорируем ошибку сети
      }
    },
    [onLogout, syncPeerSummaries]
  );

  // Загрузка и расшифровка истории выбранного личного чата по бинарному Protobuf
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
        if (resp.messages.length > 0) {
          const last = resp.messages[resp.messages.length - 1];
          setChatSummaries((prev) => ({
            ...prev,
            [peerUsername]: {
              lastText: last.decrypted_text,
              timestampMs: last.timestamp_ms,
              isMine: last.sender_username === activeUserRef.current,
              isReadByPeer: last.is_read_by_peer,
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

  useEffect(() => {
    void loadDirectoryPeers(searchQuery);
  }, [activeUsername, loadDirectoryPeers, searchQuery]);

  useEffect(() => {
    if (selectedPeer) {
      void loadChatHistory(selectedPeer);
    }
  }, [selectedPeer, activeUsername, loadChatHistory]);

  // Автопрокрутка ТОЛЬКО когда в чате реально есть сообщения (не вызывает скролл на пустом чате)
  useEffect(() => {
    if (messages.length > 0) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [messages.length, selectedPeer]);

  // Подключение бинарного WebSocket (`/ws`, `binaryType = "arraybuffer"`)
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
        const hello = encodeWsProtoEvent({
          event_type: "presence_online",
          sender: activeUserRef.current,
          recipient: "online",
          wire_bytes_len: 0,
          timestamp_ms: Date.now(),
        });
        ws.send(hello);
      };

      ws.onmessage = (event) => {
        if (!alive) return;
        if (event.data instanceof ArrayBuffer) {
          const ev = decodeWsProtoEvent(event.data);
          if (!ev) return;

          if (ev.event_type === "presence_changed") {
            const isNowOnline = ev.recipient === "online";
            setDirectoryPeers((prev) =>
              prev.map((p) =>
                p.username === ev.sender
                  ? {
                      ...p,
                      is_online: isNowOnline,
                      last_seen_ms: ev.timestamp_ms || Date.now(),
                    }
                  : p
              )
            );
            return;
          }

          if (ev.event_type === "new_message") {
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
  }, [loadChatHistory, loadDirectoryPeers, searchQuery]);

  // Выбор собеседника из поиска или списка чатов
  const handleSelectChat = (peerUsername: string) => {
    setActiveChatPeers((prev) =>
      prev.includes(peerUsername) ? prev : [peerUsername, ...prev]
    );
    setSelectedPeer(peerUsername);
    if (searchQuery.trim()) {
      setSearchQuery("");
    }
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
        await loadChatHistory(selectedPeer);
      }
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

  const activePeerObj = directoryPeers.find((p) => p.username === selectedPeer);

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

  // Когда пользователь вводит текст в «Поиск» — показываем найденных юзеров; иначе — только активные личные чаты
  const isSearching = searchQuery.trim().length > 0;
  const visibleChats = directoryPeers.filter((p) => {
    if (isSearching) {
      const q = searchQuery.trim().replace(/^@/, "").toLowerCase();
      return (
        p.username.toLowerCase().includes(q) ||
        p.display_name.toLowerCase().includes(q)
      );
    }
    return activeChatPeers.includes(p.username);
  });

  return (
    <div
      className={cn(
        "relative flex h-full w-full overflow-hidden select-none p-3 gap-3",
        isDark ? "bg-[#09090b] text-zinc-100" : "bg-[#f2f2f7] text-zinc-900"
      )}
    >
      {/* Единый сплошной бесшовный фон на ВЕСЬ экран (под плавающей левой капсулой и правой областью) */}
      <div
        className="pointer-events-none fixed inset-0 z-0"
        style={{
          backgroundImage: `url(${chatWallpaperMutedUrl})`,
          backgroundSize: "cover",
          backgroundRepeat: "no-repeat",
          backgroundPosition: "center",
          opacity: isDark ? 0.94 : 0.12,
          filter: isDark ? "none" : "invert(1)",
        }}
      />

      {/* =====================================================================
          ЛЕВАЯ ПЛАВАЮЩАЯ КАПСУЛА-ОСТРОВ (как в Telegram Web на ПК, не прижата к краям)
          ===================================================================== */}
      <aside
        className={cn(
          "relative z-20 flex h-full w-[360px] shrink-0 flex-col overflow-hidden rounded-[24px] border shadow-2xl backdrop-blur-xl",
          isDark
            ? "border-zinc-800/80 bg-[#15151b]/95"
            : "border-zinc-200/90 bg-white/95"
        )}
      >
        {/* Верхняя строка поиска внутри плавающего острова */}
        <div className="shrink-0 px-3 pt-3 pb-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Поиск"
              aria-label="Поиск"
              className={cn(
                "h-9 w-full rounded-full border pr-8 pl-10 text-xs outline-none transition-colors",
                isDark
                  ? "border-zinc-800/90 bg-[#202028] text-zinc-100 placeholder:text-zinc-400 focus:border-zinc-700"
                  : "border-zinc-200/80 bg-zinc-100 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-300 focus:bg-white"
              )}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className="absolute top-1/2 right-3 -translate-y-1/2 text-zinc-400 hover:text-zinc-200 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Список личных чатов или пустое состояние с маскотами */}
        <div
          className={cn(
            "flex-1 px-2 pb-3",
            visibleChats.length === 0 ? "overflow-hidden" : "overflow-y-auto"
          )}
        >
          {visibleChats.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center px-6 text-center">
              <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
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
                  {isSearching ? "Ничего не найдено" : "Нет сообщений"}
                </h3>
                <p className="mt-1 text-xs text-zinc-500">
                  {isSearching
                    ? "Попробуйте другой запрос"
                    : "Начните переписку первым"}
                </p>
              </motion.div>
            </div>
          ) : (
            <div className="space-y-0.5 pt-0.5">
              {visibleChats.map((peer) => {
                const isSelected = peer.username === selectedPeer;
                const unread = unreadByPeer[peer.username] ?? 0;
                const isTyping = Boolean(peerTyping[peer.username]);
                const summary = chatSummaries[peer.username];

                return (
                  <button
                    key={peer.username}
                    type="button"
                    onClick={() => handleSelectChat(peer.username)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-2xl px-2.5 py-2 text-left transition-colors cursor-pointer",
                      isSelected
                        ? "bg-[#2b5278] text-white"
                        : isDark
                          ? "text-zinc-200 hover:bg-zinc-800/45"
                          : "text-zinc-800 hover:bg-zinc-100"
                    )}
                  >
                    <div
                      className={cn(
                        "relative flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-gradient-to-br text-sm font-bold text-white shadow-xs",
                        avatarGradientFor(peer.username)
                      )}
                    >
                      {initials(peer.display_name || peer.username)}
                      {peer.is_online && (
                        <span
                          className={cn(
                            "absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 bg-emerald-500",
                            isSelected
                              ? "border-[#2b5278]"
                              : isDark
                                ? "border-[#15151b]"
                                : "border-white"
                          )}
                        />
                      )}
                    </div>

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
      </aside>

      {/* =====================================================================
          ПРАВАЯ ОБЛАСТЬ ЧАТА (поверх единого бесшовного фона)
          ===================================================================== */}
      <main className="relative z-10 flex h-full flex-1 flex-col overflow-hidden">
        {!activePeerObj ? (
          <div className="relative z-10 flex flex-1 items-center justify-center p-6">
            <div
              className={cn(
                "rounded-full px-4 py-1.5 text-xs font-medium shadow-lg backdrop-blur-md",
                isDark
                  ? "bg-[#352942]/75 text-purple-100/90"
                  : "border border-zinc-200/90 bg-white/90 text-zinc-700"
              )}
            >
              Выберите, кому хотели бы написать
            </div>
          </div>
        ) : (
          <>
            {/* Плавающая капсула собеседника сверху по центру */}
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
                  ) : activePeerObj.is_online ? (
                    <span className="font-medium text-emerald-400">в сети</span>
                  ) : (
                    "был(а) недавно"
                  )}
                </span>
              </div>
            </header>

            {/* Область сообщений (при пустом чате overflow-hidden — никакого скроллбара!) */}
            <div
              className={cn(
                "relative z-10 flex-1 px-8 py-4 space-y-2",
                messages.length === 0 ? "overflow-hidden" : "overflow-y-auto"
              )}
            >
              {messages.map((m) => {
                const isMine = m.sender_username === activeUsername;

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
                          "mt-1 flex items-center justify-end gap-1 text-[10px]",
                          isMine ? "text-sky-100/75" : "text-zinc-400"
                        )}
                      >
                        <span>{formatShortTime(m.timestamp_ms)}</span>

                        {isMine &&
                          (m.is_read_by_peer ? (
                            <span
                              title="Прочитано"
                              className="inline-flex"
                            >
                              <CheckCheck className="h-3.5 w-3.5 text-sky-300" />
                            </span>
                          ) : (
                            <span title="Отправлено" className="inline-flex">
                              <Check className="h-3.5 w-3.5 opacity-75" />
                            </span>
                          ))}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            {/* Нижняя капсула ввода: при наборе текста плавно расширяется вправо каплей и внутри появляется кнопка отправки */}
            <footer className="relative z-10 shrink-0 px-8 pb-5 pt-2">
              <form
                onSubmit={handleSendMessage}
                className="mx-auto flex w-full max-w-[640px] items-center justify-center"
              >
                <motion.div
                  layout
                  initial={false}
                  animate={{
                    width: messageInput.trim().length > 0 ? 624 : 568,
                    paddingRight: messageInput.trim().length > 0 ? 6 : 20,
                  }}
                  transition={{
                    type: "spring",
                    stiffness: 380,
                    damping: 26,
                    mass: 0.72,
                  }}
                  style={{ originX: 0 }}
                  className={cn(
                    "relative flex h-11 max-w-full items-center overflow-hidden rounded-full border pl-5 shadow-lg backdrop-blur-xl",
                    isDark
                      ? "border-zinc-800/90 bg-[#17171f]/92"
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
                      "h-full min-w-0 flex-1 bg-transparent text-sm outline-none",
                      isDark
                        ? "text-zinc-100 placeholder:text-zinc-500"
                        : "text-zinc-900 placeholder:text-zinc-400"
                    )}
                  />

                  <AnimatePresence initial={false}>
                    {messageInput.trim().length > 0 && (
                      <motion.button
                        key="liquid-send-btn"
                        type="submit"
                        disabled={sending}
                        aria-label="Отправить сообщение"
                        initial={{
                          width: 0,
                          opacity: 0,
                          scale: 0.15,
                          x: 18,
                          marginLeft: 0,
                          filter: "blur(5px)",
                        }}
                        animate={{
                          width: 32,
                          opacity: 1,
                          scale: 1,
                          x: 0,
                          marginLeft: 8,
                          filter: "blur(0px)",
                        }}
                        exit={{
                          width: 0,
                          opacity: 0,
                          scale: 0.15,
                          x: 16,
                          marginLeft: 0,
                          filter: "blur(5px)",
                        }}
                        transition={{
                          type: "spring",
                          stiffness: 430,
                          damping: 24,
                          mass: 0.62,
                        }}
                        whileTap={{ scale: 0.9 }}
                        className="flex h-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-sky-500 text-white shadow-md hover:bg-sky-400 cursor-pointer"
                      >
                        {sending ? (
                          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                        ) : (
                          <Send className="h-3.5 w-3.5 shrink-0 -translate-x-[0.5px] translate-y-[0.5px]" />
                        )}
                      </motion.button>
                    )}
                  </AnimatePresence>
                </motion.div>
              </form>
            </footer>
          </>
        )}
      </main>
    </div>
  );
};
