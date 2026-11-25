import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  Check,
  CheckCheck,
  Code2,
  Cpu,
  Database,
  HardDrive,
  KeyRound,
  Laptop,
  Loader2,
  Lock,
  LogOut,
  MessageSquareLock,
  Moon,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Sigma,
  Sparkles,
  Sun,
  UserCheck,
  Users,
  X,
} from "lucide-react";
import {
  TelegramPatternWallpapers,
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

interface MessengerWorkspaceProps {
  activeUsername: string;
  theme: "dark" | "light";
  wallpaper: WallpaperVariant;
  onChangeWallpaper: (w: WallpaperVariant) => void;
  onToggleTheme: (e: React.MouseEvent<HTMLButtonElement>) => void;
  onSwitchAccount: (username: string) => void;
  onLogout: () => void;
}

export const MessengerWorkspace: React.FC<MessengerWorkspaceProps> = ({
  activeUsername,
  theme,
  wallpaper,
  onChangeWallpaper,
  onToggleTheme,
  onSwitchAccount,
  onLogout,
}) => {
  const isDark = theme === "dark";

  const [allProfiles, setAllProfiles] = useState<ClientDirectoryPeer[]>([]);
  const [directoryPeers, setDirectoryPeers] = useState<ClientDirectoryPeer[]>([]);
  const [selectedPeer, setSelectedPeer] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const [messages, setMessages] = useState<ClientDecryptedMessageItem[]>([]);
  const [channelIdHex, setChannelIdHex] = useState<string>("");
  const [messageInput, setMessageInput] = useState<string>("");
  const [sending, setSending] = useState<boolean>(false);

  const [expandedMsgId, setExpandedMsgId] = useState<string | null>(null);
  const [showInspector, setShowInspector] = useState<boolean>(false);
  const [syncingDevice, setSyncingDevice] = useState<boolean>(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  // Метрики хранилища и протокола, приходящие по бинарному Protobuf
  const [metrics, setMetrics] = useState({
    l1Hits: 0,
    l2Reads: 0,
    diskCommits: 0,
    recordsWritten: 0,
    absorbedFailures: 0,
    lastWireBytes: 0,
  });

  // Индикатор набора текста и непрочитанных сообщений по бинарному WebSocket
  const [peerTyping, setPeerTyping] = useState<Record<string, number>>({});
  const [unreadByPeer, setUnreadByPeer] = useState<Record<string, number>>({});
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);
  const selectedPeerRef = useRef<string>("");
  const activeUserRef = useRef<string>(activeUsername);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const lastTypingSentRef = useRef<number>(0);

  selectedPeerRef.current = selectedPeer;
  activeUserRef.current = activeUsername;

  const showToast = useCallback((text: string) => {
    setToastMsg(text);
    window.setTimeout(() => {
      setToastMsg((prev) => (prev === text ? null : prev));
    }, 3500);
  }, []);

  // 1. Загрузка состояния узла и списка профилей по бинарному Protobuf
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
      // Игнорируем временную сетевую ошибку при опросе
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
          if (!selectedPeerRef.current && others.length > 0) {
            setSelectedPeer(others[0].username);
          }
        }
      } catch {
        // Fallback на локальные профили
      }
    },
    []
  );

  // 3. Загрузка и локальная E2EE-расшифровка истории чата по бинарному Protobuf
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
        // Отмечаем чат прочитанным по бинарному Protobuf
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
      // Игнорируем ошибку
    }
  }, []);

  // Инициализация при смене активного пользователя
  useEffect(() => {
    refreshState();
    loadDirectoryPeers(searchQuery);
  }, [activeUsername, refreshState, loadDirectoryPeers, searchQuery]);

  // Загрузка истории при выборе собеседника
  useEffect(() => {
    if (selectedPeer) {
      loadChatHistory(selectedPeer);
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
            refreshState();
            const currentActive = activeUserRef.current;
            const currentPeer = selectedPeerRef.current;
            if (
              (ev.sender === currentPeer && ev.recipient === currentActive) ||
              (ev.sender === currentActive && ev.recipient === currentPeer)
            ) {
              loadChatHistory(currentPeer);
            } else if (ev.recipient === currentActive) {
              setUnreadByPeer((prev) => ({
                ...prev,
                [ev.sender]: (prev[ev.sender] ?? 0) + 1,
              }));
            }
          } else if (ev.event_type === "read_receipt") {
            const currentPeer = selectedPeerRef.current;
            if (ev.sender === currentPeer || ev.recipient === currentPeer) {
              loadChatHistory(currentPeer);
            }
          } else if (ev.event_type === "user_registered") {
            refreshState();
            loadDirectoryPeers(searchQuery);
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

    // Очистка устаревших статусов набора текста
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
          `Устройство #${resp.device_number} синхронизировано через CloudKeyVault (${resp.wire_bytes_len} байт Protobuf)`
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

  const formatTime = (ms: number) => {
    if (!ms) return "";
    const d = new Date(ms);
    return d.toLocaleTimeString("ru-RU", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div
      className={cn(
        "relative flex h-screen w-screen overflow-hidden select-none transition-colors duration-200",
        isDark ? "bg-[#09090b] text-zinc-100" : "bg-[#f4f4f5] text-zinc-900"
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
              "fixed top-4 left-1/2 z-50 -translate-x-1/2 flex items-center gap-2.5 rounded-xl border px-4 py-2.5 text-xs font-medium shadow-2xl backdrop-blur-md",
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

      {/* ЛЕВАЯ ПАНЕЛЬ КОНТАКТОВ И ПРОФИЛЯ */}
      <aside
        className={cn(
          "z-20 flex w-[340px] shrink-0 flex-col border-r transition-colors",
          isDark
            ? "border-zinc-800/80 bg-[#111114]/95"
            : "border-zinc-200/90 bg-white/95"
        )}
      >
        {/* Шапка активного сотрудника */}
        <div
          className={cn(
            "flex flex-col gap-3 border-b p-4",
            isDark ? "border-zinc-800/80" : "border-zinc-200/80"
          )}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-3 min-w-0">
              <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 text-xs font-bold text-white shadow-sm">
                {initials(currentProfile.display_name || currentProfile.username)}
                <span
                  className={cn(
                    "absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2",
                    isDark ? "border-[#111114]" : "border-white",
                    wsConnected ? "bg-emerald-500" : "bg-amber-500"
                  )}
                  title={
                    wsConnected
                      ? "Бинарный WebSocket Protobuf активен"
                      : "Переподключение..."
                  }
                />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <h2 className="truncate text-sm font-semibold">
                    {currentProfile.display_name}
                  </h2>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-zinc-500">
                  <span className="truncate font-mono">@{currentProfile.username}</span>
                  <span>•</span>
                  <span>Устр. #{currentProfile.device_number || 1}</span>
                  <span>•</span>
                  <span>Сейф v{currentProfile.vault_version || 1}</span>
                </div>
              </div>
            </div>

            {/* Кнопки управления темой (с волной), облачным сейфом, статусом и выходом */}
            <div className="flex items-center gap-1 shrink-0">
              <button
                type="button"
                onClick={handleCloudSyncDevice}
                disabled={syncingDevice}
                title="Синхронизировать новое устройство через Zero-Knowledge CloudKeyVault"
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-lg border transition-colors cursor-pointer",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:bg-zinc-800 hover:text-white"
                    : "border-zinc-200 bg-zinc-100/80 text-zinc-700 hover:bg-zinc-200 hover:text-zinc-950"
                )}
              >
                {syncingDevice ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Laptop className="h-3.5 w-3.5" />
                )}
              </button>

              <a
                href="/status"
                target="_blank"
                rel="noreferrer"
                title="Мониторинг микросервисов и Circuit Breakers (/status)"
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-lg border transition-colors",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:bg-zinc-800 hover:text-white"
                    : "border-zinc-200 bg-zinc-100/80 text-zinc-700 hover:bg-zinc-200 hover:text-zinc-950"
                )}
              >
                <Activity className="h-3.5 w-3.5" />
              </a>

              <button
                type="button"
                onClick={onToggleTheme}
                title={
                  isDark
                    ? "Светлая тема (волна из правого верхнего угла)"
                    : "Тёмная тема (волна из правого верхнего угла)"
                }
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-lg border transition-colors cursor-pointer",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:bg-zinc-800 hover:text-white"
                    : "border-zinc-200 bg-zinc-100/80 text-zinc-700 hover:bg-zinc-200 hover:text-zinc-950"
                )}
              >
                {isDark ? (
                  <Sun className="h-3.5 w-3.5" />
                ) : (
                  <Moon className="h-3.5 w-3.5" />
                )}
              </button>

              <button
                type="button"
                onClick={onLogout}
                title="Выйти на экран авторизации"
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-lg border transition-colors cursor-pointer",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/80 text-zinc-400 hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400"
                    : "border-zinc-200 bg-zinc-100/80 text-zinc-600 hover:border-red-300 hover:bg-red-50 hover:text-red-600"
                )}
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Переключатель тематического паттерна обоев (Космос / Математика / Кибер) */}
          <div className="flex items-center justify-between gap-1.5">
            <div
              className={cn(
                "flex flex-1 items-center rounded-lg border p-0.5 text-[11px]",
                isDark
                  ? "border-zinc-800/90 bg-zinc-900/70"
                  : "border-zinc-200/90 bg-zinc-100/80"
              )}
            >
              {(
                [
                  { id: "space", label: "Космос", icon: Sparkles },
                  { id: "math", label: "Математика", icon: Sigma },
                  { id: "cyber", label: "Кибер", icon: Cpu },
                ] as const
              ).map((item) => {
                const Icon = item.icon;
                const active = wallpaper === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onChangeWallpaper(item.id)}
                    className={cn(
                      "flex flex-1 items-center justify-center gap-1 rounded-md py-1 font-medium transition-all cursor-pointer",
                      active
                        ? isDark
                          ? "bg-zinc-800 text-white shadow-xs"
                          : "bg-white text-zinc-900 shadow-xs"
                        : isDark
                          ? "text-zinc-400 hover:text-zinc-200"
                          : "text-zinc-600 hover:text-zinc-900"
                    )}
                  >
                    <Icon className="h-3 w-3" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Поиск по корпоративному каталогу `user-directory-svc` (Protobuf) */}
        <div className="p-3">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Поиск сотрудников (@username)..."
              aria-label="Поиск сотрудников"
              className={cn(
                "h-9 w-full rounded-xl border pr-8 pl-9 text-xs outline-none transition-all",
                isDark
                  ? "border-zinc-800 bg-zinc-900/90 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-700"
                  : "border-zinc-200 bg-zinc-100/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-300 focus:bg-white"
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

        {/* Список диалогов / сотрудников */}
        <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-1">
          <div className="flex items-center justify-between px-2 py-1 text-[10px] font-semibold tracking-wider uppercase text-zinc-500">
            <span className="flex items-center gap-1.5">
              <Users className="h-3 w-3" />
              Защищённые каналы ({directoryPeers.length})
            </span>
            <span className="font-mono text-[10px] text-emerald-500">Protobuf v3</span>
          </div>

          {directoryPeers.map((peer) => {
            const isSelected = peer.username === selectedPeer;
            const unread = unreadByPeer[peer.username] ?? 0;
            const isTyping = Boolean(peerTyping[peer.username]);

            return (
              <motion.button
                key={peer.username}
                type="button"
                whileTap={{ scale: 0.99 }}
                onClick={() => setSelectedPeer(peer.username)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-all cursor-pointer",
                  isSelected
                    ? isDark
                      ? "bg-zinc-800/90 text-white shadow-sm"
                      : "bg-zinc-900 text-white shadow-sm"
                    : isDark
                      ? "text-zinc-300 hover:bg-zinc-800/40"
                      : "text-zinc-700 hover:bg-zinc-100"
                )}
              >
                <div
                  className={cn(
                    "relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-xs font-bold",
                    isSelected
                      ? "bg-indigo-500 text-white"
                      : isDark
                        ? "bg-zinc-800 text-zinc-200"
                        : "bg-zinc-200 text-zinc-800"
                  )}
                >
                  {initials(peer.display_name || peer.username)}
                  <span
                    className={cn(
                      "absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 bg-emerald-500",
                      isSelected
                        ? "border-zinc-900"
                        : isDark
                          ? "border-[#111114]"
                          : "border-white"
                    )}
                  />
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-1">
                    <span className="truncate text-xs font-semibold">
                      {peer.display_name}
                    </span>
                    <span
                      className={cn(
                        "shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px]",
                        isSelected
                          ? "bg-white/15 text-zinc-200"
                          : isDark
                            ? "bg-zinc-800 text-zinc-400"
                            : "bg-zinc-200/80 text-zinc-600"
                      )}
                    >
                      KT #{peer.transparency_seq || 1}
                    </span>
                  </div>

                  <div className="mt-0.5 flex items-center justify-between gap-2">
                    {isTyping ? (
                      <span className="truncate text-[11px] font-medium text-emerald-400">
                        печатает...
                      </span>
                    ) : (
                      <span
                        className={cn(
                          "truncate font-mono text-[11px]",
                          isSelected
                            ? "text-zinc-300"
                            : isDark
                              ? "text-zinc-500"
                              : "text-zinc-500"
                        )}
                      >
                        @{peer.username}
                      </span>
                    )}

                    {unread > 0 && (
                      <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-indigo-500 px-1.5 text-[10px] font-bold text-white">
                        {unread}
                      </span>
                    )}
                  </div>
                </div>
              </motion.button>
            );
          })}
        </div>

        {/* Нижний блок быстрого переключения локальной сессии для проверки двустороннего чата */}
        <div
          className={cn(
            "border-t p-3",
            isDark
              ? "border-zinc-800/80 bg-zinc-900/40"
              : "border-zinc-200/80 bg-zinc-50/80"
          )}
        >
          <div className="mb-1.5 flex items-center justify-between text-[10px] font-medium text-zinc-500">
            <span className="flex items-center gap-1">
              <UserCheck className="h-3 w-3" />
              Быстрая смена активного анклава
            </span>
            <span className="font-mono">E2EE</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {allProfiles.map((u) => {
              const active = u.username === activeUsername;
              return (
                <button
                  key={u.username}
                  type="button"
                  onClick={() => onSwitchAccount(u.username)}
                  className={cn(
                    "rounded-lg px-2 py-1 font-mono text-[10px] font-medium transition-all cursor-pointer",
                    active
                      ? isDark
                        ? "bg-white text-zinc-950 shadow-xs"
                        : "bg-zinc-900 text-white shadow-xs"
                      : isDark
                        ? "bg-zinc-800/80 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                        : "bg-zinc-200/70 text-zinc-700 hover:bg-zinc-200"
                  )}
                >
                  @{u.username}
                </button>
              );
            })}
          </div>
        </div>
      </aside>

      {/* ЦЕНТРАЛЬНАЯ ОБЛАСТЬ ЧАТА С ФОНОМ TELEGRAM SVG */}
      <main className="relative flex flex-1 flex-col overflow-hidden">
        {/* Бесшовные статичные обои в стиле Telegram */}
        <TelegramPatternWallpapers variant={wallpaper} theme={theme} />

        {/* Верхняя панель открытого диалога */}
        <header
          className={cn(
            "relative z-10 flex h-16 shrink-0 items-center justify-between border-b px-6 backdrop-blur-xl transition-colors",
            isDark
              ? "border-zinc-800/80 bg-[#111114]/85"
              : "border-zinc-200/80 bg-white/85"
          )}
        >
          {activePeerObj ? (
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/15 font-bold text-xs text-indigo-400 border border-indigo-500/30">
                {initials(activePeerObj.display_name || activePeerObj.username)}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-sm font-semibold">
                    {activePeerObj.display_name}
                  </h1>
                  <span className="font-mono text-xs text-zinc-500">
                    @{activePeerObj.username}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-zinc-500">
                  {peerTyping[activePeerObj.username] ? (
                    <span className="font-medium text-emerald-400">
                      печатает зашифрованный пакет...
                    </span>
                  ) : (
                    <>
                      <Lock className="h-3 w-3 text-emerald-500" />
                      <span>
                        X25519 + XChaCha20-Poly1305 • Ed25519 • Binary Protobuf
                      </span>
                    </>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-zinc-500">
              Выберите сотрудника в списке слева
            </div>
          )}

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => selectedPeer && loadChatHistory(selectedPeer)}
              title="Обновить историю из зашифрованного хранилища"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-xl border transition-colors cursor-pointer",
                isDark
                  ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:bg-zinc-800"
                  : "border-zinc-200 bg-zinc-100/80 text-zinc-700 hover:bg-zinc-200"
              )}
            >
              <RefreshCw className="h-4 w-4" />
            </button>

            <button
              type="button"
              onClick={() => setShowInspector((v) => !v)}
              className={cn(
                "flex h-9 items-center gap-2 rounded-xl border px-3 text-xs font-medium transition-colors cursor-pointer",
                showInspector
                  ? isDark
                    ? "border-indigo-500/50 bg-indigo-500/15 text-indigo-300"
                    : "border-indigo-300 bg-indigo-50 text-indigo-700"
                  : isDark
                    ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:bg-zinc-800"
                    : "border-zinc-200 bg-zinc-100/80 text-zinc-700 hover:bg-zinc-200"
              )}
            >
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              <span>Инспектор Protobuf</span>
            </button>
          </div>
        </header>

        {/* Поток сообщений */}
        <div className="relative z-10 flex-1 overflow-y-auto px-6 py-5 space-y-3">
          {messages.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center">
              <div
                className={cn(
                  "max-w-sm rounded-2xl border p-6 shadow-xl backdrop-blur-xl",
                  isDark
                    ? "border-zinc-800/90 bg-[#141418]/90"
                    : "border-zinc-200/90 bg-white/90"
                )}
              >
                <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-2xl bg-indigo-500/15 text-indigo-400">
                  <MessageSquareLock className="h-5 w-5" />
                </div>
                <h3 className="text-sm font-semibold">
                  Сквозное шифрование Zero-Knowledge
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">
                  Все сообщения шифруются на клиенте алгоритмом{" "}
                  <span className="font-mono text-zinc-400">XChaCha20-Poly1305</span>,
                  подписываются ключом{" "}
                  <span className="font-mono text-zinc-400">Ed25519</span> и
                  передаются исключительно в бинарном формате{" "}
                  <span className="font-mono text-zinc-400">Protobuf</span>.
                </p>
              </div>
            </div>
          ) : (
            messages.map((m) => {
              const isMine = m.sender_username === activeUsername;
              const isExpanded = expandedMsgId === m.message_id_short;

              return (
                <motion.div
                  key={`${m.message_id_short}-${m.ratchet_step}`}
                  initial={{ opacity: 0, y: 10, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
                  className={cn(
                    "flex flex-col",
                    isMine ? "items-end" : "items-start"
                  )}
                >
                  <div
                    className={cn(
                      "max-w-xl rounded-2xl border px-4 py-2.5 shadow-md backdrop-blur-md transition-all",
                      isMine
                        ? isDark
                          ? "border-indigo-500/30 bg-indigo-600/90 text-white"
                          : "border-zinc-800 bg-zinc-900 text-white"
                        : isDark
                          ? "border-zinc-800/90 bg-[#16161b]/95 text-zinc-100"
                          : "border-zinc-200/90 bg-white/95 text-zinc-900"
                    )}
                  >
                    <p className="text-[13px] leading-relaxed whitespace-pre-wrap break-words">
                      {m.decrypted_text}
                    </p>

                    <div
                      className={cn(
                        "mt-1.5 flex items-center justify-end gap-2 text-[10px]",
                        isMine
                          ? "text-indigo-100/80"
                          : isDark
                            ? "text-zinc-400"
                            : "text-zinc-500"
                      )}
                    >
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedMsgId(isExpanded ? null : m.message_id_short)
                        }
                        title="Показать бинарный конверт EncryptedEnvelope (Protobuf)"
                        className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono hover:bg-black/15 cursor-pointer"
                      >
                        <Code2 className="h-3 w-3" />
                        <span>
                          Шаг #{m.ratchet_step} • {m.wire_bytes_len} B
                        </span>
                      </button>

                      <span>{formatTime(m.timestamp_ms)}</span>

                      {isMine &&
                        (m.is_read_by_peer ? (
                          <CheckCheck
                            className="h-3.5 w-3.5 text-emerald-300"
                            title="Прочитано собеседником"
                          />
                        ) : (
                          <Check
                            className="h-3.5 w-3.5 opacity-75"
                            title="Доставлено в B+Tree индекс"
                          />
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
                          <div className="mt-2 space-y-1 rounded-xl bg-black/30 p-2.5 font-mono text-[10px] text-zinc-200">
                            <div>
                              <span className="text-zinc-400">UUIDv7:</span>{" "}
                              {m.message_id_short}
                            </div>
                            <div>
                              <span className="text-zinc-400">Nonce (192-bit):</span>{" "}
                              {m.nonce_hex}
                            </div>
                            <div className="truncate">
                              <span className="text-zinc-400">Ciphertext:</span>{" "}
                              {m.ciphertext_hex}
                            </div>
                            <div className="truncate">
                              <span className="text-zinc-400">Ed25519 Sig:</span>{" "}
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

        {/* Нижняя панель ввода и отправки сообщения по бинарному Protobuf */}
        <footer
          className={cn(
            "relative z-10 border-t px-6 py-3.5 backdrop-blur-xl",
            isDark
              ? "border-zinc-800/80 bg-[#111114]/90"
              : "border-zinc-200/80 bg-white/90"
          )}
        >
          <form onSubmit={handleSendMessage} className="flex items-center gap-3">
            <input
              type="text"
              value={messageInput}
              onChange={(e) => handleInputTyping(e.target.value)}
              placeholder={
                selectedPeer
                  ? `Зашифрованное сообщение для @${selectedPeer} (Protobuf)...`
                  : "Выберите собеседника..."
              }
              aria-label="Текст сообщения"
              disabled={!selectedPeer || sending}
              className={cn(
                "h-11 flex-1 rounded-xl border px-4 text-sm outline-none transition-all",
                isDark
                  ? "border-zinc-800 bg-zinc-900/90 text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-700"
                  : "border-zinc-200 bg-zinc-100/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-300 focus:bg-white"
              )}
            />
            <button
              type="submit"
              disabled={!selectedPeer || !messageInput.trim() || sending}
              className={cn(
                "flex h-11 items-center gap-2 rounded-xl px-5 text-xs font-semibold transition-all cursor-pointer disabled:opacity-40",
                isDark
                  ? "bg-white text-zinc-950 hover:bg-zinc-200"
                  : "bg-zinc-900 text-white hover:bg-zinc-800"
              )}
            >
              {sending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <span>Отправить</span>
                  <Send className="h-3.5 w-3.5" />
                </>
              )}
            </button>
          </form>
        </footer>
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
                ? "border-zinc-800/80 bg-[#111114]/95"
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
                <div className="flex items-center gap-1.5 font-semibold text-indigo-400">
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
