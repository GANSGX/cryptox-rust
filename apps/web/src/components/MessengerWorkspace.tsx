import React, { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Check,
  CheckCheck,
  ChevronDown,
  Copy,
  Pencil,
  Reply,
  Search,
  Trash2,
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

interface MessageContextMenuState {
  x: number;
  y: number;
  message: ClientDecryptedMessageItem;
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

const GROUP_WINDOW_MS = 5 * 60 * 1000;

function isSameCalendarDay(tsA: number, tsB: number): boolean {
  if (!tsA || !tsB) return false;
  const a = new Date(tsA);
  const b = new Date(tsB);
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function formatDateSeparatorLabel(tsMs: number): string {
  if (!tsMs) return "Сегодня";
  const target = new Date(tsMs);
  const now = new Date();
  if (isSameCalendarDay(tsMs, now.getTime())) {
    return "Сегодня";
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (isSameCalendarDay(tsMs, yesterday.getTime())) {
    return "Вчера";
  }
  const sameYear = target.getFullYear() === now.getFullYear();
  return target.toLocaleDateString(
    "ru-RU",
    sameYear
      ? { day: "numeric", month: "long" }
      : { day: "numeric", month: "long", year: "numeric" }
  );
}

function isGroupedWithAdjacent(
  a: ClientDecryptedMessageItem | undefined,
  b: ClientDecryptedMessageItem | undefined
): boolean {
  if (!a || !b) return false;
  if (a.sender_username !== b.sender_username) return false;
  if (!isSameCalendarDay(a.timestamp_ms, b.timestamp_ms)) return false;
  return Math.abs(b.timestamp_ms - a.timestamp_ms) <= GROUP_WINDOW_MS;
}

function getBubbleShapeClasses(
  isMine: boolean,
  isFirstInGroup: boolean,
  isLastInGroup: boolean
): string {
  if (isMine) {
    const topRight = isFirstInGroup ? "rounded-tr-[18px]" : "rounded-tr-[6px]";
    const bottomRight = isLastInGroup ? "rounded-br-[4px]" : "rounded-br-[6px]";
    return `rounded-l-[18px] ${topRight} ${bottomRight}`;
  }
  const topLeft = isFirstInGroup ? "rounded-tl-[18px]" : "rounded-tl-[6px]";
  const bottomLeft = isLastInGroup ? "rounded-bl-[4px]" : "rounded-bl-[6px]";
  return `rounded-r-[18px] ${topLeft} ${bottomLeft}`;
}

function getReplyQuoteClasses(isMine: boolean, isDark: boolean): string {
  if (isMine) {
    return "border-sky-300 bg-sky-950/35 hover:bg-sky-950/50";
  }
  if (isDark) {
    return "border-sky-400 bg-zinc-800/70 hover:bg-zinc-800";
  }
  return "border-sky-500 bg-sky-50 hover:bg-sky-100/80";
}

/**
 * Анимированный SVG-самолётик оригами:
 * при появлении кнопки раскладывает левое и правое крыло из центрального бумажного сгиба,
 * а при отправке — взлетает по диагонали вперёд.
 */
const OrigamiPaperPlaneIcon: React.FC = () => (
  <motion.svg
    width="17"
    height="17"
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className="shrink-0 overflow-visible"
    initial={{ scale: 0.45, rotate: -32, x: -4, y: 4 }}
    animate={{ scale: 1, rotate: 0, x: 0, y: 0 }}
    exit={{ scale: 0.55, x: 18, y: -18, opacity: 0 }}
    transition={{
      type: "spring",
      stiffness: 320,
      damping: 20,
      mass: 0.65,
    }}
  >
    {/* Внутренняя теневая складка фюзеляжа оригами */}
    <motion.path
      d="M21 3L9.6 14.4L12.1 20.2L15.2 16.1L21 3Z"
      fill="rgba(255,255,255,0.52)"
      initial={{ opacity: 0, scale: 0.3 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: 0.08, duration: 0.24, ease: "easeOut" }}
      style={{ transformOrigin: "14px 11px" }}
    />

    {/* Левое (верхнее) крыло — раскладывается вверх-влево из линии сгиба */}
    <motion.path
      d="M21 3L2.4 10.1L9.6 14.4L21 3Z"
      fill="rgba(255,255,255,0.96)"
      stroke="white"
      strokeWidth="1.15"
      strokeLinejoin="round"
      initial={{ rotate: 38, scaleY: 0.12, opacity: 0.15 }}
      animate={{ rotate: 0, scaleY: 1, opacity: 1 }}
      transition={{
        type: "spring",
        stiffness: 250,
        damping: 15,
        mass: 0.6,
        delay: 0.1,
      }}
      style={{ transformOrigin: "14px 10px" }}
    />

    {/* Правое (нижнее) крыло — раскладывается вниз-вправо из линии сгиба */}
    <motion.path
      d="M21 3L9.6 14.4L16.3 21.4L21 3Z"
      fill="rgba(255,255,255,0.82)"
      stroke="white"
      strokeWidth="1.15"
      strokeLinejoin="round"
      initial={{ rotate: -38, scaleX: 0.12, opacity: 0.15 }}
      animate={{ rotate: 0, scaleX: 1, opacity: 1 }}
      transition={{
        type: "spring",
        stiffness: 250,
        damping: 15,
        mass: 0.6,
        delay: 0.16,
      }}
      style={{ transformOrigin: "14px 10px" }}
    />

    {/* Центральный диагональный сгиб бумаги от хвоста к носу */}
    <motion.path
      d="M9.6 14.4L21 3"
      stroke="#0284c7"
      strokeWidth="1.35"
      strokeLinecap="round"
      initial={{ pathLength: 0, opacity: 0 }}
      animate={{ pathLength: 1, opacity: 0.85 }}
      transition={{ delay: 0.14, duration: 0.28, ease: "easeOut" }}
    />
  </motion.svg>
);

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
  const [isInitialChatsLoaded, setIsInitialChatsLoaded] = useState<boolean>(false);

  const [messages, setMessages] = useState<ClientDecryptedMessageItem[]>([]);
  const [messageInput, setMessageInput] = useState<string>("");

  // Контекстное меню ПКМ по сообщению, модалка удаления как в ТГ, состояния Ответа (Reply) и Редактирования (Edit)
  const [contextMenu, setContextMenu] =
    useState<MessageContextMenuState | null>(null);
  const [deleteModalMessage, setDeleteModalMessage] =
    useState<ClientDecryptedMessageItem | null>(null);
  const [deleteForEveryone, setDeleteForEveryone] = useState<boolean>(true);
  const [replyingToMessage, setReplyingToMessage] =
    useState<ClientDecryptedMessageItem | null>(null);
  const [editingMessage, setEditingMessage] =
    useState<ClientDecryptedMessageItem | null>(null);
  const [highlightedMessageId, setHighlightedMessageId] = useState<string>("");
  const [copiedToastVisible, setCopiedToastVisible] = useState<boolean>(false);

  // Индикатор набора текста и непрочитанных сообщений (бинарный WebSocket)
  const [peerTyping, setPeerTyping] = useState<Record<string, number>>({});
  const [unreadByPeer, setUnreadByPeer] = useState<Record<string, number>>({});
  const [showScrollToBottom, setShowScrollToBottom] = useState<boolean>(false);
  const [unseenBelowCount, setUnseenBelowCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const selectedPeerRef = useRef<string>("");
  const activeUserRef = useRef<string>(activeUsername);
  const messagesContainerRef = useRef<HTMLDivElement | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const messageInputRef = useRef<HTMLInputElement | null>(null);
  const isNearBottomRef = useRef<boolean>(true);
  const prevMessagesLenRef = useRef<number>(0);
  const lastTypingSentRef = useRef<number>(0);

  selectedPeerRef.current = selectedPeer;
  activeUserRef.current = activeUsername;

  // Параллельная подгрузка существующих переписок для формирования списка личных чатов без задержек
  const syncPeerSummaries = useCallback(async (peers: ClientDirectoryPeer[]) => {
    const caller = activeUserRef.current;
    if (!caller) return;
    const nextSummaries: Record<string, PeerChatSummary> = {};
    const peersWithHistory: string[] = [];

    await Promise.all(
      peers
        .filter((p) => p.username !== caller)
        .map(async (p) => {
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
        })
    );

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
          await syncPeerSummaries(others);
          setDirectoryPeers(others);
        } else if (resp.error_message.includes("не найден")) {
          onLogout?.();
        }
      } catch {
        // Игнорируем ошибку сети
      } finally {
        setIsInitialChatsLoaded(true);
      }
    },
    [onLogout, syncPeerSummaries]
  );

  // Загрузка и расшифровка истории выбранного личного чата по бинарному Protobuf
  const loadChatHistory = useCallback(
    async (peerUsername: string, shouldMarkRead = true) => {
      if (!peerUsername || !activeUserRef.current) return;
      try {
        const resp = await callClientWireProtobuf({
          op: ClientWireOp.FetchChatHistory,
          caller_username: activeUserRef.current,
          peer_username: peerUsername,
        });
        if (resp.ok) {
          setMessages(resp.messages);
          let hasIncomingFromPeer = false;
          if (resp.messages.length > 0) {
            const last = resp.messages[resp.messages.length - 1];
            hasIncomingFromPeer =
              last.sender_username !== activeUserRef.current;
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
          if (shouldMarkRead && hasIncomingFromPeer) {
            void callClientWireProtobuf({
              op: ClientWireOp.MarkChatRead,
              caller_username: activeUserRef.current,
              peer_username: peerUsername,
            });
          }
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
    },
    []
  );

  const scrollToBottom = useCallback((behavior: ScrollBehavior = "smooth") => {
    window.requestAnimationFrame(() => {
      const el = messagesContainerRef.current;
      if (el) {
        el.scrollTo({ top: el.scrollHeight, behavior });
      }
    });
    isNearBottomRef.current = true;
    setShowScrollToBottom(false);
    setUnseenBelowCount(0);
  }, []);

  const handleMessagesScroll = useCallback(() => {
    const el = messagesContainerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    const nearBottom = distanceFromBottom <= 130;
    isNearBottomRef.current = nearBottom;
    setShowScrollToBottom(!nearBottom);
    if (nearBottom) {
      setUnseenBelowCount(0);
    }
  }, []);

  // Если открылась плашка Ответа/Редактирования, поднимаем нижние сообщения над ней
  useEffect(() => {
    if ((replyingToMessage || editingMessage) && isNearBottomRef.current) {
      scrollToBottom("smooth");
    }
  }, [replyingToMessage, editingMessage, scrollToBottom]);

  useEffect(() => {
    void loadDirectoryPeers(searchQuery);
  }, [activeUsername, loadDirectoryPeers, searchQuery]);

  useEffect(() => {
    if (selectedPeer) {
      isNearBottomRef.current = true;
      prevMessagesLenRef.current = 0;
      setShowScrollToBottom(false);
      setUnseenBelowCount(0);
      setContextMenu(null);
      setReplyingToMessage(null);
      setEditingMessage(null);
      void loadChatHistory(selectedPeer);
    }
  }, [selectedPeer, activeUsername, loadChatHistory]);

  // Закрытие контекстного меню ПКМ по клику вне меню, скроллу или клавише Escape
  useEffect(() => {
    const handleGlobalClick = () => {
      setContextMenu(null);
    };
    const handleKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (deleteModalMessage) {
          setDeleteModalMessage(null);
        } else if (contextMenu) {
          setContextMenu(null);
        } else if (editingMessage) {
          setEditingMessage(null);
          setMessageInput("");
        } else if (replyingToMessage) {
          setReplyingToMessage(null);
        }
      }
    };
    window.addEventListener("click", handleGlobalClick);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("click", handleGlobalClick);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [contextMenu, deleteModalMessage, editingMessage, replyingToMessage]);

  // Умная автопрокрутка: скроллит вниз при открытии чата, отправке своего сообщения или если юзер уже внизу ленты
  useEffect(() => {
    const prevLen = prevMessagesLenRef.current;
    const currLen = messages.length;
    prevMessagesLenRef.current = currLen;

    if (currLen === 0) return;
    const lastMsg = messages[currLen - 1];
    const sentByMe = lastMsg?.sender_username === activeUsername;

    if (prevLen === 0 || sentByMe || isNearBottomRef.current) {
      scrollToBottom(prevLen === 0 ? "auto" : "smooth");
    } else if (currLen > prevLen) {
      setUnseenBelowCount((prev) => prev + (currLen - prevLen));
    }
  }, [messages, activeUsername, selectedPeer, scrollToBottom]);

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
            }

            if (
              (ev.sender === currentPeer && ev.recipient === currentActive) ||
              (ev.sender === currentActive && ev.recipient === currentPeer)
            ) {
              void loadChatHistory(currentPeer, ev.sender === currentPeer);
            } else if (ev.recipient === currentActive) {
              setUnreadByPeer((prev) => ({
                ...prev,
                [ev.sender]: (prev[ev.sender] ?? 0) + 1,
              }));
              void syncPeerSummaries([
                {
                  username: ev.sender,
                  display_name: ev.sender,
                  key_version: 1,
                  transparency_seq: 1,
                  ed25519_pub_hex_short: "",
                  x25519_pub_hex_short: "",
                  device_number: 1,
                  vault_version: 1,
                  is_online: true,
                  last_seen_ms: Date.now(),
                },
              ]);
            }
          } else if (ev.event_type === "read_receipt") {
            const currentPeer = selectedPeerRef.current;
            if (ev.sender === currentPeer || ev.recipient === currentPeer) {
              void loadChatHistory(currentPeer, false);
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

  const resolveSenderDisplayName = useCallback(
    (uname: string): string => {
      if (!uname) return "";
      if (uname === activeUsername) return "Вы";
      const found = directoryPeers.find((p) => p.username === uname);
      return found?.display_name || uname;
    },
    [activeUsername, directoryPeers]
  );

  // Открытие кастомного контекстного меню по правому клику (ПКМ) на баббл сообщения
  const handleMessageContextMenu = (
    e: React.MouseEvent,
    msg: ClientDecryptedMessageItem
  ) => {
    e.preventDefault();
    e.stopPropagation();
    const menuWidth = 196;
    const menuHeight = msg.sender_username === activeUsername ? 176 : 104;
    const clampedX = Math.max(
      16,
      Math.min(e.clientX, window.innerWidth - menuWidth - 16)
    );
    const clampedY = Math.max(
      16,
      Math.min(e.clientY, window.innerHeight - menuHeight - 16)
    );
    setContextMenu({
      x: clampedX,
      y: clampedY,
      message: msg,
    });
  };

  const handleStartReply = (msg: ClientDecryptedMessageItem) => {
    setContextMenu(null);
    setEditingMessage(null);
    setReplyingToMessage(msg);
    window.setTimeout(() => {
      messageInputRef.current?.focus();
    }, 10);
  };

  const handleCopyMessageText = (msg: ClientDecryptedMessageItem) => {
    setContextMenu(null);
    if (navigator.clipboard) {
      navigator.clipboard
        .writeText(msg.decrypted_text)
        .then(() => {
          setCopiedToastVisible(true);
          window.setTimeout(() => setCopiedToastVisible(false), 1800);
        })
        .catch(() => {});
    }
  };

  const handleStartEdit = (msg: ClientDecryptedMessageItem) => {
    setContextMenu(null);
    if (msg.sender_username !== activeUsername) return;
    setReplyingToMessage(null);
    setEditingMessage(msg);
    setMessageInput(msg.decrypted_text);
    window.setTimeout(() => {
      messageInputRef.current?.focus();
    }, 10);
  };

  const handleOpenDeleteModal = (msg: ClientDecryptedMessageItem) => {
    setContextMenu(null);
    setDeleteForEveryone(true);
    setDeleteModalMessage(msg);
  };

  const handleConfirmDeleteMessage = async () => {
    const msg = deleteModalMessage;
    const forEveryone = deleteForEveryone;
    setDeleteModalMessage(null);
    const peer = selectedPeer;
    if (!msg || !peer) return;

    if (replyingToMessage?.message_id_short === msg.message_id_short) {
      setReplyingToMessage(null);
    }
    if (editingMessage?.message_id_short === msg.message_id_short) {
      setEditingMessage(null);
      setMessageInput("");
    }

    // Оптимистичное удаление из ленты за 0 мс
    setMessages((prev) => {
      const filtered = prev.filter(
        (item) => item.message_id_short !== msg.message_id_short
      );
      const last = filtered[filtered.length - 1];
      setChatSummaries((prevSum) => ({
        ...prevSum,
        [peer]: {
          lastText: last ? last.decrypted_text : "",
          timestampMs: last ? last.timestamp_ms : 0,
          isMine: last ? last.sender_username === activeUsername : false,
          isReadByPeer: last ? last.is_read_by_peer : false,
        },
      }));
      return filtered;
    });

    if (!msg.message_id_short.startsWith("opt-")) {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.DeleteChatMessage,
        caller_username: activeUsername,
        peer_username: peer,
        target_message_id_short: msg.message_id_short,
        delete_for_everyone: forEveryone,
      });
      if (resp.ok) {
        void loadChatHistory(peer, false);
      }
    }
  };

  const scrollToQuotedMessage = (targetShortId: string) => {
    if (!targetShortId) return;
    const el = document.getElementById(`msg-bubble-${targetShortId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      setHighlightedMessageId(targetShortId);
      window.setTimeout(() => {
        setHighlightedMessageId((curr) =>
          curr === targetShortId ? "" : curr
        );
      }, 1500);
    }
  };

  // Мгновенная (0ms Optimistic UI) отправка или редактирование E2EE сообщения через бинарный Protobuf
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = messageInput.trim();
    const peer = selectedPeer;
    if (!text || !peer) return;

    // Режим редактирования существующего сообщения
    if (editingMessage) {
      const targetMsg = editingMessage;
      setEditingMessage(null);
      setMessageInput("");

      setMessages((prev) =>
        prev.map((item) =>
          item.message_id_short === targetMsg.message_id_short
            ? { ...item, decrypted_text: text, is_edited: true }
            : item
        )
      );

      if (!targetMsg.message_id_short.startsWith("opt-")) {
        const editResp = await callClientWireProtobuf({
          op: ClientWireOp.EditChatMessage,
          caller_username: activeUsername,
          peer_username: peer,
          target_message_id_short: targetMsg.message_id_short,
          plaintext_message: text,
        });
        if (editResp.ok) {
          void loadChatHistory(peer, false);
        }
      }
      return;
    }

    const nowMs = Date.now();
    const currentReply = replyingToMessage;
    // 1. Мгновенно очищаем инпут и плашку цитаты (самолетик сразу улетает, капсула плавно сжимается)
    setMessageInput("");
    setReplyingToMessage(null);
    setActiveChatPeers((prev) => (prev.includes(peer) ? prev : [peer, ...prev]));

    const replyIdShort = currentReply?.message_id_short ?? "";
    const replySender = currentReply?.sender_username ?? "";
    const replyText = currentReply?.decrypted_text ?? "";

    // 2. Оптимистично добавляем сообщение в ленту чата и превью слева за 0 мс
    const optimisticId = `opt-${nowMs}`;
    setMessages((prev) => [
      ...prev,
      {
        sender_username: activeUsername,
        ratchet_step: prev.length + 1,
        message_id_short: optimisticId,
        timestamp_ms: nowMs,
        is_read_by_peer: false,
        decrypted_text: text,
        wire_bytes_len: text.length,
        nonce_hex: "",
        ciphertext_hex: "",
        signature_hex_short: "",
        reply_to_message_id_short: replyIdShort,
        reply_to_sender: replySender,
        reply_to_text: replyText,
        is_edited: false,
      },
    ]);
    setChatSummaries((prev) => ({
      ...prev,
      [peer]: {
        lastText: text,
        timestampMs: nowMs,
        isMine: true,
        isReadByPeer: false,
      },
    }));

    // 3. Отправляем бинарный Protobuf-конверт на шлюз
    const resp = await callClientWireProtobuf({
      op: ClientWireOp.SendChatMessage,
      caller_username: activeUsername,
      peer_username: peer,
      plaintext_message: text,
      reply_to_message_id_short: replyIdShort,
      reply_to_sender: replySender,
      reply_to_text: replyText,
    });
    if (resp.ok) {
      void loadChatHistory(peer, false);
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
        "relative flex h-full w-full overflow-hidden select-none gap-3",
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
          "relative z-20 my-3 ml-3 flex h-[calc(100%-24px)] w-[360px] shrink-0 flex-col overflow-hidden rounded-[24px] border shadow-2xl backdrop-blur-xl",
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
            "flex-1 px-3 pb-3",
            visibleChats.length === 0 ? "overflow-hidden" : "overflow-y-auto"
          )}
        >
          {visibleChats.length === 0 && isInitialChatsLoaded && (
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
          )}
          {visibleChats.length > 0 && (
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
            {/* Плавающая капсула собеседника сверху по центру (поверх полновысотного скролла чата) */}
            <header className="pointer-events-none absolute inset-x-0 top-3 z-20 flex items-center justify-center px-6">
              <div
                className={cn(
                  "pointer-events-auto flex min-w-[200px] flex-col items-center justify-center rounded-full border px-6 py-1.5 shadow-lg backdrop-blur-xl",
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

            {/* Полновысотная область сообщений от самого верха до самого низа экрана (скроллбар во всю высоту окна!) */}
            <div
              ref={messagesContainerRef}
              onScroll={handleMessagesScroll}
              className={cn(
                "relative z-10 h-full w-full px-8 pt-20",
                messages.length === 0 ? "overflow-hidden" : "overflow-y-auto"
              )}
            >
              {messages.map((m, idx) => {
                const isMine = m.sender_username === activeUsername;
                const prevMsg = idx > 0 ? messages[idx - 1] : undefined;
                const nextMsg =
                  idx + 1 < messages.length ? messages[idx + 1] : undefined;

                const showDateSeparator =
                  !prevMsg ||
                  !isSameCalendarDay(prevMsg.timestamp_ms, m.timestamp_ms);
                const isFirstInGroup =
                  showDateSeparator || !isGroupedWithAdjacent(prevMsg, m);
                const isLastInGroup = !isGroupedWithAdjacent(m, nextMsg);
                const bubbleShape = getBubbleShapeClasses(
                  isMine,
                  isFirstInGroup,
                  isLastInGroup
                );

                return (
                  <React.Fragment key={`${m.message_id_short}-${m.ratchet_step}`}>
                    {showDateSeparator && (
                      <div className="my-3 flex items-center justify-center select-none">
                        <span
                          className={cn(
                            "rounded-full border px-3.5 py-0.5 text-[11.5px] font-medium shadow-sm backdrop-blur-md",
                            isDark
                              ? "border-zinc-800/80 bg-[#17171f]/80 text-zinc-300"
                              : "border-zinc-200/80 bg-white/85 text-zinc-600"
                          )}
                        >
                          {formatDateSeparatorLabel(m.timestamp_ms)}
                        </span>
                      </div>
                    )}

                    <motion.div
                      id={`msg-bubble-${m.message_id_short}`}
                      initial={{ opacity: 0, y: 6, scale: 0.985 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      transition={{ duration: 0.15, ease: [0.22, 1, 0.36, 1] }}
                      onContextMenu={(e) => handleMessageContextMenu(e, m)}
                      onDoubleClick={() => handleStartReply(m)}
                      className={cn(
                        "flex flex-col",
                        isMine ? "items-end" : "items-start",
                        isFirstInGroup ? "mt-2.5" : "mt-[3px]"
                      )}
                    >
                      <div
                        className={cn(
                          "relative max-w-lg px-3.5 py-1.5 shadow-md backdrop-blur-md transition-shadow duration-300",
                          bubbleShape,
                          isMine
                            ? "bg-[#2b5278] text-white"
                            : isDark
                              ? "border border-zinc-800/80 bg-[#181820]/95 text-zinc-100"
                              : "border border-zinc-200/90 bg-white/95 text-zinc-900",
                          highlightedMessageId === m.message_id_short &&
                            "ring-2 ring-sky-400 shadow-sky-500/30"
                        )}
                      >
                        {/* Встроенный блок цитируемого сообщения (Reply Quote), клик скроллит к оригиналу */}
                        {m.reply_to_text && (
                          <button
                            type="button"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              scrollToQuotedMessage(m.reply_to_message_id_short);
                            }}
                            className={cn(
                              "mb-1.5 flex w-full flex-col rounded-r-lg border-l-2 py-1 pr-2.5 pl-2.5 text-left transition-colors cursor-pointer",
                              getReplyQuoteClasses(isMine, isDark)
                            )}
                          >
                            <span
                              className={cn(
                                "truncate text-[11px] font-semibold leading-tight",
                                isMine ? "text-sky-200" : "text-sky-400"
                              )}
                            >
                              {resolveSenderDisplayName(m.reply_to_sender)}
                            </span>
                            <span
                              className={cn(
                                "truncate text-[12px] leading-snug",
                                isMine ? "text-sky-100/85" : "text-zinc-400"
                              )}
                            >
                              {m.reply_to_text}
                            </span>
                          </button>
                        )}

                        {/* Аккуратная короткая микро-капелька (~2px) по диагонали вниз и вправо (↘) */}
                        {isLastInGroup && isMine && (
                          <svg
                            viewBox="0 0 12 12"
                            width="12"
                            height="12"
                            aria-hidden="true"
                            className="pointer-events-none absolute -right-[2px] -bottom-[2px] text-[#2b5278]"
                          >
                            <path
                              d="M 2 9.5 L 10 2 C 10 5.6 10.5 8.1 11.4 9.9 C 11.8 10.7 11.0 11.5 10.1 11.2 C 7.9 10.4 5.2 9.5 2 9.5 Z"
                              fill="currentColor"
                            />
                          </svg>
                        )}
                        {isLastInGroup && !isMine && (
                          <svg
                            viewBox="0 0 12 12"
                            width="12"
                            height="12"
                            aria-hidden="true"
                            style={{ transform: "scaleX(-1)" }}
                            className={cn(
                              "pointer-events-none absolute -bottom-[2px] -left-[2px]",
                              isDark ? "text-[#181820]" : "text-white"
                            )}
                          >
                            <path
                              d="M 2 9.5 L 10 2 C 10 5.6 10.5 8.1 11.4 9.9 C 11.8 10.7 11.0 11.5 10.1 11.2 C 7.9 10.4 5.2 9.5 2 9.5 Z"
                              fill="currentColor"
                            />
                          </svg>
                        )}

                        <div className="text-[13.5px] leading-[1.38] whitespace-pre-wrap break-words">
                          <span>{m.decrypted_text}</span>
                          <span
                            className={cn(
                              "float-right ml-2.5 mt-1.5 inline-flex translate-y-[2px] select-none items-center gap-1 text-[10px] leading-none",
                              isMine ? "text-sky-100/75" : "text-zinc-400"
                            )}
                          >
                            {m.is_edited && (
                              <span className="italic opacity-80">изм.</span>
                            )}
                            <span>{formatShortTime(m.timestamp_ms)}</span>

                            {isMine &&
                              (m.is_read_by_peer ? (
                                <span title="Прочитано" className="inline-flex">
                                  <CheckCheck className="h-3.5 w-3.5 text-sky-300" />
                                </span>
                              ) : (
                                <span title="Отправлено" className="inline-flex">
                                  <Check className="h-3.5 w-3.5 opacity-75" />
                                </span>
                              ))}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  </React.Fragment>
                );
              })}
              <div
                ref={messagesEndRef}
                className={cn(
                  "w-full shrink-0",
                  replyingToMessage || editingMessage ? "h-36" : "h-24"
                )}
              />
            </div>

            {/* Плавающая кнопка быстрого скролла вниз «↓» (появляется при прокрутке истории вверх) */}
            <AnimatePresence>
              {showScrollToBottom && messages.length > 0 && (
                <motion.button
                  key="scroll-to-bottom-btn"
                  type="button"
                  onClick={() => scrollToBottom("smooth")}
                  aria-label="Прокрутить вниз"
                  initial={{ opacity: 0, scale: 0.7, y: 12 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.7, y: 12 }}
                  transition={{
                    type: "spring",
                    stiffness: 420,
                    damping: 26,
                  }}
                  whileTap={{ scale: 0.92 }}
                  className={cn(
                    "absolute right-7 bottom-20 z-20 flex h-10 w-10 items-center justify-center rounded-full border shadow-xl backdrop-blur-xl transition-colors cursor-pointer",
                    isDark
                      ? "border-zinc-800/90 bg-[#17171f]/90 text-zinc-200 hover:bg-zinc-800/90"
                      : "border-zinc-200/90 bg-white/95 text-zinc-700 hover:bg-zinc-100"
                  )}
                >
                  <ChevronDown className="h-5 w-5" />
                  {unseenBelowCount > 0 && (
                    <span className="absolute -top-1.5 -right-1 flex h-5 min-w-5 items-center justify-center rounded-full bg-sky-500 px-1.5 text-[10px] font-bold text-white shadow-sm">
                      {unseenBelowCount}
                    </span>
                  )}
                </motion.button>
              )}
            </AnimatePresence>

            {/* Всплывающее уведомление «Скопировано» */}
            <AnimatePresence>
              {copiedToastVisible && (
                <motion.div
                  key="copied-toast"
                  initial={{ opacity: 0, y: -10, scale: 0.92 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -10, scale: 0.92 }}
                  transition={{ duration: 0.16 }}
                  className={cn(
                    "pointer-events-none absolute top-20 left-1/2 z-30 -translate-x-1/2 rounded-full border px-4 py-1.5 text-xs font-medium shadow-xl backdrop-blur-xl",
                    isDark
                      ? "border-zinc-700/80 bg-[#1c1c26]/95 text-zinc-100"
                      : "border-zinc-200 bg-white/95 text-zinc-800"
                  )}
                >
                  Текст скопирован в буфер обмена
                </motion.div>
              )}
            </AnimatePresence>

            {/* Контекстное меню ПКМ по сообщению (в точном монохромном стиле Telegram Desktop на ПК) */}
            <AnimatePresence>
              {contextMenu && (
                <motion.div
                  key="msg-context-menu"
                  initial={{ opacity: 0, scale: 0.92, y: 4 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.94, y: 4 }}
                  transition={{
                    type: "spring",
                    stiffness: 460,
                    damping: 28,
                    mass: 0.55,
                  }}
                  style={{
                    left: contextMenu.x,
                    top: contextMenu.y,
                  }}
                  onClick={(ev) => ev.stopPropagation()}
                  className={cn(
                    "fixed z-50 w-52 overflow-hidden rounded-xl border py-1.5 shadow-2xl backdrop-blur-2xl",
                    isDark
                      ? "border-zinc-800/80 bg-[#17212b]/95 text-zinc-100"
                      : "border-zinc-200/90 bg-white/95 text-zinc-800"
                  )}
                >
                  <button
                    type="button"
                    onClick={() => handleStartReply(contextMenu.message)}
                    className={cn(
                      "flex w-full items-center gap-4 px-4 py-2 text-left text-[13.5px] font-normal transition-colors cursor-pointer",
                      isDark ? "hover:bg-white/[0.06]" : "hover:bg-zinc-100"
                    )}
                  >
                    <Reply
                      className={cn(
                        "h-[18px] w-[18px] shrink-0 stroke-[1.75]",
                        isDark ? "text-zinc-300" : "text-zinc-600"
                      )}
                    />
                    <span>Ответить</span>
                  </button>

                  {contextMenu.message.sender_username === activeUsername &&
                    !contextMenu.message.message_id_short.startsWith("opt-") && (
                      <button
                        type="button"
                        onClick={() => handleStartEdit(contextMenu.message)}
                        className={cn(
                          "flex w-full items-center gap-4 px-4 py-2 text-left text-[13.5px] font-normal transition-colors cursor-pointer",
                          isDark ? "hover:bg-white/[0.06]" : "hover:bg-zinc-100"
                        )}
                      >
                        <Pencil
                          className={cn(
                            "h-[18px] w-[18px] shrink-0 stroke-[1.75]",
                            isDark ? "text-zinc-300" : "text-zinc-600"
                          )}
                        />
                        <span>Изменить</span>
                      </button>
                    )}

                  <button
                    type="button"
                    onClick={() => handleCopyMessageText(contextMenu.message)}
                    className={cn(
                      "flex w-full items-center gap-4 px-4 py-2 text-left text-[13.5px] font-normal transition-colors cursor-pointer",
                      isDark ? "hover:bg-white/[0.06]" : "hover:bg-zinc-100"
                    )}
                  >
                    <Copy
                      className={cn(
                        "h-[18px] w-[18px] shrink-0 stroke-[1.75]",
                        isDark ? "text-zinc-300" : "text-zinc-600"
                      )}
                    />
                    <span>Копировать текст</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleOpenDeleteModal(contextMenu.message)}
                    className={cn(
                      "flex w-full items-center gap-4 px-4 py-2 text-left text-[13.5px] font-normal transition-colors cursor-pointer",
                      isDark ? "hover:bg-white/[0.06]" : "hover:bg-zinc-100"
                    )}
                  >
                    <Trash2
                      className={cn(
                        "h-[18px] w-[18px] shrink-0 stroke-[1.75]",
                        isDark ? "text-zinc-300" : "text-zinc-600"
                      )}
                    />
                    <span>Удалить</span>
                  </button>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Модальное окно подтверждения удаления сообщения как в Telegram (с галочкой «Также удалить для ...») */}
            <AnimatePresence>
              {deleteModalMessage && (
                <motion.div
                  key="delete-confirm-backdrop"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  onClick={() => setDeleteModalMessage(null)}
                  className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 px-4 backdrop-blur-xs"
                >
                  <motion.div
                    initial={{ opacity: 0, scale: 0.92, y: 8 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.94, y: 8 }}
                    transition={{
                      type: "spring",
                      stiffness: 440,
                      damping: 30,
                      mass: 0.6,
                    }}
                    onClick={(ev) => ev.stopPropagation()}
                    className={cn(
                      "w-full max-w-[340px] rounded-2xl border p-5 shadow-2xl",
                      isDark
                        ? "border-zinc-800/90 bg-[#17212b] text-zinc-100"
                        : "border-zinc-200 bg-white text-zinc-900"
                    )}
                  >
                    <h3 className="text-[16px] font-semibold">
                      Удалить сообщение
                    </h3>
                    <p
                      className={cn(
                        "mt-2 text-[13.5px] leading-relaxed",
                        isDark ? "text-zinc-300" : "text-zinc-600"
                      )}
                    >
                      Вы точно хотите удалить это сообщение?
                    </p>

                    <label className="mt-4 flex items-center gap-3 select-none cursor-pointer">
                      <input
                        type="checkbox"
                        checked={deleteForEveryone}
                        onChange={(e) =>
                          setDeleteForEveryone(e.target.checked)
                        }
                        className="h-4 w-4 rounded border-zinc-600 accent-sky-500 cursor-pointer"
                      />
                      <span
                        className={cn(
                          "text-[13.5px]",
                          isDark ? "text-zinc-200" : "text-zinc-800"
                        )}
                      >
                        Также удалить для {activePeerObj.display_name}
                      </span>
                    </label>

                    <div className="mt-5 flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setDeleteModalMessage(null)}
                        className={cn(
                          "rounded-xl px-4 py-2 text-[13.5px] font-medium transition-colors cursor-pointer",
                          isDark
                            ? "text-sky-400 hover:bg-sky-500/10"
                            : "text-sky-600 hover:bg-sky-50"
                        )}
                      >
                        Отмена
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleConfirmDeleteMessage()}
                        className={cn(
                          "rounded-xl px-4 py-2 text-[13.5px] font-medium text-rose-400 transition-colors cursor-pointer",
                          isDark
                            ? "hover:bg-rose-500/15"
                            : "text-rose-600 hover:bg-rose-50"
                        )}
                      >
                        Удалить
                      </button>
                    </div>
                  </motion.div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Плавающая нижняя капсула ввода + плашка Ответа (Reply) или Редактирования (Edit) */}
            <footer className="pointer-events-none absolute inset-x-0 bottom-5 z-20 px-8">
              <div className="mx-auto flex w-full max-w-[640px] flex-col items-center">
                <AnimatePresence>
                  {(replyingToMessage || editingMessage) && (
                    <motion.div
                      key="compose-action-banner"
                      initial={{ opacity: 0, y: 10, scale: 0.96 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: 10, scale: 0.96 }}
                      transition={{
                        type: "spring",
                        stiffness: 420,
                        damping: 28,
                      }}
                      className={cn(
                        "pointer-events-auto mb-2 flex w-[568px] max-w-full items-center justify-between gap-3 rounded-2xl border px-4 py-2 shadow-lg backdrop-blur-xl",
                        isDark
                          ? "border-zinc-800/90 bg-[#17171f]/95 text-zinc-100"
                          : "border-zinc-200/90 bg-white/95 text-zinc-900"
                      )}
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-2.5">
                        {editingMessage ? (
                          <Pencil className="h-4 w-4 shrink-0 text-amber-400" />
                        ) : (
                          <Reply className="h-4 w-4 shrink-0 text-sky-400" />
                        )}
                        <div
                          className={cn(
                            "h-7 w-0.5 shrink-0 rounded-full",
                            editingMessage ? "bg-amber-400" : "bg-sky-400"
                          )}
                        />
                        <div className="flex min-w-0 flex-1 flex-col">
                          <span
                            className={cn(
                              "truncate text-[11.5px] font-semibold leading-tight",
                              editingMessage ? "text-amber-400" : "text-sky-400"
                            )}
                          >
                            {editingMessage
                              ? "Редактирование сообщения"
                              : `В ответ ${resolveSenderDisplayName(replyingToMessage?.sender_username ?? "")}`}
                          </span>
                          <span className="truncate text-xs text-zinc-400">
                            {editingMessage
                              ? editingMessage.decrypted_text
                              : replyingToMessage?.decrypted_text}
                          </span>
                        </div>
                      </div>

                      <button
                        type="button"
                        aria-label="Отменить действие"
                        onClick={() => {
                          if (editingMessage) {
                            setEditingMessage(null);
                            setMessageInput("");
                          } else {
                            setReplyingToMessage(null);
                          }
                        }}
                        className="rounded-full p-1 text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200 cursor-pointer"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>

                <form
                  onSubmit={handleSendMessage}
                  className="pointer-events-auto flex w-full items-center justify-center"
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
                      ref={messageInputRef}
                      type="text"
                      value={messageInput}
                      onChange={(e) => handleInputTyping(e.target.value)}
                      placeholder="Сообщение"
                      aria-label="Сообщение"
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
                        <OrigamiPaperPlaneIcon />
                      </motion.button>
                    )}
                  </AnimatePresence>
                </motion.div>
              </form>
            </div>
          </footer>
          </>
        )}
      </main>
    </div>
  );
};
