import React, { useEffect, useState } from "react";
import { flushSync } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  AtSign,
  Check,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  Moon,
  Sun,
  User,
  XCircle,
} from "lucide-react";
import { TelegramPatternWallpapers } from "./components/TelegramPatternWallpapers";
import { MessengerWorkspace } from "./components/MessengerWorkspace";
import { callClientWireProtobuf, ClientWireOp } from "./lib/protoWire";
import { cn } from "./lib/utils";
import cryptoxLogoUrl from "./assets/cryptox-logo.jpg";

type AuthView = "login" | "register" | "recovery-issued" | "recover-password";

type UsernameStatus = "idle" | "checking" | "available" | "taken" | "invalid";

/**
 * Сгенерированный 3D-логотип CryptoX в шапке формы (без лишних текстовых заголовков).
 */
const CryptoXBrandLogo: React.FC<{ isDark: boolean }> = ({ isDark }) => (
  <div className="flex flex-col items-center justify-center select-none">
    <div
      className={cn(
        "relative h-16 w-16 overflow-hidden rounded-[18px] border shadow-md",
        isDark ? "border-zinc-700/80" : "border-zinc-300"
      )}
    >
      <img
        src={cryptoxLogoUrl}
        alt="CryptoX"
        className="h-full w-full object-cover scale-[1.42]"
        draggable={false}
      />
    </div>
  </div>
);

export const App: React.FC = () => {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const saved = localStorage.getItem("cryptox_theme");
    return saved === "light" ? "light" : "dark";
  });

  // Если открыт `/auth` — показываем экран входа; если `/` — открываем мессенджер для активной сессии
  const [activeUser, setActiveUser] = useState<string | null>(() => {
    if (window.location.pathname.startsWith("/auth")) {
      return null;
    }
    const params = new URLSearchParams(window.location.search);
    const fromQuery = params.get("user");
    if (fromQuery && fromQuery.trim()) {
      return fromQuery.trim().replace(/^@/, "").toLowerCase();
    }
    const fromSession =
      sessionStorage.getItem("cryptox_active_user") ||
      localStorage.getItem("cryptox_active_user");
    return fromSession ? fromSession.trim().toLowerCase() : null;
  });

  const [view, setView] = useState<AuthView>("login");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Вход
  const [loginId, setLoginId] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [showLoginPass, setShowLoginPass] = useState(false);

  // Регистрация
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regUsername, setRegUsername] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [showRegPass, setShowRegPass] = useState(false);

  // Живая проверка доступности @username по бинарному Protobuf
  const [usernameStatus, setUsernameStatus] = useState<UsernameStatus>("idle");
  const [usernameHint, setUsernameHint] = useState<string>("");

  // Выданный Recovery Key
  const [issuedRecoveryKey, setIssuedRecoveryKey] = useState("");
  const [registeredUsername, setRegisteredUsername] = useState("");
  const [copiedKey, setCopiedKey] = useState(false);

  // Восстановление пароля
  const [recId, setRecId] = useState("");
  const [recKey, setRecKey] = useState("");
  const [recNewPassword, setRecNewPassword] = useState("");
  const [showRecPass, setShowRecPass] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
      root.setAttribute("data-theme", "dark");
    } else {
      root.classList.remove("dark");
      root.setAttribute("data-theme", "light");
    }
    localStorage.setItem("cryptox_theme", theme);
  }, [theme]);

  // Живая проверка уникальности @username через `ClientWireOp.CheckUsername` (Debounce 200 мс)
  useEffect(() => {
    if (view !== "register") return;
    const raw = regUsername.trim().replace(/^@/, "").toLowerCase();
    if (!raw) {
      setUsernameStatus("idle");
      setUsernameHint("");
      return;
    }
    if (raw.length < 3) {
      setUsernameStatus("invalid");
      setUsernameHint("Минимум 3 символа");
      return;
    }
    if (!/^[a-z0-9_.-]+$/.test(raw)) {
      setUsernameStatus("invalid");
      setUsernameHint("Латиница, цифры, _ . -");
      return;
    }

    setUsernameStatus("checking");
    setUsernameHint("Проверка...");
    let cancelled = false;

    const timer = window.setTimeout(async () => {
      try {
        const resp = await callClientWireProtobuf({
          op: ClientWireOp.CheckUsername,
          caller_username: raw,
        });
        if (cancelled) return;
        if (resp.ok) {
          setUsernameStatus("available");
          setUsernameHint("Свободен");
        } else {
          setUsernameStatus("taken");
          setUsernameHint(resp.error_message || "Уже занят");
        }
      } catch {
        if (!cancelled) {
          setUsernameStatus("idle");
          setUsernameHint("");
        }
      }
    }, 200);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [regUsername, view]);

  // Анимация заливки темы каплей из правого верхнего угла в левый нижний (120 FPS, одинаково контрастно в обе стороны)
  const handleLiquidThemeToggle = (e: React.MouseEvent<HTMLButtonElement>) => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    const rect = e.currentTarget.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    // Расстояние от кнопки в правом верхнем углу до левого нижнего угла экрана
    const maxRadius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y)
    );

    const docWithVT = document as Document & {
      startViewTransition?: (cb: () => void) => {
        ready: Promise<void>;
        finished: Promise<void>;
      };
    };

    const root = document.documentElement;

    if (typeof docWithVT.startViewTransition !== "function") {
      setTheme(nextTheme);
      return;
    }

    // Отключаем внутренние transition-colors на время создания снапшота, чтобы новая тема зафиксировалась за 0 мс
    root.classList.add("theme-wave-active");

    const transition = docWithVT.startViewTransition(() => {
      if (nextTheme === "dark") {
        root.classList.add("dark");
        root.setAttribute("data-theme", "dark");
      } else {
        root.classList.remove("dark");
        root.setAttribute("data-theme", "light");
      }
      localStorage.setItem("cryptox_theme", nextTheme);
      flushSync(() => {
        setTheme(nextTheme);
      });
    });

    transition.ready
      .then(() => {
        document.documentElement.animate(
          [
            {
              clipPath: `circle(0px at ${x}px ${y}px)`,
              offset: 0,
            },
            {
              clipPath: `circle(${Math.round(maxRadius * 0.36)}px at ${Math.round(x - 32)}px ${Math.round(y + 24)}px)`,
              offset: 0.34,
            },
            {
              clipPath: `circle(${Math.round(maxRadius * 1.08)}px at ${Math.round(x - 76)}px ${Math.round(y + 58)}px)`,
              offset: 1,
            },
          ],
          {
            duration: 760,
            easing: "cubic-bezier(0.22, 1, 0.36, 1)",
            pseudoElement: "::view-transition-new(root)",
          }
        );
      })
      .finally(() => {
        transition.finished.finally(() => {
          root.classList.remove("theme-wave-active");
        });
      });
  };

  const switchAuthView = (next: AuthView) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    setView(next);
  };

  const finishAuth = (username: string) => {
    const clean = username.trim().replace(/^@/, "").toLowerCase();
    sessionStorage.setItem("cryptox_active_user", clean);
    localStorage.setItem("cryptox_active_user", clean);
    window.history.pushState({}, "", "/?user=" + encodeURIComponent(clean));
    setActiveUser(clean);
  };

  const handleLogout = () => {
    sessionStorage.removeItem("cryptox_active_user");
    localStorage.removeItem("cryptox_active_user");
    window.history.pushState({}, "", "/auth");
    setActiveUser(null);
    setView("login");
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!loginId.trim()) {
      setErrorMsg("Укажите username или mail");
      return;
    }
    if (!loginPassword) {
      setErrorMsg("Укажите password");
      return;
    }

    setLoading(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.Login,
        caller_username: loginId.trim(),
        password: loginPassword,
      });
      if (!resp.ok) {
        setErrorMsg(resp.error_message || "Неверный логин или пароль");
        return;
      }
      finishAuth(resp.username);
    } catch {
      setErrorMsg("Не удалось связаться с сервером по бинарному каналу Protobuf");
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!regName.trim()) {
      setErrorMsg("Укажите имя");
      return;
    }
    if (!regEmail.trim() || !regEmail.includes("@") || !regEmail.includes(".")) {
      setErrorMsg("Укажите корректный mail");
      return;
    }
    if (!regUsername.trim() || regUsername.trim().replace(/^@/, "").length < 3) {
      setErrorMsg("Username должен содержать минимум 3 символа");
      return;
    }
    if (usernameStatus === "taken") {
      setErrorMsg("Этот username уже занят, выберите другой");
      return;
    }
    if (!isPasswordFullyValid) {
      setErrorMsg(
        missingRequirements.length > 0
          ? `Пароль: ${missingRequirements.join(", ")}`
          : "Пароль не соответствует требованиям безопасности"
      );
      return;
    }

    setLoading(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.Register,
        display_name: regName.trim(),
        email: regEmail.trim(),
        caller_username: regUsername.trim(),
        password: regPassword,
      });
      if (!resp.ok) {
        setErrorMsg(resp.error_message || "Не удалось создать аккаунт");
        return;
      }
      setRegisteredUsername(resp.username);
      setIssuedRecoveryKey(resp.recovery_key);
      switchAuthView("recovery-issued");
    } catch {
      setErrorMsg("Не удалось связаться с сервером по бинарному каналу Protobuf");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyRecoveryKey = async () => {
    if (!issuedRecoveryKey) return;
    try {
      await navigator.clipboard.writeText(issuedRecoveryKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } catch {
      setCopiedKey(false);
    }
  };

  const handleRecoverPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!recId.trim() || !recKey.trim() || !recNewPassword) {
      setErrorMsg("Заполните все поля для восстановления доступа");
      return;
    }
    if (recNewPassword.length < 6) {
      setErrorMsg("Новый пароль должен содержать минимум 6 символов");
      return;
    }

    setLoading(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.RecoverPassword,
        caller_username: recId.trim(),
        recovery_key: recKey.trim(),
        password: recNewPassword,
      });
      if (!resp.ok) {
        setErrorMsg(resp.error_message || "Не удалось восстановить пароль");
        return;
      }
      setSuccessMsg("Пароль обновлён, сейф ключей перешифрован");
      setTimeout(() => finishAuth(resp.username), 800);
    } catch {
      setErrorMsg("Не удалось связаться с сервером по бинарному каналу Protobuf");
    } finally {
      setLoading(false);
    }
  };

  const isDark = theme === "dark";

  if (activeUser) {
    return (
      <MessengerWorkspace
        activeUsername={activeUser}
        theme={theme}
        wallpaper="unified"
        onChangeWallpaper={() => {}}
        onToggleTheme={handleLiquidThemeToggle}
        onSwitchAccount={(uname) => finishAuth(uname)}
        onLogout={handleLogout}
      />
    );
  }

  // Строгие критерии сложности пароля (показываются ТОЛЬКО когда пользователь начал печатать пароль)
  const ruleLength = regPassword.length >= 8;
  const ruleCase = /[A-ZА-Я]/.test(regPassword) && /[a-zа-я]/.test(regPassword);
  const ruleDigit = /[0-9]/.test(regPassword);
  const ruleSpecial = /[^a-zA-Zа-яА-Я0-9\s]/.test(regPassword);

  const hasRepeatingDigits = /(\d)\1/.test(regPassword);
  const hasSequentialDigits = (() => {
    for (let i = 0; i + 2 < regPassword.length; i++) {
      const a = regPassword.charCodeAt(i);
      const b = regPassword.charCodeAt(i + 1);
      const c = regPassword.charCodeAt(i + 2);
      const isDig =
        a >= 48 && a <= 57 && b >= 48 && b <= 57 && c >= 48 && c <= 57;
      if (isDig && ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1))) {
        return true;
      }
    }
    return false;
  })();
  const ruleNoBadDigits = !hasRepeatingDigits && !hasSequentialDigits;

  const missingRequirements: string[] = [];
  if (hasRepeatingDigits) {
    missingRequirements.push("без одинаковых цифр подряд (11, 00)");
  } else if (hasSequentialDigits) {
    missingRequirements.push("без идущих подряд цифр (123, 321)");
  }
  if (!ruleLength) missingRequirements.push("минимум 8 символов");
  if (!ruleCase) missingRequirements.push("заглавная и строчная буква");
  if (!ruleDigit) missingRequirements.push("цифра");
  if (!ruleSpecial) missingRequirements.push("спецсимвол (!@#$%)");

  const isPasswordFullyValid =
    regPassword.length > 0 &&
    ruleLength &&
    ruleCase &&
    ruleDigit &&
    ruleSpecial &&
    ruleNoBadDigits;

  // Плавный расчёт процента заполнения 3 капсул "батарейки" слева направо (0..300 -> 3 x 100%)
  const totalScorePercent = (() => {
    if (!regPassword) return 0;
    let pts = Math.min(60, Math.round((regPassword.length / 8) * 60));
    if (ruleCase) pts += 60;
    if (ruleDigit) pts += 60;
    if (ruleSpecial) pts += 60;
    if (ruleLength && ruleNoBadDigits) pts += 60;
    if (!ruleNoBadDigits) pts = Math.min(pts, 130);
    return Math.min(300, pts);
  })();

  const bar1Fill = Math.min(100, Math.max(0, totalScorePercent));
  const bar2Fill = Math.min(100, Math.max(0, totalScorePercent - 100));
  const bar3Fill = Math.min(100, Math.max(0, totalScorePercent - 200));

  return (
    <div
      className={cn(
        "relative flex min-h-screen w-full items-center justify-center overflow-hidden px-4 py-10",
        isDark ? "bg-[#09090b] text-zinc-50" : "bg-[#f3f3f6] text-zinc-950"
      )}
    >
      {/* Единый высокоплотный бесшовный SVG-фон (Космос + Астрономия + Математика + Физика) без свечений */}
      <TelegramPatternWallpapers theme={theme} />

      {/* В правом верхнем углу ТОЛЬКО одна аккуратная кнопка смены темы (как в оригинальном Telegram Web) */}
      <div className="fixed top-5 right-6 z-20">
        <button
          type="button"
          onClick={handleLiquidThemeToggle}
          title={isDark ? "Светлая тема" : "Тёмная тема"}
          aria-label="Переключить тему оформления"
          className={cn(
            "flex h-10 w-10 items-center justify-center rounded-full border transition-transform active:scale-95 cursor-pointer",
            isDark
              ? "border-zinc-800 bg-[#141417]/90 text-zinc-200 hover:bg-zinc-800 hover:text-white"
              : "border-zinc-200/90 bg-white/90 text-zinc-700 hover:bg-zinc-100 hover:text-zinc-950"
          )}
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>

      {/* Центральная карточка авторизации без лишних свечений и текстовой шапки */}
      <motion.div
        layout
        transition={{
          layout: { type: "spring", stiffness: 340, damping: 32, mass: 0.8 },
        }}
        className={cn(
          "relative z-10 w-full max-w-[400px] overflow-hidden rounded-3xl border p-7",
          isDark
            ? "border-zinc-800/90 bg-[#121215]/95"
            : "border-zinc-200/90 bg-white/95"
        )}
      >
        {/* Кастомный векторный логотип вместо текстовой шапки */}
        <div className="mb-5">
          <CryptoXBrandLogo isDark={isDark} />
        </div>

        {/* Переключатель Вход / Регистрация с плавным перетеканием плашки (`layoutId`) */}
        {(view === "login" || view === "register") && (
          <div
            className={cn(
              "relative mb-5 grid grid-cols-2 rounded-2xl p-1 border",
              isDark
                ? "border-zinc-800/80 bg-zinc-950/90"
                : "border-zinc-200/80 bg-zinc-100"
            )}
          >
            {(
              [
                { id: "login", label: "Вход" },
                { id: "register", label: "Регистрация" },
              ] as const
            ).map((tab) => {
              const isActive = view === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => switchAuthView(tab.id)}
                  className={cn(
                    "relative z-10 rounded-xl py-2 text-xs font-semibold transition-colors duration-200 cursor-pointer",
                    isActive
                      ? isDark
                        ? "text-white"
                        : "text-zinc-950"
                      : isDark
                        ? "text-zinc-400 hover:text-zinc-200"
                        : "text-zinc-500 hover:text-zinc-900"
                  )}
                >
                  {isActive && (
                    <motion.div
                      layoutId="auth-sliding-pill"
                      transition={{
                        type: "spring",
                        stiffness: 400,
                        damping: 33,
                        mass: 0.75,
                      }}
                      className={cn(
                        "absolute inset-0 -z-10 rounded-xl border",
                        isDark
                          ? "border-zinc-700/70 bg-zinc-800/95"
                          : "border-zinc-200/90 bg-white shadow-xs"
                      )}
                    />
                  )}
                  {tab.label}
                </button>
              );
            })}
          </div>
        )}

        {/* Уведомление об ошибке или успехе */}
        <AnimatePresence mode="popLayout">
          {errorMsg && (
            <motion.div
              key="err-banner"
              initial={{ opacity: 0, y: -6, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -6, scale: 0.98 }}
              transition={{ duration: 0.16 }}
              className={cn(
                "mb-4 flex items-center gap-2.5 rounded-xl border px-3.5 py-2.5 text-xs font-medium",
                isDark
                  ? "border-red-500/30 bg-red-500/10 text-red-300"
                  : "border-red-200 bg-red-50 text-red-600"
              )}
            >
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{errorMsg}</span>
            </motion.div>
          )}

          {successMsg && (
            <motion.div
              key="ok-banner"
              initial={{ opacity: 0, y: -6, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -6, scale: 0.98 }}
              transition={{ duration: 0.16 }}
              className={cn(
                "mb-4 flex items-center gap-2.5 rounded-xl border px-3.5 py-2.5 text-xs font-medium",
                isDark
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-emerald-200 bg-emerald-50 text-emerald-700"
              )}
            >
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{successMsg}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Анимированное содержимое формы */}
        <AnimatePresence mode="wait" initial={false}>
          {view === "login" && (
            <motion.form
              key="form-login"
              initial={{ opacity: 0, x: -14 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 14 }}
              transition={{ type: "spring", stiffness: 380, damping: 32 }}
              onSubmit={handleLogin}
              className="space-y-4"
            >
              <div className="space-y-1.5">
                <label
                  htmlFor="login-identifier"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Логин или почта
                </label>
                <div className="relative">
                  <AtSign className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="login-identifier"
                    type="text"
                    autoComplete="username"
                    value={loginId}
                    onChange={(e) => setLoginId(e.target.value)}
                    placeholder="username / mail"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-3.5 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="login-password"
                    className={cn(
                      "block text-xs font-medium",
                      isDark ? "text-zinc-300" : "text-zinc-700"
                    )}
                  >
                    Пароль
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setRecId(loginId);
                      switchAuthView("recover-password");
                    }}
                    className={cn(
                      "text-xs font-medium transition-colors cursor-pointer",
                      isDark
                        ? "text-zinc-400 hover:text-zinc-200"
                        : "text-zinc-500 hover:text-zinc-900"
                    )}
                  >
                    Забыли пароль?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="login-password"
                    type={showLoginPass ? "text" : "password"}
                    autoComplete="current-password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="password"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-10 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowLoginPass((v) => !v)}
                    aria-label="Показать или скрыть пароль"
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                  >
                    {showLoginPass ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-1 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-sm font-semibold transition-all active:scale-[0.99] cursor-pointer disabled:opacity-50",
                  isDark
                    ? "bg-white text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-900 text-white hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <span>Войти</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </motion.form>
          )}

          {view === "register" && (
            <motion.form
              key="form-register"
              initial={{ opacity: 0, x: 14 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -14 }}
              transition={{ type: "spring", stiffness: 380, damping: 32 }}
              onSubmit={handleRegister}
              className="space-y-3.5"
            >
              <div className="space-y-1">
                <label
                  htmlFor="reg-name"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Имя
                </label>
                <div className="relative">
                  <User className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="reg-name"
                    type="text"
                    autoComplete="name"
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="name"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="reg-email"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Почта
                </label>
                <div className="relative">
                  <Mail className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="reg-email"
                    type="email"
                    autoComplete="email"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="mail"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              {/* Поле Username с мгновенной проверкой доступности по Protobuf */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="reg-username"
                    className={cn(
                      "block text-xs font-medium",
                      isDark ? "text-zinc-300" : "text-zinc-700"
                    )}
                  >
                    Имя пользователя
                  </label>

                  <AnimatePresence mode="wait">
                    {usernameStatus !== "idle" && (
                      <motion.span
                        key={usernameStatus + usernameHint}
                        initial={{ opacity: 0, y: -3 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -3 }}
                        className={cn(
                          "inline-flex items-center gap-1 text-[11px] font-medium",
                          usernameStatus === "checking" && "text-zinc-400",
                          usernameStatus === "available" && "text-emerald-400",
                          (usernameStatus === "taken" ||
                            usernameStatus === "invalid") &&
                            "text-rose-400"
                        )}
                      >
                        {usernameStatus === "checking" && (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        )}
                        {usernameStatus === "available" && (
                          <Check className="h-3 w-3" />
                        )}
                        {(usernameStatus === "taken" ||
                          usernameStatus === "invalid") && (
                          <XCircle className="h-3 w-3" />
                        )}
                        <span>{usernameHint}</span>
                      </motion.span>
                    )}
                  </AnimatePresence>
                </div>

                <div className="relative">
                  <AtSign className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="reg-username"
                    type="text"
                    autoComplete="username"
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value)}
                    placeholder="username"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 font-mono text-sm outline-none transition-colors",
                      usernameStatus === "available"
                        ? isDark
                          ? "border-emerald-500/50 bg-zinc-900/80 text-zinc-100"
                          : "border-emerald-500/60 bg-white text-zinc-900"
                        : usernameStatus === "taken" ||
                            usernameStatus === "invalid"
                          ? isDark
                            ? "border-rose-500/50 bg-zinc-900/80 text-zinc-100"
                            : "border-rose-400 bg-white text-zinc-900"
                          : isDark
                            ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                            : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              {/* Пароль + 3-секционная "батарейка" с перетекающим градиентом и кастомными подсказками */}
              <div className="space-y-2">
                <label
                  htmlFor="reg-password"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Пароль
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="reg-password"
                    type={showRegPass ? "text" : "password"}
                    autoComplete="new-password"
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="password"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-10 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowRegPass((v) => !v)}
                    aria-label="Показать или скрыть пароль"
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                  >
                    {showRegPass ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>

                {/* Полоски "батарейки" и живая подсказка появляются ТОЛЬКО когда пользователь печатает пароль */}
                <AnimatePresence initial={false}>
                  {regPassword.length > 0 && (
                    <motion.div
                      key="pwd-battery-hint"
                      initial={{ opacity: 0, height: 0, marginTop: 0 }}
                      animate={{ opacity: 1, height: "auto", marginTop: 8 }}
                      exit={{ opacity: 0, height: 0, marginTop: 0 }}
                      transition={{
                        type: "spring",
                        stiffness: 340,
                        damping: 30,
                      }}
                      className="overflow-hidden"
                    >
                      <div className="space-y-2 pt-0.5">
                        {/* 3 капсулы "батарейки": красное перетекает в оранжевое, оранжевое в зеленое */}
                        <div className="grid grid-cols-3 gap-2">
                          <div
                            className={cn(
                              "h-2 w-full overflow-hidden rounded-full",
                              isDark ? "bg-zinc-800/90" : "bg-zinc-200"
                            )}
                          >
                            <motion.div
                              initial={{ width: "0%" }}
                              animate={{ width: `${bar1Fill}%` }}
                              transition={{
                                type: "spring",
                                stiffness: 260,
                                damping: 28,
                              }}
                              className="h-full rounded-full"
                              style={{
                                background:
                                  "linear-gradient(90deg, #ef4444 0%, #f97316 100%)",
                              }}
                            />
                          </div>

                          <div
                            className={cn(
                              "h-2 w-full overflow-hidden rounded-full",
                              isDark ? "bg-zinc-800/90" : "bg-zinc-200"
                            )}
                          >
                            <motion.div
                              initial={{ width: "0%" }}
                              animate={{ width: `${bar2Fill}%` }}
                              transition={{
                                type: "spring",
                                stiffness: 260,
                                damping: 28,
                              }}
                              className="h-full rounded-full"
                              style={{
                                background:
                                  "linear-gradient(90deg, #f97316 0%, #eab308 55%, #22c55e 100%)",
                              }}
                            />
                          </div>

                          <div
                            className={cn(
                              "h-2 w-full overflow-hidden rounded-full",
                              isDark ? "bg-zinc-800/90" : "bg-zinc-200"
                            )}
                          >
                            <motion.div
                              initial={{ width: "0%" }}
                              animate={{ width: `${bar3Fill}%` }}
                              transition={{
                                type: "spring",
                                stiffness: 260,
                                damping: 28,
                              }}
                              className="h-full rounded-full"
                              style={{
                                background:
                                  "linear-gradient(90deg, #22c55e 0%, #10b981 100%)",
                              }}
                            />
                          </div>
                        </div>

                        {/* Кастомное динамическое оповещение о том, чего ещё не хватает в пароле */}
                        <motion.div
                          layout
                          className={cn(
                            "flex items-start gap-2 rounded-xl border px-3 py-2 text-[11px] leading-snug transition-colors",
                            !ruleNoBadDigits
                              ? isDark
                                ? "border-rose-500/35 bg-rose-500/10 text-rose-300"
                                : "border-rose-200 bg-rose-50 text-rose-700"
                              : isPasswordFullyValid
                                ? isDark
                                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                                  : "border-emerald-200 bg-emerald-50 text-emerald-700"
                                : isDark
                                  ? "border-zinc-800 bg-zinc-900/75 text-zinc-400"
                                  : "border-zinc-200 bg-zinc-100/80 text-zinc-600"
                          )}
                        >
                          {isPasswordFullyValid ? (
                            <>
                              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                              <span>
                                Надёжный пароль — все требования выполнены
                              </span>
                            </>
                          ) : (
                            <>
                              <AlertCircle
                                className={cn(
                                  "mt-0.5 h-3.5 w-3.5 shrink-0",
                                  !ruleNoBadDigits
                                    ? "text-rose-400"
                                    : "text-amber-400"
                                )}
                              />
                              <span>
                                <strong
                                  className={
                                    isDark ? "text-zinc-200" : "text-zinc-800"
                                  }
                                >
                                  Добавьте:{" "}
                                </strong>
                                {missingRequirements.join(" • ")}
                              </span>
                            </>
                          )}
                        </motion.div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <button
                type="submit"
                disabled={loading || usernameStatus === "taken"}
                className={cn(
                  "mt-1 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-sm font-semibold transition-all active:scale-[0.99] cursor-pointer disabled:opacity-50",
                  isDark
                    ? "bg-white text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-900 text-white hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <span>Создать аккаунт</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </motion.form>
          )}

          {view === "recovery-issued" && (
            <motion.div
              key="view-recovery-issued"
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.97 }}
              transition={{ duration: 0.2 }}
              className="space-y-4"
            >
              <div
                className={cn(
                  "rounded-2xl border p-4",
                  isDark
                    ? "border-zinc-800 bg-zinc-900/80"
                    : "border-zinc-200 bg-zinc-50"
                )}
              >
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                    Резервный ключ восстановления
                  </span>
                  <span className="font-mono text-[11px] text-emerald-500">
                    @{registeredUsername}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <code
                    className={cn(
                      "font-mono text-sm font-semibold tracking-wider select-all",
                      isDark ? "text-zinc-100" : "text-zinc-900"
                    )}
                  >
                    {issuedRecoveryKey}
                  </code>
                  <button
                    type="button"
                    onClick={handleCopyRecoveryKey}
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border transition-colors cursor-pointer",
                      isDark
                        ? "border-zinc-700 bg-zinc-800 text-zinc-200 hover:bg-zinc-700"
                        : "border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-100"
                    )}
                    title="Скопировать ключ"
                  >
                    {copiedKey ? (
                      <Check className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-zinc-500">
                  Сохраните этот ключ. Он позволяет расшифровать облачный сейф
                  ключей и сбросить пароль без участия сервера.
                </p>
              </div>

              <button
                type="button"
                onClick={() => finishAuth(registeredUsername)}
                className={cn(
                  "flex h-11 w-full items-center justify-center gap-2 rounded-xl text-sm font-semibold transition-all cursor-pointer",
                  isDark
                    ? "bg-white text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-900 text-white hover:bg-zinc-800"
                )}
              >
                <span>Перейти в мессенджер</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}

          {view === "recover-password" && (
            <motion.form
              key="form-recover"
              initial={{ opacity: 0, x: 14 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -14 }}
              transition={{ type: "spring", stiffness: 380, damping: 32 }}
              onSubmit={handleRecoverPassword}
              className="space-y-3.5"
            >
              <div className="space-y-1">
                <label
                  htmlFor="rec-id"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Логин или почта
                </label>
                <div className="relative">
                  <AtSign className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="rec-id"
                    type="text"
                    value={recId}
                    onChange={(e) => setRecId(e.target.value)}
                    placeholder="username / mail"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="rec-key"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Резервный ключ (Recovery Key)
                </label>
                <div className="relative">
                  <KeyRound className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="rec-key"
                    type="text"
                    value={recKey}
                    onChange={(e) => setRecKey(e.target.value.toUpperCase())}
                    placeholder="CX-XXXX-XXXX-XXXX-XXXX"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 font-mono text-xs tracking-wider outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="rec-new-pass"
                  className={cn(
                    "block text-xs font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Новый пароль
                </label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    id="rec-new-pass"
                    type={showRecPass ? "text" : "password"}
                    value={recNewPassword}
                    onChange={(e) => setRecNewPassword(e.target.value)}
                    placeholder="password"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-10 pl-10 text-sm outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-900/80 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                        : "border-zinc-200 bg-zinc-50 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowRecPass((v) => !v)}
                    aria-label="Показать или скрыть пароль"
                    className="absolute top-1/2 right-3 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                  >
                    {showRecPass ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-1 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-sm font-semibold transition-all cursor-pointer disabled:opacity-50",
                  isDark
                    ? "bg-white text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-900 text-white hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <span>Обновить пароль</span>
                )}
              </button>

              <button
                type="button"
                onClick={() => switchAuthView("login")}
                className={cn(
                  "flex h-9 w-full items-center justify-center gap-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer",
                  isDark
                    ? "text-zinc-400 hover:text-zinc-200"
                    : "text-zinc-500 hover:text-zinc-900"
                )}
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                <span>Назад ко входу</span>
              </button>
            </motion.form>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
};
