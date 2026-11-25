import React, { useEffect, useState } from "react";
import { flushSync } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  AtSign,
  Building2,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  Globe,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  Moon,
  ShieldCheck,
  Sigma,
  Sparkles,
  Sun,
  User,
} from "lucide-react";
import {
  TelegramPatternWallpapers,
  type WallpaperVariant,
} from "./components/TelegramPatternWallpapers";
import { MessengerWorkspace } from "./components/MessengerWorkspace";
import { callClientWireProtobuf, ClientWireOp } from "./lib/protoWire";
import { cn } from "./lib/utils";

type AuthView = "login" | "register" | "sso" | "recovery-issued" | "recover-password";

export const App: React.FC = () => {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const saved = localStorage.getItem("cryptox_theme");
    return saved === "light" ? "light" : "dark";
  });

  const [wallpaper, setWallpaper] = useState<WallpaperVariant>(() => {
    const saved = localStorage.getItem("cryptox_wallpaper") as WallpaperVariant | null;
    if (saved === "space" || saved === "math" || saved === "cyber") return saved;
    return "space";
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

  // SSO Корпоративный вход
  const [ssoDomain, setSsoDomain] = useState("cryptox.corp");
  const [ssoEmail, setSsoEmail] = useState("");

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

  useEffect(() => {
    localStorage.setItem("cryptox_wallpaper", wallpaper);
  }, [wallpaper]);

  // Анимация заливки темы каплей из правого верхнего угла в левый нижний
  const handleLiquidThemeToggle = (e: React.MouseEvent<HTMLButtonElement>) => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    const rect = e.currentTarget.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const maxRadius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y)
    );

    const docWithVT = document as Document & {
      startViewTransition?: (cb: () => void) => { ready: Promise<void> };
    };

    if (typeof docWithVT.startViewTransition !== "function") {
      setTheme(nextTheme);
      return;
    }

    const transition = docWithVT.startViewTransition(() => {
      flushSync(() => {
        setTheme(nextTheme);
      });
    });

    transition.ready.then(() => {
      document.documentElement.animate(
        {
          clipPath: [
            `circle(0px at ${x}px ${y}px)`,
            `circle(${maxRadius}px at ${x}px ${y}px)`,
          ],
        },
        {
          duration: 720,
          easing: "cubic-bezier(0.22, 1, 0.36, 1)",
          pseudoElement: "::view-transition-new(root)",
        }
      );
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
      setErrorMsg("Введите электронную почту или имя пользователя");
      return;
    }
    if (!loginPassword) {
      setErrorMsg("Введите пароль");
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
      setErrorMsg("Укажите ваше имя");
      return;
    }
    if (!regEmail.trim() || !regEmail.includes("@") || !regEmail.includes(".")) {
      setErrorMsg("Укажите корректный адрес электронной почты");
      return;
    }
    if (!regUsername.trim() || regUsername.trim().replace(/^@/, "").length < 3) {
      setErrorMsg("Имя пользователя должно содержать минимум 3 символа");
      return;
    }
    if (regPassword.length < 6) {
      setErrorMsg("Пароль должен содержать минимум 6 символов");
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

  const handleSsoLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!ssoDomain.trim() || !ssoDomain.includes(".")) {
      setErrorMsg("Укажите корпоративный домен организации (например, company.ru)");
      return;
    }
    if (!ssoEmail.trim()) {
      setErrorMsg("Укажите рабочую почту или логин сотрудника");
      return;
    }

    setLoading(true);
    try {
      const resp = await callClientWireProtobuf({
        op: ClientWireOp.SsoLogin,
        domain: ssoDomain.trim(),
        email: ssoEmail.trim(),
      });
      if (!resp.ok) {
        setErrorMsg(resp.error_message || "Ошибка корпоративного входа SSO");
        return;
      }
      finishAuth(resp.username);
    } catch {
      setErrorMsg("Не удалось связаться с сервером SSO по каналу Protobuf");
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
      setSuccessMsg("Пароль обновлён, сейф ключей перешифрован (Protobuf)");
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
        wallpaper={wallpaper}
        onChangeWallpaper={setWallpaper}
        onToggleTheme={handleLiquidThemeToggle}
        onSwitchAccount={(uname) => finishAuth(uname)}
        onLogout={handleLogout}
      />
    );
  }

  // Оценка надежности пароля (0..4)
  const passwordStrength = (() => {
    if (!regPassword) return 0;
    let s = 1;
    if (regPassword.length >= 6) s++;
    if (regPassword.length >= 10 || /[A-ZА-Я]/.test(regPassword)) s++;
    if (/[0-9!@#$%^&*]/.test(regPassword)) s++;
    return Math.min(4, s);
  })();

  const wallpapers: { id: WallpaperVariant; label: string; icon: React.ReactNode }[] = [
    { id: "space", label: "Космос", icon: <Sparkles className="h-3.5 w-3.5" /> },
    { id: "math", label: "Математика", icon: <Sigma className="h-3.5 w-3.5" /> },
    { id: "cyber", label: "Кибер", icon: <Cpu className="h-3.5 w-3.5" /> },
  ];

  return (
    <div
      className={cn(
        "relative flex min-h-screen w-full items-center justify-center overflow-hidden px-4 py-10",
        isDark ? "bg-[#09090b] text-zinc-50" : "bg-[#f2f2f5] text-zinc-950"
      )}
    >
      {/* Статичный детализированный SVG-паттерн в стиле Telegram Web */}
      <TelegramPatternWallpapers variant={wallpaper} theme={theme} />

      {/* Верхняя правая панель: Переключатель паттерна фона + Кнопка темы с заливкой каплей */}
      <div className="fixed top-5 right-6 z-20 flex items-center gap-2.5">
        <div
          className={cn(
            "flex items-center gap-1 rounded-full border p-1 backdrop-blur-md",
            isDark
              ? "border-zinc-800/90 bg-zinc-900/80"
              : "border-zinc-200/90 bg-white/85 shadow-sm"
          )}
        >
          {wallpapers.map((wp) => {
            const active = wallpaper === wp.id;
            return (
              <button
                key={wp.id}
                type="button"
                onClick={() => setWallpaper(wp.id)}
                className={cn(
                  "relative flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11.5px] font-medium transition-colors",
                  active
                    ? isDark
                      ? "text-zinc-950"
                      : "text-zinc-50"
                    : isDark
                    ? "text-zinc-400 hover:text-zinc-200"
                    : "text-zinc-600 hover:text-zinc-900"
                )}
              >
                {active && (
                  <motion.div
                    layoutId="wallpaperActivePill"
                    transition={{ type: "spring", stiffness: 450, damping: 34 }}
                    className={cn(
                      "absolute inset-0 rounded-full",
                      isDark ? "bg-zinc-100" : "bg-zinc-900"
                    )}
                  />
                )}
                <span className="relative z-10 flex items-center gap-1">
                  {wp.icon}
                  <span>{wp.label}</span>
                </span>
              </button>
            );
          })}
        </div>

        <motion.button
          type="button"
          whileHover={{ scale: 1.07 }}
          whileTap={{ scale: 0.93 }}
          onClick={handleLiquidThemeToggle}
          aria-label="Переключить тему оформления"
          title="Переключить тему (заливка волной)"
          className={cn(
            "flex h-10 w-10 items-center justify-center rounded-full border backdrop-blur-md transition-colors",
            isDark
              ? "border-zinc-800 bg-zinc-900/85 text-zinc-200 hover:border-zinc-700 hover:text-white"
              : "border-zinc-200 bg-white/90 text-zinc-800 shadow-sm hover:border-zinc-300 hover:text-black"
          )}
        >
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={theme}
              initial={{ rotate: -90, opacity: 0, scale: 0.5 }}
              animate={{ rotate: 0, opacity: 1, scale: 1 }}
              exit={{ rotate: 90, opacity: 0, scale: 0.5 }}
              transition={{ duration: 0.22 }}
              className="flex items-center justify-center"
            >
              {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </motion.span>
          </AnimatePresence>
        </motion.button>
      </div>

      {/* Центральная анимированная карточка авторизации */}
      <motion.main
        layout
        initial={{ opacity: 0, y: 18, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", stiffness: 360, damping: 30 }}
        className={cn(
          "relative z-10 w-full max-w-[420px] overflow-hidden rounded-3xl border p-8 backdrop-blur-2xl",
          isDark
            ? "border-zinc-800/90 bg-zinc-900/90 shadow-[0_28px_70px_rgba(0,0,0,0.75)]"
            : "border-zinc-200/90 bg-white/95 shadow-[0_24px_60px_rgba(9,9,11,0.09)]"
        )}
      >
        {/* Декоративный верхний блик карточки */}
        <div
          className="pointer-events-none absolute -top-24 left-1/2 h-44 w-72 -translate-x-1/2 rounded-full blur-3xl"
          style={{
            background: isDark
              ? "radial-gradient(circle, rgba(250,250,250,0.09) 0%, rgba(0,0,0,0) 70%)"
              : "radial-gradient(circle, rgba(24,24,27,0.05) 0%, rgba(255,255,255,0) 70%)",
          }}
        />

        {/* Шапка карточки с анимированной иконкой */}
        <motion.div layout className="mb-6 flex flex-col items-center text-center">
          <motion.div
            key={view}
            initial={{ scale: 0.8, rotate: -8, opacity: 0 }}
            animate={{ scale: 1, rotate: 0, opacity: 1 }}
            transition={{ type: "spring", stiffness: 420, damping: 22 }}
            className={cn(
              "mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border shadow-md",
              isDark
                ? "border-zinc-700 bg-zinc-100 text-zinc-950"
                : "border-zinc-900 bg-zinc-950 text-zinc-50"
            )}
          >
            {view === "recovery-issued" ? (
              <KeyRound className="h-5 w-5" />
            ) : view === "sso" ? (
              <Building2 className="h-5 w-5" />
            ) : (
              <ShieldCheck className="h-5 w-5" />
            )}
          </motion.div>

          <motion.h1 layout className="text-[22px] font-bold tracking-tight">
            {view === "login" && "Вход в CryptoX"}
            {view === "register" && "Создание аккаунта"}
            {view === "sso" && "Корпоративный вход SSO"}
            {view === "recovery-issued" && "Резервный ключ доступа"}
            {view === "recover-password" && "Восстановление доступа"}
          </motion.h1>

          <motion.p
            layout
            className={cn(
              "mt-1.5 text-[13px] leading-relaxed",
              isDark ? "text-zinc-400" : "text-zinc-500"
            )}
          >
            {view === "login" && "Защищённый мессенджер со сквозным шифрованием"}
            {view === "register" && "Ключи шифрования генерируются на вашем устройстве"}
            {view === "sso" && "Подключение к закрытому пространству вашей компании"}
            {view === "recovery-issued" &&
              "Сохраните этот ключ — он нужен для сброса пароля без потери переписки"}
            {view === "recover-password" &&
              "Введите резервный ключ, чтобы перешифровать сейф под новый пароль"}
          </motion.p>
        </motion.div>

        {/* Пружинный переключатель вкладок: Вход | Регистрация | Корп. SSO */}
        {(view === "login" || view === "register" || view === "sso") && (
          <div
            className={cn(
              "mb-6 grid grid-cols-3 rounded-2xl border p-1",
              isDark
                ? "border-zinc-800/90 bg-zinc-950/90"
                : "border-zinc-200/80 bg-zinc-100/90"
            )}
          >
            {(
              [
                { id: "login", label: "Вход" },
                { id: "register", label: "Регистрация" },
                { id: "sso", label: "SSO Компания" },
              ] as const
            ).map((tab) => {
              const active = view === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => switchAuthView(tab.id)}
                  className={cn(
                    "relative rounded-xl py-2 text-[12.5px] font-semibold transition-colors",
                    active
                      ? isDark
                        ? "text-zinc-50"
                        : "text-zinc-950"
                      : isDark
                      ? "text-zinc-400 hover:text-zinc-200"
                      : "text-zinc-500 hover:text-zinc-900"
                  )}
                >
                  {active && (
                    <motion.div
                      layoutId="authActiveTabPill"
                      transition={{ type: "spring", stiffness: 430, damping: 32 }}
                      className={cn(
                        "absolute inset-0 rounded-xl shadow-sm",
                        isDark
                          ? "border border-zinc-700/70 bg-zinc-800"
                          : "border border-zinc-200/80 bg-white"
                      )}
                    />
                  )}
                  <span className="relative z-10">{tab.label}</span>
                </button>
              );
            })}
          </div>
        )}

        {/* Анимированные уведомления об ошибке / успехе */}
        <AnimatePresence mode="wait">
          {errorMsg && (
            <motion.div
              key="err"
              initial={{ opacity: 0, y: -6, height: 0 }}
              animate={{ opacity: 1, y: 0, height: "auto" }}
              exit={{ opacity: 0, y: -6, height: 0 }}
              className={cn(
                "mb-4 flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-[12.5px] leading-snug",
                isDark
                  ? "border-red-500/30 bg-red-500/10 text-red-300"
                  : "border-red-200 bg-red-50 text-red-700"
              )}
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{errorMsg}</span>
            </motion.div>
          )}

          {successMsg && (
            <motion.div
              key="ok"
              initial={{ opacity: 0, y: -6, height: 0 }}
              animate={{ opacity: 1, y: 0, height: "auto" }}
              exit={{ opacity: 0, y: -6, height: 0 }}
              className={cn(
                "mb-4 flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-[12.5px] leading-snug",
                isDark
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-emerald-200 bg-emerald-50 text-emerald-700"
              )}
            >
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{successMsg}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* АНИМИРОВАННЫЕ ЭКРАНЫ ФОРМ */}
        <AnimatePresence mode="wait" initial={false}>
          {/* 1. ЭКРАН ВХОДА */}
          {view === "login" && (
            <motion.form
              key="form-login"
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 16 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              onSubmit={handleLogin}
              className="space-y-4"
            >
              <div className="space-y-1.5">
                <label
                  htmlFor="loginIdInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Почта или имя пользователя
                </label>
                <div className="relative">
                  <AtSign
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="loginIdInput"
                    type="text"
                    value={loginId}
                    onChange={(e) => setLoginId(e.target.value)}
                    placeholder="name@company.ru или @username"
                    autoComplete="username"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/15"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white focus:ring-2 focus:ring-zinc-900/5"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="loginPasswordInput"
                    className={cn(
                      "block text-[12.5px] font-medium",
                      isDark ? "text-zinc-300" : "text-zinc-700"
                    )}
                  >
                    Пароль
                  </label>
                  <button
                    type="button"
                    onClick={() => switchAuthView("recover-password")}
                    className={cn(
                      "text-[12px] font-medium underline-offset-4 hover:underline",
                      isDark ? "text-zinc-400 hover:text-zinc-200" : "text-zinc-500 hover:text-zinc-900"
                    )}
                  >
                    Забыли пароль?
                  </button>
                </div>
                <div className="relative">
                  <Lock
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="loginPasswordInput"
                    type={showLoginPass ? "text" : "password"}
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="Введите пароль"
                    autoComplete="current-password"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-10 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/15"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white focus:ring-2 focus:ring-zinc-900/5"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowLoginPass(!showLoginPass)}
                    aria-label="Показать или скрыть пароль"
                    className={cn(
                      "absolute top-1/2 right-3 -translate-y-1/2 p-1 transition-colors",
                      isDark ? "text-zinc-500 hover:text-zinc-300" : "text-zinc-400 hover:text-zinc-700"
                    )}
                  >
                    {showLoginPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold shadow-sm transition-colors disabled:opacity-50",
                  isDark
                    ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <span>Войти в аккаунт</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </motion.button>

              {/* Нижняя кнопка быстрого перехода к Корпоративному SSO */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => switchAuthView("sso")}
                  className={cn(
                    "flex h-10 w-full items-center justify-center gap-2 rounded-xl border text-[12.5px] font-medium transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/50 text-zinc-300 hover:border-zinc-700 hover:bg-zinc-800/60 hover:text-white"
                      : "border-zinc-200 bg-zinc-50 text-zinc-700 hover:border-zinc-300 hover:bg-zinc-100 hover:text-black"
                  )}
                >
                  <Building2 className="h-4 w-4" />
                  <span>Войти через корпоративный SSO</span>
                </button>
              </div>
            </motion.form>
          )}

          {/* 2. ЭКРАН РЕГИСТРАЦИИ */}
          {view === "register" && (
            <motion.form
              key="form-register"
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              onSubmit={handleRegister}
              className="space-y-3.5"
            >
              <div className="space-y-1.5">
                <label
                  htmlFor="regNameInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Ваше имя
                </label>
                <div className="relative">
                  <User
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="regNameInput"
                    type="text"
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="Вадим"
                    autoComplete="name"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="regEmailInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Электронная почта
                </label>
                <div className="relative">
                  <Mail
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="regEmailInput"
                    type="email"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="name@company.ru"
                    autoComplete="email"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="regUsernameInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Имя пользователя (@username)
                </label>
                <div className="relative">
                  <AtSign
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="regUsernameInput"
                    type="text"
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value)}
                    placeholder="vadim"
                    autoComplete="username"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="regPasswordInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Пароль защиты крипто-сейфа
                </label>
                <div className="relative">
                  <Lock
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="regPasswordInput"
                    type={showRegPass ? "text" : "password"}
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="Минимум 6 символов"
                    autoComplete="new-password"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-10 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowRegPass(!showRegPass)}
                    aria-label="Показать или скрыть пароль"
                    className={cn(
                      "absolute top-1/2 right-3 -translate-y-1/2 p-1 transition-colors",
                      isDark ? "text-zinc-500 hover:text-zinc-300" : "text-zinc-400 hover:text-zinc-700"
                    )}
                  >
                    {showRegPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>

                {/* Анимированная шкала стойкости пароля */}
                <div className="grid grid-cols-4 gap-1.5 pt-1">
                  {[1, 2, 3, 4].map((level) => (
                    <div
                      key={level}
                      className={cn(
                        "h-1 rounded-full transition-all duration-300",
                        passwordStrength >= level
                          ? passwordStrength <= 2
                            ? "bg-amber-500"
                            : "bg-emerald-500"
                          : isDark
                          ? "bg-zinc-800"
                          : "bg-zinc-200"
                      )}
                    />
                  ))}
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold shadow-sm transition-colors disabled:opacity-50",
                  isDark
                    ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
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
              </motion.button>
            </motion.form>
          )}

          {/* 3. ЭКРАН КОРПОРАТИВНОГО SSO (SINGLE SIGN-ON) */}
          {view === "sso" && (
            <motion.form
              key="form-sso"
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -16 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              onSubmit={handleSsoLogin}
              className="space-y-4"
            >
              <div className="space-y-1.5">
                <label
                  htmlFor="ssoDomainInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Корпоративный домен организации
                </label>
                <div className="relative">
                  <Globe
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="ssoDomainInput"
                    type="text"
                    value={ssoDomain}
                    onChange={(e) => setSsoDomain(e.target.value)}
                    placeholder="company.ru"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="ssoEmailInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Рабочая почта или логин сотрудника
                </label>
                <div className="relative">
                  <Building2
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="ssoEmailInput"
                    type="text"
                    value={ssoEmail}
                    onChange={(e) => setSsoEmail(e.target.value)}
                    placeholder="vadim@company.ru"
                    className={cn(
                      "h-11 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-all",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold shadow-sm transition-colors disabled:opacity-50",
                  isDark
                    ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <span>Войти через SSO организации</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </motion.button>
            </motion.form>
          )}

          {/* 4. ЭКРАН ВЫДАЧИ РЕЗЕРВНОГО КЛЮЧА ПОСЛЕ РЕГИСТРАЦИИ */}
          {view === "recovery-issued" && (
            <motion.div
              key="form-recovery-issued"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="space-y-4"
            >
              <div
                className={cn(
                  "flex items-center justify-between rounded-xl border px-4 py-3.5",
                  isDark
                    ? "border-zinc-800 bg-zinc-950/90"
                    : "border-zinc-200 bg-zinc-50"
                )}
              >
                <code className="font-mono text-[14px] font-semibold tracking-wider">
                  {issuedRecoveryKey}
                </code>
                <button
                  type="button"
                  onClick={handleCopyRecoveryKey}
                  aria-label="Скопировать ключ восстановления"
                  className={cn(
                    "flex h-8 w-8 items-center justify-center rounded-lg border transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-900 text-zinc-300 hover:text-zinc-50"
                      : "border-zinc-200 bg-white text-zinc-700 hover:text-zinc-950"
                  )}
                >
                  {copiedKey ? (
                    <Check className="h-4 w-4 text-emerald-500" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              </div>

              <motion.button
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                type="button"
                onClick={() => finishAuth(registeredUsername)}
                className={cn(
                  "flex h-11 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-colors",
                  isDark
                    ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
                )}
              >
                <span>Перейти в мессенджер</span>
                <ArrowRight className="h-4 w-4" />
              </motion.button>
            </motion.div>
          )}

          {/* 5. ЭКРАН ВОССТАНОВЛЕНИЯ ПАРОЛЯ ПО КЛЮЧУ */}
          {view === "recover-password" && (
            <motion.form
              key="form-recover"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              onSubmit={handleRecoverPassword}
              className="space-y-3.5"
            >
              <div className="space-y-1.5">
                <label
                  htmlFor="recIdInput"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Почта или имя пользователя
                </label>
                <div className="relative">
                  <AtSign
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="recIdInput"
                    type="text"
                    value={recId}
                    onChange={(e) => setRecId(e.target.value)}
                    placeholder="name@company.ru или @username"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="recKeyField"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Резервный ключ (Recovery Key)
                </label>
                <div className="relative">
                  <KeyRound
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="recKeyField"
                    type="text"
                    value={recKey}
                    onChange={(e) => setRecKey(e.target.value)}
                    placeholder="CX-XXXX-XXXX-XXXX-XXXX"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-3.5 pl-10 font-mono text-[13px] outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="recNewPassField"
                  className={cn(
                    "block text-[12.5px] font-medium",
                    isDark ? "text-zinc-300" : "text-zinc-700"
                  )}
                >
                  Новый пароль
                </label>
                <div className="relative">
                  <Lock
                    className={cn(
                      "pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2",
                      isDark ? "text-zinc-500" : "text-zinc-400"
                    )}
                  />
                  <input
                    id="recNewPassField"
                    type={showRecPass ? "text" : "password"}
                    value={recNewPassword}
                    onChange={(e) => setRecNewPassword(e.target.value)}
                    placeholder="Минимум 6 символов"
                    className={cn(
                      "h-10 w-full rounded-xl border pr-10 pl-10 text-[13.5px] outline-none transition-colors",
                      isDark
                        ? "border-zinc-800 bg-zinc-950/75 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500"
                        : "border-zinc-200 bg-zinc-50/90 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setShowRecPass(!showRecPass)}
                    aria-label="Показать или скрыть пароль"
                    className={cn(
                      "absolute top-1/2 right-3 -translate-y-1/2 p-1 transition-colors",
                      isDark ? "text-zinc-500 hover:text-zinc-300" : "text-zinc-400 hover:text-zinc-700"
                    )}
                  >
                    {showRecPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.01 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                className={cn(
                  "mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-colors disabled:opacity-50",
                  isDark
                    ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                    : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
                )}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <span>Сбросить пароль</span>
                )}
              </motion.button>

              <button
                type="button"
                onClick={() => switchAuthView("login")}
                className={cn(
                  "mt-1 flex w-full items-center justify-center gap-1.5 py-1.5 text-[12.5px] font-medium transition-colors",
                  isDark ? "text-zinc-400 hover:text-zinc-200" : "text-zinc-500 hover:text-zinc-900"
                )}
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                <span>Вернуться ко входу</span>
              </button>
            </motion.form>
          )}
        </AnimatePresence>
      </motion.main>
    </div>
  );
};
