import React, { useEffect, useState } from "react";
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
  ShieldCheck,
  Sun,
  User,
} from "lucide-react";
import { AntigravityMathCanvas } from "./components/AntigravityMathCanvas";
import { cn } from "./lib/utils";

type AuthView = "login" | "register" | "recovery-issued" | "recover-password";

export const App: React.FC = () => {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const saved = localStorage.getItem("cryptox_theme");
    return saved === "light" ? "light" : "dark";
  });

  const [view, setView] = useState<AuthView>("login");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Login form state
  const [loginId, setLoginId] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [showLoginPass, setShowLoginPass] = useState(false);

  // Register form state
  const [regName, setRegName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regUsername, setRegUsername] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [showRegPass, setShowRegPass] = useState(false);

  // Issued Recovery Key state
  const [issuedRecoveryKey, setIssuedRecoveryKey] = useState("");
  const [registeredUsername, setRegisteredUsername] = useState("");
  const [copiedKey, setCopiedKey] = useState(false);

  // Password recovery state
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

  const switchAuthView = (next: AuthView) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    setView(next);
  };

  const finishAuth = (username: string) => {
    const clean = username.trim().replace(/^@/, "").toLowerCase();
    sessionStorage.setItem("cryptox_active_user", clean);
    localStorage.setItem("cryptox_active_user", clean);
    window.location.href = "/?user=" + encodeURIComponent(clean);
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
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginId.trim(),
          password: loginPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || "Неверный логин или пароль");
        return;
      }
      finishAuth(data.username);
    } catch {
      setErrorMsg("Не удалось связаться с сервером");
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
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: regName.trim(),
          email: regEmail.trim(),
          username: regUsername.trim(),
          password: regPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || "Не удалось создать аккаунт");
        return;
      }
      setRegisteredUsername(data.username);
      setIssuedRecoveryKey(data.recovery_key);
      switchAuthView("recovery-issued");
    } catch {
      setErrorMsg("Не удалось связаться с сервером");
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
      const res = await fetch("/api/auth/recover-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: recId.trim(),
          recovery_key: recKey.trim(),
          new_password: recNewPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || "Не удалось восстановить пароль");
        return;
      }
      setSuccessMsg("Пароль обновлён, сейф ключей перешифрован");
      setTimeout(() => finishAuth(data.username), 800);
    } catch {
      setErrorMsg("Не удалось связаться с сервером");
    } finally {
      setLoading(false);
    }
  };

  const isDark = theme === "dark";

  return (
    <div
      className={cn(
        "relative flex min-h-screen w-full items-center justify-center overflow-hidden px-4 py-10 transition-colors duration-300",
        isDark ? "bg-[#09090b] text-zinc-50" : "bg-[#f4f4f5] text-zinc-950"
      )}
    >
      {/* Осмысленный математический и геометрический фон Antigravity */}
      <AntigravityMathCanvas theme={theme} />

      {/* Кнопка переключения темы (Lucide Sun / Moon) */}
      <div className="fixed top-5 right-6 z-20">
        <button
          type="button"
          onClick={() => setTheme(isDark ? "light" : "dark")}
          aria-label="Переключить тему оформления"
          className={cn(
            "flex h-10 w-10 items-center justify-center rounded-full border backdrop-blur-md transition-all duration-200 hover:scale-105 active:scale-95",
            isDark
              ? "border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:border-zinc-700 hover:text-zinc-50"
              : "border-zinc-200 bg-white/85 text-zinc-700 shadow-sm hover:border-zinc-300 hover:text-zinc-950"
          )}
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>

      {/* Центральная карточка shadcn/ui */}
      <main
        className={cn(
          "relative z-10 w-full max-w-[400px] rounded-2xl border p-7 backdrop-blur-xl transition-all duration-300",
          isDark
            ? "border-zinc-800/90 bg-zinc-900/88 shadow-[0_24px_60px_rgba(0,0,0,0.65)]"
            : "border-zinc-200/90 bg-white/92 shadow-[0_20px_50px_rgba(9,9,11,0.07)]"
        )}
      >
        {/* Шапка бренда */}
        <div className="mb-6 flex flex-col items-center text-center">
          <div
            className={cn(
              "mb-3.5 flex h-11 w-11 items-center justify-center rounded-xl border transition-colors",
              isDark
                ? "border-zinc-700/80 bg-zinc-50 text-zinc-950"
                : "border-zinc-900 bg-zinc-950 text-zinc-50"
            )}
          >
            {view === "recovery-issued" ? (
              <KeyRound className="h-5 w-5" />
            ) : (
              <ShieldCheck className="h-5 w-5" />
            )}
          </div>

          <h1 className="text-xl font-semibold tracking-tight">
            {view === "login" && "Вход в CryptoX"}
            {view === "register" && "Создание аккаунта"}
            {view === "recovery-issued" && "Резервный ключ доступа"}
            {view === "recover-password" && "Восстановление доступа"}
          </h1>

          <p
            className={cn(
              "mt-1.5 text-[13px] leading-relaxed",
              isDark ? "text-zinc-400" : "text-zinc-500"
            )}
          >
            {view === "login" && "Введите почту или логин для входа в мессенджер"}
            {view === "register" && "Личные ключи шифрования создаются на устройстве"}
            {view === "recovery-issued" &&
              "Сохраните этот код. Он понадобится, если вы забудете пароль от аккаунта"}
            {view === "recover-password" &&
              "Укажите резервный ключ, чтобы задать новый пароль без потери чатов"}
          </p>
        </div>

        {/* Переключатель вкладок Вход / Регистрация (shadcn Tabs) */}
        {(view === "login" || view === "register") && (
          <div
            className={cn(
              "mb-5 grid grid-cols-2 rounded-xl p-1",
              isDark ? "bg-zinc-950/80 border border-zinc-800/80" : "bg-zinc-100 border border-zinc-200/70"
            )}
          >
            <button
              type="button"
              onClick={() => switchAuthView("login")}
              className={cn(
                "rounded-lg py-1.5 text-[13px] font-medium transition-all",
                view === "login"
                  ? isDark
                    ? "bg-zinc-800 text-zinc-50 shadow-sm"
                    : "bg-white text-zinc-950 shadow-sm"
                  : isDark
                  ? "text-zinc-400 hover:text-zinc-200"
                  : "text-zinc-600 hover:text-zinc-950"
              )}
            >
              Вход
            </button>
            <button
              type="button"
              onClick={() => switchAuthView("register")}
              className={cn(
                "rounded-lg py-1.5 text-[13px] font-medium transition-all",
                view === "register"
                  ? isDark
                    ? "bg-zinc-800 text-zinc-50 shadow-sm"
                    : "bg-white text-zinc-950 shadow-sm"
                  : isDark
                  ? "text-zinc-400 hover:text-zinc-200"
                  : "text-zinc-600 hover:text-zinc-950"
              )}
            >
              Регистрация
            </button>
          </div>
        )}

        {/* Уведомления об ошибке или успехе */}
        {errorMsg && (
          <div
            className={cn(
              "mb-4 flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-[12.5px] leading-snug",
              isDark
                ? "border-red-500/30 bg-red-500/10 text-red-300"
                : "border-red-200 bg-red-50 text-red-700"
            )}
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div
            className={cn(
              "mb-4 flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-[12.5px] leading-snug",
              isDark
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                : "border-emerald-200 bg-emerald-50 text-emerald-700"
            )}
          >
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* ФОРМА 1: ВХОД */}
        {view === "login" && (
          <form onSubmit={handleLogin} className="space-y-4">
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
                    "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                    "h-10 w-full rounded-xl border pr-10 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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

            <button
              type="submit"
              disabled={loading}
              className={cn(
                "mt-2 flex h-10 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-all active:scale-[0.99] disabled:opacity-50",
                isDark
                  ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                  : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
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
          </form>
        )}

        {/* ФОРМА 2: РЕГИСТРАЦИЯ */}
        {view === "register" && (
          <form onSubmit={handleRegister} className="space-y-3.5">
            <div className="space-y-1.5">
              <label
                htmlFor="regNameInput"
                className={cn(
                  "block text-[12.5px] font-medium",
                  isDark ? "text-zinc-300" : "text-zinc-700"
                )}
              >
                Имя
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
                    "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                    "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                Имя пользователя
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
                    "h-10 w-full rounded-xl border pr-3.5 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                Пароль
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
                    "h-10 w-full rounded-xl border pr-10 pl-10 text-[13.5px] outline-none transition-colors",
                    isDark
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
            </div>

            <button
              type="submit"
              disabled={loading}
              className={cn(
                "mt-2 flex h-10 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-all active:scale-[0.99] disabled:opacity-50",
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
            </button>
          </form>
        )}

        {/* ЭКРАН 3: ВЫДАННЫЙ КЛЮЧ ВОССТАНОВЛЕНИЯ */}
        {view === "recovery-issued" && (
          <div className="space-y-4">
            <div
              className={cn(
                "flex items-center justify-between rounded-xl border px-3.5 py-3",
                isDark
                  ? "border-zinc-800 bg-zinc-950/80"
                  : "border-zinc-200 bg-zinc-50"
              )}
            >
              <code className="font-mono text-[13.5px] font-semibold tracking-wider">
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

            <button
              type="button"
              onClick={() => finishAuth(registeredUsername)}
              className={cn(
                "flex h-10 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-all",
                isDark
                  ? "bg-zinc-50 text-zinc-950 hover:bg-zinc-200"
                  : "bg-zinc-950 text-zinc-50 hover:bg-zinc-800"
              )}
            >
              <span>Перейти в мессенджер</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* ЭКРАН 4: ВОССТАНОВЛЕНИЕ ПАРОЛЯ */}
        {view === "recover-password" && (
          <form onSubmit={handleRecoverPassword} className="space-y-3.5">
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
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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
                      ? "border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600"
                      : "border-zinc-200 bg-zinc-50/80 text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:bg-white"
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

            <button
              type="submit"
              disabled={loading}
              className={cn(
                "mt-2 flex h-10 w-full items-center justify-center gap-2 rounded-xl text-[13.5px] font-semibold transition-all active:scale-[0.99] disabled:opacity-50",
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
            </button>

            <button
              type="button"
              onClick={() => switchAuthView("login")}
              className={cn(
                "mt-2 flex w-full items-center justify-center gap-1.5 py-1.5 text-[12.5px] font-medium transition-colors",
                isDark ? "text-zinc-400 hover:text-zinc-200" : "text-zinc-500 hover:text-zinc-900"
              )}
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>Вернуться ко входу</span>
            </button>
          </form>
        )}
      </main>
    </div>
  );
};
