import React from "react";

export type WallpaperVariant = "space" | "math" | "cyber";

interface Props {
  variant: WallpaperVariant;
  theme: "dark" | "light";
}

export const TelegramPatternWallpapers: React.FC<Props> = ({ variant, theme }) => {
  const isDark = theme === "dark";

  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none">
      {/* Мягкое радиальное свечение под центральной карточкой */}
      <div
        className="absolute inset-0 transition-opacity duration-500"
        style={{
          background: isDark
            ? "radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.06) 0%, rgba(245, 158, 11, 0.03) 35%, rgba(9, 9, 11, 0) 75%)"
            : "radial-gradient(circle at 50% 50%, rgba(99, 102, 241, 0.05) 0%, rgba(24, 24, 27, 0) 70%)",
        }}
      />

      <svg
        className="h-full w-full"
        xmlns="http://www.w3.org/2000/svg"
        width="100%"
        height="100%"
      >
        <defs>
          {/* Фирменный градиент штрихов в стиле Telegram Web (фиолетово-янтарный в темной теме, графитовый в светлой) */}
          <linearGradient id="tgStrokeGradDark" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#a78bfa" stopOpacity="0.16" />
            <stop offset="50%" stopColor="#c084fc" stopOpacity="0.13" />
            <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.15" />
          </linearGradient>

          <linearGradient id="tgStrokeGradLight" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3f3f46" stopOpacity="0.14" />
            <stop offset="50%" stopColor="#52525b" stopOpacity="0.12" />
            <stop offset="100%" stopColor="#18181b" stopOpacity="0.15" />
          </linearGradient>

          {/* =================================================================
              ПАТТЕРН 1: КОСМОС И ОРБИТЫ (TELEGRAM DOODLE WALLPAPER)
             ================================================================= */}
          <pattern
            id="pattern-space"
            width="320"
            height="320"
            patternUnits="userSpaceOnUse"
          >
            <g
              stroke={isDark ? "url(#tgStrokeGradDark)" : "url(#tgStrokeGradLight)"}
              fill="none"
              strokeWidth="1.45"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* 1. Сатурн с кольцами */}
              <g transform="translate(46, 48) rotate(-18)">
                <circle cx="0" cy="0" r="16" />
                <ellipse cx="0" cy="0" rx="30" ry="8" />
                <path d="M-12,-6 C-4,-10 6,-10 13,-5" />
              </g>

              {/* 2. Космическая ракета */}
              <g transform="translate(155, 42) rotate(28)">
                <path d="M0,-22 C10,-12 10,8 8,16 L-8,16 C-10,8 -10,-12 0,-22 Z" />
                <circle cx="0" cy="-4" r="4.5" />
                <path d="M-8,8 L-15,18 L-8,16 M8,8 L15,18 L8,16" />
                <path d="M-4,16 L0,25 L4,16" />
              </g>

              {/* 3. Телескоп на треноге */}
              <g transform="translate(268, 52) rotate(-12)">
                <rect x="-18" y="-8" width="32" height="10" rx="3" transform="rotate(-20)" />
                <path d="M0,2 L-12,22 M0,2 L12,22 M0,2 L0,24" />
                <circle cx="16" cy="-10" r="3" />
              </g>

              {/* 4. Спутник с солнечными панелями */}
              <g transform="translate(105, 118) rotate(15)">
                <rect x="-7" y="-7" width="14" height="14" rx="2" />
                <rect x="-27" y="-5" width="16" height="10" rx="1" />
                <rect x="11" y="-5" width="16" height="10" rx="1" />
                <path d="M-19,-5 L-19,5 M19,-5 L19,5 M0,7 L0,15" />
                <path d="M-5,18 A7,7 0 0,1 5,18" />
              </g>

              {/* 5. Полумесяц и звезды */}
              <g transform="translate(215, 112) rotate(-22)">
                <path d="M6,-16 A16,16 0 1,0 18,10 A12,12 0 1,1 6,-16 Z" />
                <path d="M18,-10 L20,-5 L25,-3 L20,-1 L18,4 L16,-1 L11,-3 L16,-5 Z" />
              </g>

              {/* 6. Шлем космонавта */}
              <g transform="translate(42, 168) rotate(12)">
                <circle cx="0" cy="0" r="18" />
                <rect x="-12" y="-8" width="24" height="13" rx="6" />
                <path d="M-10,16 L10,16 M-6,-4 L-2,-4" />
              </g>

              {/* 7. Спиральная галактика и орбита атома */}
              <g transform="translate(162, 182) rotate(-8)">
                <ellipse cx="0" cy="0" rx="22" ry="8" transform="rotate(30)" />
                <ellipse cx="0" cy="0" rx="22" ry="8" transform="rotate(-30)" />
                <circle cx="0" cy="0" r="4" />
                <circle cx="16" cy="9" r="2" />
              </g>

              {/* 8. НЛО / Летающая тарелка */}
              <g transform="translate(274, 174) rotate(16)">
                <path d="M-12,-2 A12,10 0 0,1 12,-2" />
                <ellipse cx="0" cy="0" rx="24" ry="7" />
                <path d="M-10,9 L-14,17 M0,10 L0,19 M10,9 L14,17" />
              </g>

              {/* 9. Созвездие Большой Медведицы */}
              <g transform="translate(96, 236) rotate(-10)">
                <circle cx="-22" cy="-8" r="2.2" />
                <circle cx="-10" cy="-4" r="2.2" />
                <circle cx="0" cy="2" r="2.2" />
                <circle cx="12" cy="0" r="2.2" />
                <circle cx="22" cy="10" r="2.2" />
                <circle cx="10" cy="14" r="2.2" />
                <path d="M-22,-8 L-10,-4 L0,2 L12,0 L22,10 L10,14 L0,2" />
              </g>

              {/* 10. Комета с хвостом */}
              <g transform="translate(222, 248) rotate(-35)">
                <circle cx="-12" cy="0" r="7" />
                <path d="M-6,-5 L24,-10 M-4,0 L28,0 M-6,5 L22,10" />
              </g>

              {/* 11. Радиотелескоп / Антенна дальней связи */}
              <g transform="translate(44, 284) rotate(8)">
                <path d="M-16,-6 A18,18 0 0,0 16,-6 Z" />
                <path d="M0,-6 L0,-18 M-10,14 L0,3 L10,14" />
                <circle cx="0" cy="-19" r="2" />
              </g>

              {/* 12. Планета с кратерами и спутником */}
              <g transform="translate(158, 288) rotate(-14)">
                <circle cx="0" cy="0" r="15" />
                <circle cx="-5" cy="-4" r="3" />
                <circle cx="6" cy="5" r="2.2" />
                <circle cx="23" cy="-12" r="3.5" />
              </g>

              {/* 13. Компас-звезда */}
              <g transform="translate(278, 285) rotate(20)">
                <path d="M0,-16 L4,-4 L16,0 L4,4 L0,16 L-4,4 L-16,0 L-4,-4 Z" />
                <circle cx="0" cy="0" r="2" />
              </g>

              {/* Мелкие звездочки и точки для плотности паттерна */}
              <circle cx="95" cy="30" r="1.5" />
              <circle cx="210" cy="35" r="1.5" />
              <circle cx="24" cy="108" r="1.8" />
              <circle cx="152" cy="110" r="1.5" />
              <circle cx="298" cy="116" r="1.5" />
              <circle cx="102" cy="176" r="1.8" />
              <circle cx="215" cy="186" r="1.5" />
              <circle cx="32" cy="230" r="1.5" />
              <circle cx="290" cy="235" r="1.8" />
              <circle cx="105" cy="296" r="1.5" />
            </g>
          </pattern>

          {/* =================================================================
              ПАТТЕРН 2: МАТЕМАТИКА И КРИПТОГРАФИЯ (TELEGRAM DOODLE WALLPAPER)
             ================================================================= */}
          <pattern
            id="pattern-math"
            width="320"
            height="320"
            patternUnits="userSpaceOnUse"
          >
            <g
              stroke={isDark ? "url(#tgStrokeGradDark)" : "url(#tgStrokeGradLight)"}
              fill="none"
              strokeWidth="1.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* 1. Изометрический гиперкуб */}
              <g transform="translate(48, 48) rotate(-14)">
                <polygon points="0,-20 18,-10 18,10 0,20 -18,10 -18,-10" />
                <path d="M0,-20 L0,0 M18,10 L0,0 M-18,10 L0,0" />
                <polygon points="0,-10 9,-5 9,5 0,10 -9,5 -9,-5" />
              </g>

              {/* 2. Формула эллиптической кривой Curve25519 */}
              <g transform="translate(120, 42) rotate(-6)">
                <text
                  x="0"
                  y="0"
                  stroke="none"
                  fill={isDark ? "rgba(196,181,253,0.17)" : "rgba(39,39,42,0.17)"}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="600"
                >
                  y² = x³ + 486662x² + x
                </text>
              </g>

              {/* 3. Циркуль и геометрия */}
              <g transform="translate(274, 48) rotate(18)">
                <path d="M0,-18 L-10,16 M0,-18 L10,16" />
                <circle cx="0" cy="-18" r="3" />
                <path d="M-12,6 A16,16 0 0,0 12,6" />
              </g>

              {/* 4. Лента Мёбиуса / Знак бесконечности */}
              <g transform="translate(98, 108) rotate(12)">
                <path d="M-18,0 C-18,-12 -6,-12 0,0 C6,12 18,12 18,0 C18,-12 6,-12 0,0 C-6,12 -18,12 -18,0 Z" />
              </g>

              {/* 5. График функции и интеграл */}
              <g transform="translate(216, 108) rotate(-10)">
                <path d="M-20,14 L22,14 M-16,18 L-16,-16" />
                <path d="M-16,10 C-6,-14 4,14 18,-12" />
                <text
                  x="-6"
                  y="-4"
                  stroke="none"
                  fill={isDark ? "rgba(251,191,36,0.16)" : "rgba(39,39,42,0.16)"}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="13"
                  fontWeight="600"
                >
                  ∮ E·dA
                </text>
              </g>

              {/* 6. Тетраэдр Симплекс */}
              <g transform="translate(42, 168) rotate(22)">
                <polygon points="0,-20 19,14 -19,14" />
                <path d="M0,-20 L2,4 M19,14 L2,4 M-19,14 L2,4" />
              </g>

              {/* 7. Формула Эйлера и Argon2id */}
              <g transform="translate(115, 174) rotate(8)">
                <text
                  x="0"
                  y="0"
                  stroke="none"
                  fill={isDark ? "rgba(196,181,253,0.17)" : "rgba(39,39,42,0.17)"}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="12"
                  fontWeight="600"
                >
                  e^(iπ) + 1 = 0
                </text>
              </g>

              {/* 8. Золотая спираль Фибоначчи */}
              <g transform="translate(268, 172) rotate(-15)">
                <rect x="-18" y="-12" width="36" height="24" rx="2" />
                <path d="M6,-12 L6,12 M6,2 L18,2" />
                <path d="M-18,12 A24,24 0 0,1 6,-12 A14,14 0 0,1 18,2 A10,10 0 0,1 6,12" />
              </g>

              {/* 9. Криптографический ключ и замок */}
              <g transform="translate(96, 236) rotate(-24)">
                <circle cx="-10" cy="0" r="8" />
                <circle cx="-10" cy="0" r="2.5" />
                <path d="M-2,0 L18,0 M12,0 L12,7 M17,0 L17,5" />
              </g>

              {/* 10. Сумма ряда и хэш BLAKE3 */}
              <g transform="translate(178, 240) rotate(-7)">
                <text
                  x="0"
                  y="0"
                  stroke="none"
                  fill={isDark ? "rgba(251,191,36,0.17)" : "rgba(39,39,42,0.17)"}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="600"
                >
                  ∑ x_i · G → BLAKE3
                </text>
              </g>

              {/* 11. Октаэдр */}
              <g transform="translate(46, 286) rotate(-12)">
                <polygon points="0,-18 16,0 0,18 -16,0" />
                <path d="M0,-18 L0,18 M-16,0 L16,0" />
              </g>

              {/* 12. Диаграмма Венна / Пересечение множеств */}
              <g transform="translate(162, 288) rotate(14)">
                <circle cx="-7" cy="0" r="12" />
                <circle cx="7" cy="0" r="12" />
              </g>

              {/* 13. Диффи-Хеллман формула */}
              <g transform="translate(226, 292) rotate(10)">
                <text
                  x="0"
                  y="0"
                  stroke="none"
                  fill={isDark ? "rgba(196,181,253,0.17)" : "rgba(39,39,42,0.17)"}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="600"
                >
                  g^(ab) mod p
                </text>
              </g>
            </g>
          </pattern>

          {/* =================================================================
              ПАТТЕРН 3: КИБЕРНЕТИКА И СЕТИ (TELEGRAM DOODLE WALLPAPER)
             ================================================================= */}
          <pattern
            id="pattern-cyber"
            width="320"
            height="320"
            patternUnits="userSpaceOnUse"
          >
            <g
              stroke={isDark ? "url(#tgStrokeGradDark)" : "url(#tgStrokeGradLight)"}
              fill="none"
              strokeWidth="1.45"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* 1. Микропроцессор с ножками */}
              <g transform="translate(48, 48) rotate(-12)">
                <rect x="-14" y="-14" width="28" height="28" rx="4" />
                <rect x="-7" y="-7" width="14" height="14" rx="2" />
                <path d="M-8,-14 L-8,-20 M0,-14 L0,-20 M8,-14 L8,-20" />
                <path d="M-8,14 L-8,20 M0,14 L0,20 M8,14 L8,20" />
                <path d="M-14,-8 L-20,-8 M-14,0 L-20,0 M-14,8 L-20,8" />
                <path d="M14,-8 L20,-8 M14,0 L20,0 M14,8 L20,8" />
              </g>

              {/* 2. Крипто-щит с замком */}
              <g transform="translate(160, 48) rotate(14)">
                <path d="M0,-18 L15,-12 L15,2 C15,12 0,19 0,19 C0,19 -15,12 -15,2 L-15,-12 Z" />
                <rect x="-5" y="-2" width="10" height="8" rx="1.5" />
                <path d="M-3,-2 L-3,-5 A3,3 0 0,1 3,-5 L3,-2" />
              </g>

              {/* 3. Окно терминала >_ */}
              <g transform="translate(268, 50) rotate(-16)">
                <rect x="-20" y="-14" width="40" height="28" rx="4" />
                <path d="M-20,-6 L20,-6 M-12,2 L-6,6 L-12,10 M-2,10 L6,10" />
              </g>

              {/* 4. Дерево хэшей (Merkle Tree) */}
              <g transform="translate(104, 118) rotate(8)">
                <circle cx="0" cy="-12" r="4" />
                <circle cx="-14" cy="10" r="4" />
                <circle cx="14" cy="10" r="4" />
                <path d="M-2,-8 L-12,6 M2,-8 L12,6" />
              </g>

              {/* 5. Серверный кластер */}
              <g transform="translate(220, 118) rotate(-14)">
                <rect x="-18" y="-14" width="36" height="11" rx="2" />
                <rect x="-18" y="2" width="36" height="11" rx="2" />
                <circle cx="-11" cy="-8.5" r="1.5" />
                <circle cx="-11" cy="7.5" r="1.5" />
                <path d="M2,-8.5 L12,-8.5 M2,7.5 L12,7.5" />
              </g>

              {/* 6. Глобус сети */}
              <g transform="translate(46, 174) rotate(18)">
                <circle cx="0" cy="0" r="16" />
                <ellipse cx="0" cy="0" rx="8" ry="16" />
                <path d="M-15,-5 L15,-5 M-15,5 L15,5" />
              </g>

              {/* 7. Радар и волны */}
              <g transform="translate(162, 180) rotate(-20)">
                <circle cx="0" cy="0" r="3" />
                <path d="M-8,-6 A10,10 0 0,1 8,-6" />
                <path d="M-14,-11 A18,18 0 0,1 14,-11" />
                <path d="M0,3 L-6,16 L6,16 Z" />
              </g>

              {/* 8. Молния / High-Speed Hotpath */}
              <g transform="translate(274, 178) rotate(12)">
                <polygon points="3,-18 -11,2 1,2 -3,18 11,-2 -1,-2" />
              </g>

              {/* 9. Пара ключей шифрования */}
              <g transform="translate(100, 242) rotate(-18)">
                <circle cx="-10" cy="0" r="7" />
                <path d="M-3,0 L16,0 M10,0 L10,6 M15,0 L15,6" />
              </g>

              {/* 10. Печатная плата / Дорожки */}
              <g transform="translate(218, 246) rotate(10)">
                <path d="M-18,-8 L-4,-8 L4,0 L18,0" />
                <path d="M-16,8 L2,8 L10,16" />
                <circle cx="-18" cy="-8" r="2.5" />
                <circle cx="18" cy="0" r="2.5" />
                <circle cx="10" cy="16" r="2.5" />
              </g>

              {/* 11. Облачный сейф */}
              <g transform="translate(52, 286) rotate(-8)">
                <path d="M-12,8 A9,9 0 0,1 -10,-9 A12,12 0 0,1 12,-7 A8,8 0 0,1 14,8 Z" />
              </g>

              {/* 12. Блокчейн / Цепочка блоков */}
              <g transform="translate(168, 288) rotate(15)">
                <rect x="-18" y="-6" width="12" height="12" rx="2" />
                <rect x="6" y="-6" width="12" height="12" rx="2" />
                <path d="M-6,0 L6,0" />
              </g>
            </g>
          </pattern>
        </defs>

        <rect
          width="100%"
          height="100%"
          fill={`url(#pattern-${variant})`}
        />
      </svg>
    </div>
  );
};
