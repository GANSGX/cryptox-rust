import React from "react";

export type WallpaperVariant = "unified" | "space" | "math" | "cyber";

interface WallpaperProps {
  variant?: WallpaperVariant;
  theme?: "dark" | "light";
}

/**
 * Плотный бесшовный статичный SVG-паттерн в стиле оригинального Telegram Web.
 * Мемоизирован (`React.memo`) и переключает градиент штрихов через CSS-переменную
 * `--tg-doodle-stroke` за 0 мс без перерисовки SVG DOM во время View Transition волны.
 */
export const TelegramPatternWallpapers: React.FC<WallpaperProps> = React.memo(
  () => {
    const strokeStyle = { stroke: "var(--tg-doodle-stroke)" } as React.CSSProperties;
    const fillStyle = {
      fill: "var(--tg-doodle-stroke)",
      stroke: "none",
    } as React.CSSProperties;

    return (
      <div
        className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none"
        aria-hidden="true"
      >
        <svg
          className="h-full w-full"
          xmlns="http://www.w3.org/2000/svg"
          width="100%"
          height="100%"
        >
          <defs>
            {/* Градиент для тёмной темы */}
            <linearGradient
              id="tg-doodle-stroke-dark"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="100%"
            >
              <stop offset="0%" stopColor="#9370db" stopOpacity="0.24" />
              <stop offset="30%" stopColor="#c084fc" stopOpacity="0.21" />
              <stop offset="65%" stopColor="#f472b6" stopOpacity="0.20" />
              <stop offset="100%" stopColor="#fb923c" stopOpacity="0.22" />
            </linearGradient>

            {/* Градиент для светлой темы */}
            <linearGradient
              id="tg-doodle-stroke-light"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="100%"
            >
              <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.18" />
              <stop offset="35%" stopColor="#7c3aed" stopOpacity="0.16" />
              <stop offset="70%" stopColor="#db2777" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#2563eb" stopOpacity="0.18" />
            </linearGradient>

            {/* Единый высокоплотный бесшовный тайл 380x380: Космос + Астрономия + Математика + Физика */}
            <pattern
              id="pattern-science-cosmos-dense"
              x="0"
              y="0"
              width="380"
              height="380"
              patternUnits="userSpaceOnUse"
            >
              <g
                style={strokeStyle}
                fill="none"
                strokeWidth="1.45"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                {/* 1. Сатурн с кольцами и орбитальным спутником */}
                <g transform="translate(38, 42) rotate(-18)">
                  <circle cx="0" cy="0" r="16" />
                  <path d="M-9 -6 Q0 -2 9 -6" />
                  <path d="M-12 4 Q0 8 12 4" />
                  <ellipse cx="0" cy="0" rx="32" ry="9" />
                  <ellipse cx="0" cy="0" rx="26" ry="6" />
                  <circle cx="35" cy="-6" r="2.2" />
                </g>

                {/* 2. Формула Эйлера и крипто-интеграл Контура */}
                <g transform="translate(105, 30) rotate(-6)">
                  <path d="M0 22 C0 8 8 0 14 4 C16 6 14 10 11 9" />
                  <ellipse cx="3.5" cy="11" rx="4.5" ry="2.8" />
                  <text
                    x="13"
                    y="15"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="11.5"
                    fontWeight="600"
                    style={fillStyle}
                  >
                    e^(iπ)+1=0
                  </text>
                </g>

                {/* 3. Атом Резерфорда-Бора с 3 электронными орбиталями */}
                <g transform="translate(245, 42) rotate(12)">
                  <circle cx="0" cy="0" r="3.5" style={fillStyle} />
                  <ellipse cx="0" cy="0" rx="22" ry="8" />
                  <ellipse cx="0" cy="0" rx="22" ry="8" transform="rotate(60)" />
                  <ellipse cx="0" cy="0" rx="22" ry="8" transform="rotate(120)" />
                  <circle cx="22" cy="0" r="2" />
                  <circle cx="-11" cy="19" r="2" />
                  <circle cx="-11" cy="-19" r="2" />
                </g>

                {/* 4. Космическая ракета на взлёте */}
                <g transform="translate(332, 48) rotate(32)">
                  <path d="M0 -24 C10 -12 11 5 11 16 L-11 16 C-11 5 -10 -12 0 -24 Z" />
                  <path d="M-7 -12 Q0 -9 7 -12" />
                  <circle cx="0" cy="-2" r="4.5" />
                  <circle cx="0" cy="7" r="2.2" />
                  <path d="M-11 8 L-19 19 L-11 16" />
                  <path d="M11 8 L19 19 L11 16" />
                  <path d="M-5 16 Q0 28 5 16" />
                  <path d="M-2.5 16 Q0 23 2.5 16" />
                </g>

                {/* 5. Оптическая призма Ньютона с дисперсией луча */}
                <g transform="translate(158, 86) rotate(-8)">
                  <polygon points="0,-18 -20,15 20,15" />
                  <line x1="-34" y1="4" x2="-9" y2="-2" />
                  <line x1="9" y1="-4" x2="34" y2="-12" />
                  <line x1="11" y1="0" x2="36" y2="-4" />
                  <line x1="13" y1="4" x2="36" y2="4" />
                  <line x1="15" y1="8" x2="34" y2="12" />
                </g>

                {/* 6. Астрономический телескоп на треноге */}
                <g transform="translate(46, 128) rotate(14)">
                  <path d="M-20 -10 L18 -20 L22 -10 L-16 -2 Z" />
                  <path d="M18 -22 L25 -24 L28 -10 L22 -8 Z" />
                  <path d="M-20 -10 L-26 -8 L-24 -1 L-17 -3" />
                  <circle cx="0" cy="-6" r="3" />
                  <line x1="0" y1="-3" x2="-15" y2="20" />
                  <line x1="0" y1="-3" x2="15" y2="20" />
                  <line x1="0" y1="-3" x2="0" y2="22" />
                </g>

                {/* 7. 3D Изометрический тессеракт / гиперкуб */}
                <g transform="translate(108, 122) rotate(16)">
                  <polygon points="0,-18 16,-9 16,9 0,18 -16,9 -16,-9" />
                  <polyline points="-16,-9 0,0 16,-9" />
                  <line x1="0" y1="0" x2="0" y2="18" />
                  <polygon
                    points="0,-9 8,-4.5 8,4.5 0,9 -8,4.5 -8,-4.5"
                    strokeDasharray="2 2"
                  />
                </g>

                {/* 8. Шлем космонавта с бликом и антенной */}
                <g transform="translate(226, 122) rotate(-12)">
                  <circle cx="0" cy="0" r="18" />
                  <rect x="-12" y="-9" width="24" height="15" rx="7.5" />
                  <path d="M-7 -5 Q-2 -7 4 -5" />
                  <path d="M-11 16 L11 16 L14 21 L-14 21 Z" />
                  <line x1="18" y1="-4" x2="23" y2="-15" />
                  <circle cx="23" cy="-17" r="2" />
                </g>

                {/* 9. Уравнение Шрёдингера и волновая функция Ψ */}
                <g transform="translate(292, 114) rotate(7)">
                  <text
                    x="0"
                    y="12"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="11.5"
                    fontWeight="600"
                    style={fillStyle}
                  >
                    iℏ∂Ψ/∂t = ĤΨ
                  </text>
                  <path d="M2 20 Q12 10 22 20 T42 20 T62 20 T82 20" />
                </g>

                {/* 10. Орбитальный спутник с солнечными батареями */}
                <g transform="translate(164, 174) rotate(-26)">
                  <rect x="-6" y="-9" width="12" height="18" rx="2.5" />
                  <rect x="-28" y="-6" width="18" height="12" rx="1.5" />
                  <rect x="10" y="-6" width="18" height="12" rx="1.5" />
                  <line x1="-19" y1="-6" x2="-19" y2="6" />
                  <line x1="19" y1="-6" x2="19" y2="6" />
                  <line x1="-28" y1="0" x2="-10" y2="0" />
                  <line x1="10" y1="0" x2="28" y2="0" />
                  <path d="M-6 9 Q0 16 6 9" />
                  <line x1="0" y1="13" x2="0" y2="21" />
                  <circle cx="0" cy="23" r="2" />
                </g>

                {/* 11. Золотая спираль Фибоначчи и сетка */}
                <g transform="translate(36, 218) rotate(-8)">
                  <rect x="-18" y="-12" width="36" height="24" rx="1.5" />
                  <line x1="6" y1="-12" x2="6" y2="12" />
                  <line x1="6" y1="0" x2="18" y2="0" />
                  <path d="M-18 12 A24 24 0 0 1 6 -12 A12 12 0 0 1 18 0 A6 6 0 0 1 12 6 A3 3 0 0 1 9 3" />
                </g>

                {/* 12. Эллиптическая кривая Cryptography y² = x³ + ax + b */}
                <g transform="translate(94, 212) rotate(5)">
                  <line x1="-18" y1="0" x2="24" y2="0" strokeDasharray="2 2" />
                  <line x1="0" y1="-18" x2="0" y2="18" strokeDasharray="2 2" />
                  <path d="M16 -16 C2 -12 -14 0 2 0 C14 0 2 -12 -10 0 C2 12 14 0 2 0 C-14 0 2 12 16 16" />
                </g>

                {/* 13. НЛО / летающая тарелка с поисковым лучом */}
                <g transform="translate(262, 198) rotate(14)">
                  <path d="M-13 -2 A13 11 0 0 1 13 -2" />
                  <ellipse cx="0" cy="0" rx="25" ry="7" />
                  <circle cx="-13" cy="0" r="1.6" />
                  <circle cx="0" cy="2" r="1.6" />
                  <circle cx="13" cy="0" r="1.6" />
                  <path d="M-9 7 L-16 23 M9 7 L16 23" strokeDasharray="2.5 2.5" />
                </g>

                {/* 14. Молодой полумесяц с кратерами */}
                <g transform="translate(342, 192) rotate(-18)">
                  <path d="M8 -18 A20 20 0 1 0 22 14 A15 15 0 1 1 8 -18 Z" />
                  <circle cx="-6" cy="-3" r="2.6" />
                  <circle cx="-3" cy="7" r="1.8" />
                  <circle cx="-10" cy="5" r="1.4" />
                </g>

                {/* 15. Лента Мёбиуса / знак бесконечности и сумма ряда Σ */}
                <g transform="translate(154, 246) rotate(-11)">
                  <path d="M-16 0 C-16 -10 -5 -10 0 0 C5 10 16 10 16 0 C16 -10 5 -10 0 0 C-5 10 -16 10 -16 0 Z" />
                  <text
                    x="22"
                    y="5"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="11"
                    fontWeight="600"
                    style={fillStyle}
                  >
                    ∑ 1/n² = π²/6
                  </text>
                </g>

                {/* 16. Радиотелескоп Дальнего Космоса */}
                <g transform="translate(46, 308) rotate(10)">
                  <path d="M-18 -10 A22 22 0 0 0 18 -10 Z" />
                  <line x1="0" y1="-10" x2="0" y2="-22" />
                  <circle cx="0" cy="-23" r="2.2" />
                  <line x1="-10" y1="-10" x2="0" y2="-21" />
                  <line x1="10" y1="-10" x2="0" y2="-21" />
                  <path d="M-6 2 L-14 18 L14 18 L6 2" />
                  <path d="M-6 -28 A12 12 0 0 1 6 -28" />
                  <path d="M-11 -33 A18 18 0 0 1 11 -33" />
                </g>

                {/* 17. Падающая комета с хвостом */}
                <g transform="translate(122, 312) rotate(-32)">
                  <circle cx="0" cy="0" r="6.5" />
                  <circle cx="-2" cy="-1.5" r="1.4" />
                  <path d="M5 -5 L36 -13" />
                  <path d="M7 0 L42 0" />
                  <path d="M5 5 L34 12" />
                </g>

                {/* 18. Спиральная галактика Андромеды */}
                <g transform="translate(226, 298) rotate(22)">
                  <circle cx="0" cy="0" r="4.5" />
                  <ellipse cx="0" cy="0" rx="22" ry="8" />
                  <path d="M4 0 C12 -10 24 -6 22 8" />
                  <path d="M-4 0 C-12 10 -24 6 -22 -8" />
                  <path d="M0 4 C10 12 6 22 -8 20" />
                  <path d="M0 -4 C-10 -12 -6 -22 8 -20" />
                </g>

                {/* 19. Формула Эйнштейна и уравнения Максвелла */}
                <g transform="translate(296, 286) rotate(-9)">
                  <text
                    x="0"
                    y="0"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="11.5"
                    fontWeight="600"
                    style={fillStyle}
                  >
                    E = mc²
                  </text>
                  <text
                    x="-6"
                    y="16"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="10.5"
                    fontWeight="600"
                    style={fillStyle}
                  >
                    ∇×B = μ₀J + ε₀μ₀∂E/∂t
                  </text>
                </g>

                {/* 20. Геометрический циркуль и транспортир */}
                <g transform="translate(182, 344) rotate(12)">
                  <circle cx="0" cy="-14" r="2.5" />
                  <line x1="-1.5" y1="-12" x2="-11" y2="12" />
                  <line x1="1.5" y1="-12" x2="11" y2="12" />
                  <path d="M-14 4 A16 16 0 0 0 14 4" />
                </g>

                {/* 21. Тетраэдр */}
                <g transform="translate(338, 342) rotate(-16)">
                  <polygon points="0,-16 -16,11 16,11" />
                  <line x1="0" y1="-16" x2="4" y2="17" />
                  <line x1="-16" y1="11" x2="4" y2="17" />
                  <line x1="16" y1="11" x2="4" y2="17" />
                </g>

                {/* 22. Созвездие */}
                <g transform="translate(88, 168) rotate(-14)">
                  <polyline
                    points="0,0 12,-7 24,-2 34,9 48,5"
                    strokeDasharray="2.5 2.5"
                  />
                  <circle cx="0" cy="0" r="2" style={fillStyle} />
                  <circle cx="12" cy="-7" r="2" style={fillStyle} />
                  <circle cx="24" cy="-2" r="2" style={fillStyle} />
                  <circle cx="34" cy="9" r="2.2" style={fillStyle} />
                  <circle cx="48" cy="5" r="2.2" style={fillStyle} />
                </g>

                {/* 23. Магнит / силовые линии диполя */}
                <g transform="translate(298, 232) rotate(-22)">
                  <path d="M-10 -10 L-10 2 A10 10 0 0 0 10 2 L10 -10 L5 -10 L5 2 A5 5 0 0 1 -5 2 L-5 -10 Z" />
                  <line x1="-10" y1="-6" x2="-5" y2="-6" />
                  <line x1="5" y1="-6" x2="10" y2="-6" />
                  <path d="M-7 -14 Q0 -22 7 -14" strokeDasharray="2 2" />
                </g>

                {/* 24. Дополнительные математические символы */}
                <text
                  x="78"
                  y="76"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="13"
                  fontWeight="600"
                  style={fillStyle}
                >
                  ∫
                </text>
                <text
                  x="196"
                  y="54"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="12"
                  fontWeight="600"
                  style={fillStyle}
                >
                  π ≈ 3.1415
                </text>
                <text
                  x="278"
                  y="78"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11"
                  fontWeight="600"
                  style={fillStyle}
                >
                  Δx·Δp ≥ ℏ/2
                </text>
                <text
                  x="18"
                  y="176"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="600"
                  style={fillStyle}
                >
                  √2
                </text>
                <text
                  x="202"
                  y="214"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="600"
                  style={fillStyle}
                >
                  λ = h/p
                </text>
                <text
                  x="72"
                  y="268"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11"
                  fontWeight="600"
                  style={fillStyle}
                >
                  f(x)=sin(ωt)
                </text>
                <text
                  x="18"
                  y="362"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11"
                  fontWeight="600"
                  style={fillStyle}
                >
                  ∀x ∈ ℝ
                </text>
                <text
                  x="254"
                  y="358"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11"
                  fontWeight="600"
                  style={fillStyle}
                >
                  ∮ B·dl = μ₀I
                </text>

                {/* Четырёхконечные звёздочки и мини-кольца */}
                <path d="M90 14 L92 19 L97 21 L92 23 L90 28 L88 23 L83 21 L88 19 Z" />
                <path d="M292 18 L293.5 22 L297.5 23.5 L293.5 25 L292 29 L290.5 25 L286.5 23.5 L290.5 22 Z" />
                <path d="M180 120 L182 125 L187 127 L182 129 L180 134 L178 129 L173 127 L178 125 Z" />
                <path d="M356 128 L357.5 132 L361.5 133.5 L357.5 135 L356 139 L354.5 135 L350.5 133.5 L354.5 132 Z" />
                <path d="M142 196 L143.5 200 L147.5 201.5 L143.5 203 L142 207 L140.5 203 L136.5 201.5 L140.5 200 Z" />
                <path d="M242 246 L244 251 L249 253 L244 255 L242 260 L240 255 L235 253 L240 251 Z" />
                <path d="M94 348 L95.5 352 L99.5 353.5 L95.5 355 L94 359 L92.5 355 L88.5 353.5 L92.5 352 Z" />
                <path d="M12 84 L13.5 88 L17.5 89.5 L13.5 91 L12 95 L10.5 91 L6.5 89.5 L10.5 88 Z" />

                <circle cx="152" cy="18" r="2.5" />
                <circle cx="62" cy="92" r="2" />
                <circle cx="268" cy="154" r="3" />
                <circle cx="326" cy="154" r="1.8" />
                <circle cx="18" cy="264" r="2.5" />
                <circle cx="192" cy="284" r="2.2" />
                <circle cx="364" cy="252" r="2.5" />
                <circle cx="144" cy="364" r="2" />
              </g>
            </pattern>
          </defs>

          <rect
            x="0"
            y="0"
            width="100%"
            height="100%"
            fill="url(#pattern-science-cosmos-dense)"
          />
        </svg>
      </div>
    );
  }
);
