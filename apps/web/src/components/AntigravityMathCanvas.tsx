import React, { useEffect, useRef } from "react";

interface Props {
  theme: "dark" | "light";
}

const FORMULAS = [
  "y² ≡ x³ + 486662x² + x (mod 2²⁵⁵ − 19)",
  "K = Argon2id(P, S, m, t, p)",
  "E(M) = M^e mod n",
  "∮ E · dA = Q / ε₀",
  "BLAKE3(K, M) → {0, 1}²⁵⁶",
  "e^(iπ) + 1 = 0",
  "g^(ab) ≡ g^(ba) (mod p)",
  "P = [k]G ∈ E(𝔽_q)",
  "H(K ⊕ opad ∥ H(K ⊕ ipad ∥ m))",
  "AEAD(K, N, AAD, P) → (C, T)",
  "∑_{i=1}^n λ_i · x_i",
  "∇ × B = μ₀(J + ε₀ ∂E/∂t)",
  "Ed25519.Verify(pk, M, σ) = 1",
  "Δx · Δp ≥ ℏ / 2",
];

type ShapeKind = "formula" | "hexagon" | "cube" | "tetra" | "ring" | "octa";

interface FloatingItem {
  x: number;
  y: number;
  vx: number;
  vy: number;
  angle: number;
  vAngle: number;
  size: number;
  kind: ShapeKind;
  text: string;
  alpha: number;
}

export const AntigravityMathCanvas: React.FC<Props> = ({ theme }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const themeRef = useRef(theme);
  themeRef.current = theme;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const mouse = { x: -9999, y: -9999 };
    const onMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };
    const onResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("resize", onResize);

    const shapes: ShapeKind[] = ["hexagon", "cube", "tetra", "ring", "octa"];
    const items: FloatingItem[] = [];

    // 1. Геометрические фигуры (каркасные многогранники)
    for (let i = 0; i < 24; i++) {
      items.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.25,
        vy: -(Math.random() * 0.35 + 0.12),
        angle: Math.random() * Math.PI * 2,
        vAngle: (Math.random() - 0.5) * 0.005,
        size: 16 + Math.random() * 18,
        kind: shapes[i % shapes.length],
        text: "",
        alpha: 0.11 + Math.random() * 0.1,
      });
    }

    // 2. Математические и криптографические формулы
    for (let i = 0; i < 18; i++) {
      items.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.2,
        vy: -(Math.random() * 0.3 + 0.1),
        angle: (Math.random() - 0.5) * 0.14,
        vAngle: 0,
        size: 12,
        kind: "formula",
        text: FORMULAS[i % FORMULAS.length],
        alpha: 0.1 + Math.random() * 0.09,
      });
    }

    let animId = 0;

    const drawPolygon = (sides: number, r: number, internalLines: boolean) => {
      ctx.beginPath();
      const pts: [number, number][] = [];
      for (let i = 0; i < sides; i++) {
        const a = (i * Math.PI * 2) / sides;
        const px = Math.cos(a) * r;
        const py = Math.sin(a) * r;
        pts.push([px, py]);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.stroke();

      if (internalLines) {
        ctx.beginPath();
        for (let i = 0; i < sides; i++) {
          ctx.moveTo(0, 0);
          ctx.lineTo(pts[i][0], pts[i][1]);
        }
        ctx.stroke();
      }
    };

    const drawIsometricCube = (r: number) => {
      drawPolygon(6, r, false);
      ctx.beginPath();
      for (let i = 0; i < 6; i += 2) {
        const a = (i * Math.PI * 2) / 6;
        ctx.moveTo(0, 0);
        ctx.lineTo(Math.cos(a) * r, Math.sin(a) * r);
      }
      ctx.stroke();
    };

    const drawRingOrbit = (r: number) => {
      ctx.beginPath();
      ctx.arc(0, 0, r, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(0, 0, r * 0.52, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(r, 0, 2.2, 0, Math.PI * 2);
      ctx.fill();
    };

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      const isDark = themeRef.current === "dark";
      const rgb = isDark ? "244, 244, 245" : "24, 24, 27";

      for (const it of items) {
        it.x += it.vx;
        it.y += it.vy;
        it.angle += it.vAngle;

        // Плавное отталкивание от курсора (эффект антигравитации)
        const dx = it.x - mouse.x;
        const dy = it.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150 && dist > 1) {
          const force = (150 - dist) / 150;
          it.x += (dx / dist) * force * 1.4;
          it.y += (dy / dist) * force * 1.4;
        }

        if (it.y < -60) {
          it.y = height + 50;
          it.x = Math.random() * width;
        }
        if (it.x < -120) it.x = width + 100;
        if (it.x > width + 120) it.x = -100;

        ctx.save();
        ctx.translate(it.x, it.y);
        ctx.rotate(it.angle);
        ctx.strokeStyle = `rgba(${rgb}, ${it.alpha})`;
        ctx.fillStyle = `rgba(${rgb}, ${it.alpha})`;
        ctx.lineWidth = 1.1;

        switch (it.kind) {
          case "formula":
            ctx.font = `500 ${it.size}px "JetBrains Mono", monospace`;
            ctx.fillText(it.text, 0, 0);
            break;
          case "hexagon":
            drawPolygon(6, it.size, true);
            break;
          case "cube":
            drawIsometricCube(it.size);
            break;
          case "tetra":
            drawPolygon(3, it.size, true);
            break;
          case "octa":
            drawPolygon(4, it.size, true);
            break;
          case "ring":
            drawRingOrbit(it.size);
            break;
        }

        ctx.restore();
      }

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0 h-full w-full"
    />
  );
};
