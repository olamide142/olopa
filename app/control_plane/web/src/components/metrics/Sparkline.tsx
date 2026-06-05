import { useEffect, useRef } from "react";

interface SparklineProps {
  data: number[];
  color: string;
  height?: number;
}

/** Lightweight canvas sparkline with a soft area fill. Redraws on data change. */
export function Sparkline({ data, color, height = 36 }: SparklineProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = canvas.offsetWidth || 160;
    const h = height;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    if (data.length < 2) return;
    const min = Math.min(...data) * 0.97;
    const max = Math.max(...data) * 1.03;
    const span = max - min || 1;
    const x = (i: number) => (i / (data.length - 1)) * w;
    const y = (v: number) => h - ((v - min) / span) * (h - 4) - 2;

    ctx.beginPath();
    data.forEach((v, i) => (i === 0 ? ctx.moveTo(x(i), y(v)) : ctx.lineTo(x(i), y(v))));
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = "round";
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + "33");
    grad.addColorStop(1, color + "00");
    ctx.fillStyle = grad;
    ctx.fill();
  }, [data, color, height]);

  return <canvas ref={canvasRef} className="w-full" style={{ height }} />;
}
