import React, { useEffect, useRef } from 'react';

export default function GlobeCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let rotation = 0;

    const threatSignals = [
      { lat: 0.3, lon: 0.5, label: "ApexBank Phish", color: "#f43f5e", pulse: 0 },
      { lat: -0.2, lon: 1.8, label: "IG Impersonator", color: "#38bdf8", pulse: 0.5 },
      { lat: 0.6, lon: 3.2, label: "Rogue APK", color: "#fbbf24", pulse: 0.2 },
      { lat: -0.5, lon: 4.5, label: "Telegram Bot", color: "#c084fc", pulse: 0.8 },
      { lat: 0.1, lon: 5.7, label: "Lookalike Domain", color: "#00f2fe", pulse: 0.4 }
    ];

    function resize() {
      if (!canvas) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    function render() {
      const width = canvas.width;
      const height = canvas.height;
      ctx.clearRect(0, 0, width, height);

      const isDesktop = window.innerWidth > 992;
      const cx = isDesktop ? width * 0.28 : width * 0.5;
      const cy = isDesktop ? height * 0.52 : height * 0.35;
      const radius = Math.min(width, height) * (isDesktop ? 0.32 : 0.38);

      rotation += 0.003;

      // Outer Glow Aura
      const glowGrad = ctx.createRadialGradient(cx, cy, radius * 0.7, cx, cy, radius * 1.25);
      glowGrad.addColorStop(0, "rgba(56, 189, 248, 0.08)");
      glowGrad.addColorStop(0.6, "rgba(129, 140, 248, 0.04)");
      glowGrad.addColorStop(1, "transparent");
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.3, 0, Math.PI * 2);
      ctx.fill();

      // Equatorial Coordinate Ring
      ctx.strokeStyle = "rgba(56, 189, 248, 0.18)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.12, 0, Math.PI * 2);
      ctx.stroke();

      // Dashed Orbit Ring
      ctx.save();
      ctx.strokeStyle = "rgba(129, 140, 248, 0.25)";
      ctx.setLineDash([4, 8]);
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.2, rotation * 0.8, rotation * 0.8 + Math.PI * 1.5);
      ctx.stroke();
      ctx.restore();

      // Latitudes
      const latSteps = 6;
      for (let i = -latSteps; i <= latSteps; i++) {
        const lat = (i / latSteps) * (Math.PI / 2);
        const y = cy + Math.sin(lat) * radius;
        const rLat = Math.cos(lat) * radius;
        ctx.strokeStyle = i === 0 ? "rgba(56, 189, 248, 0.3)" : "rgba(56, 189, 248, 0.07)";
        ctx.lineWidth = i === 0 ? 1.5 : 0.75;
        ctx.beginPath();
        ctx.ellipse(cx, y, rLat, rLat * 0.28, 0, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Longitudes
      const lonSteps = 10;
      for (let i = 0; i < lonSteps; i++) {
        const lonAngle = (i / lonSteps) * Math.PI + rotation;
        const widthFactor = Math.sin(lonAngle);
        ctx.strokeStyle = "rgba(129, 140, 248, 0.08)";
        ctx.lineWidth = 0.75;
        ctx.beginPath();
        ctx.ellipse(cx, cy, Math.abs(widthFactor) * radius, radius, 0, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Threat Signal Beacons
      threatSignals.forEach((sig) => {
        sig.pulse = (sig.pulse + 0.015) % 1;
        const currentLon = sig.lon + rotation;
        const isFront = Math.cos(currentLon) > 0;

        if (isFront) {
          const sx = cx + Math.sin(currentLon) * Math.cos(sig.lat) * radius;
          const sy = cy + Math.sin(sig.lat) * (radius * 0.95);

          // Pulsing halo
          ctx.strokeStyle = sig.color;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(sx, sy, 4 + sig.pulse * 14, 0, Math.PI * 2);
          ctx.stroke();

          // Center solid beacon
          ctx.fillStyle = sig.color;
          ctx.beginPath();
          ctx.arc(sx, sy, 3.5, 0, Math.PI * 2);
          ctx.fill();

          // Connecting ray
          ctx.strokeStyle = "rgba(56, 189, 248, 0.15)";
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.lineTo(sx, sy);
          ctx.stroke();
        }
      });

      animationFrameId = requestAnimationFrame(render);
    }

    render();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <>
      <div className="guardian-cosmos-overlay" aria-hidden="true" />
      <canvas
        ref={canvasRef}
        id="guardianGlobeCanvas"
        className="guardian-globe-canvas"
        aria-hidden="true"
      />
    </>
  );
}
