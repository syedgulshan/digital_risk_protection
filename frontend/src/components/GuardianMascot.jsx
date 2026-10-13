import React, { useState, useEffect, useRef } from 'react';

const MESSAGES = [
  "Greetings, Analyst. BrandShield Neural Net is monitoring 5 brand perimeters.",
  "Perimeter secure. 5 corporate brands protected against impersonation.",
  "Analyzing neural bot entropy across social networks.",
  "VirusTotal v3 & Gemini explainability modules synchronized.",
  "Drebin permission model active for Android APK verification.",
  "Ready to inspect rogue domains and lookalike profiles, Analyst."
];

export default function GuardianMascot({ customMessage }) {
  const [msgIndex, setMsgIndex] = useState(0);
  const [isBlinking, setIsBlinking] = useState(false);
  const [pupilOffset, setPupilOffset] = useState({ x: 0, y: 0 });
  const containerRef = useRef(null);

  // Mouse eye tracking
  useEffect(() => {
    function handleMouseMove(e) {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;

      const deltaX = (e.clientX - centerX) / (window.innerWidth / 2);
      const deltaY = (e.clientY - centerY) / (window.innerHeight / 2);

      const maxOffset = 4.5;
      const x = Math.max(-maxOffset, Math.min(maxOffset, deltaX * maxOffset));
      const y = Math.max(-maxOffset, Math.min(maxOffset, deltaY * maxOffset));

      setPupilOffset({ x, y });
    }

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Blinking effect
  useEffect(() => {
    let blinkTimer;
    function scheduleBlink() {
      setIsBlinking(true);
      setTimeout(() => {
        setIsBlinking(false);
        blinkTimer = setTimeout(scheduleBlink, 3000 + Math.random() * 3000);
      }, 150);
    }
    blinkTimer = setTimeout(scheduleBlink, 2500);
    return () => clearTimeout(blinkTimer);
  }, []);

  const handleClickMascot = () => {
    setMsgIndex((prev) => (prev + 1) % MESSAGES.length);
  };

  const currentText = customMessage || MESSAGES[msgIndex];

  return (
    <div className="guardian-mascot-container" id="guardianMascotContainer" ref={containerRef} onClick={handleClickMascot}>
      {/* Holographic Rings Behind Mascot */}
      <div className="hologram-ring-outer" />
      <div className="hologram-ring-inner" />

      {/* Custom AI Guardian SVG Mascot */}
      <div className="guardian-mascot-figure" id="guardianFigure" aria-label="Guardian AI Cyber Mascot" style={{ cursor: 'pointer' }}>
        <svg viewBox="0 0 240 240" width="220" height="220" className="guardian-mascot-svg">
          <defs>
            <filter id="neonGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="bodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#1e293b" />
              <stop offset="50%" stopColor="#0f172a" />
              <stop offset="100%" stopColor="#020617" />
            </linearGradient>
            <linearGradient id="armorGlow" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#00f2fe" />
              <stop offset="100%" stopColor="#818cf8" />
            </linearGradient>
          </defs>

          {/* Floating Cyber Wings */}
          <path d="M40 90 L10 110 L30 130 Z" fill="#0ea5e9" opacity="0.6" className="mascot-wing left" />
          <path d="M200 90 L230 110 L210 130 Z" fill="#0ea5e9" opacity="0.6" className="mascot-wing right" />

          {/* Mascot Robot Head */}
          <rect x="60" y="45" width="120" height="95" rx="35" fill="url(#bodyGrad)" stroke="url(#armorGlow)" strokeWidth="3" filter="url(#neonGlow)" />

          {/* Visor Screen */}
          <rect x="75" y="65" width="90" height="55" rx="18" fill="#030712" stroke="#00f2fe" strokeWidth="1.5" />

          {/* Animated Visor Eyes */}
          <g className="guardian-eyes-group" id="guardianEyes">
            {/* Left Eye */}
            <ellipse
              cx={98 + pupilOffset.x}
              cy={92 + pupilOffset.y}
              rx="10"
              ry={isBlinking ? 1 : 8}
              fill="#00f2fe"
              className="eye-pupil left"
              filter="url(#neonGlow)"
            />
            <circle cx={96 + pupilOffset.x} cy={90 + pupilOffset.y} r={isBlinking ? 0 : 3} fill="#ffffff" />
            {/* Right Eye */}
            <ellipse
              cx={142 + pupilOffset.x}
              cy={92 + pupilOffset.y}
              rx="10"
              ry={isBlinking ? 1 : 8}
              fill="#00f2fe"
              className="eye-pupil right"
              filter="url(#neonGlow)"
            />
            <circle cx={140 + pupilOffset.x} cy={90 + pupilOffset.y} r={isBlinking ? 0 : 3} fill="#ffffff" />
          </g>

          {/* Forehead Crest Badge */}
          <polygon points="120,48 128,60 112,60" fill="#38bdf8" />

          {/* Ear Headset Modules */}
          <rect x="48" y="75" width="14" height="35" rx="6" fill="#0284c7" stroke="#38bdf8" strokeWidth="1.5" />
          <rect x="178" y="75" width="14" height="35" rx="6" fill="#0284c7" stroke="#38bdf8" strokeWidth="1.5" />

          {/* Robot Torso */}
          <path d="M85 145 L155 145 L145 200 L95 200 Z" fill="url(#bodyGrad)" stroke="#38bdf8" strokeWidth="2" />

          {/* Chest Shield Reactor Core */}
          <circle cx="120" cy="170" r="16" fill="rgba(56, 189, 248, 0.2)" stroke="#00f2fe" strokeWidth="2" className="reactor-core" />
          <polygon points="120,160 130,174 110,174" fill="#38bdf8" className="reactor-crest" />

          {/* Floating Thruster Glow */}
          <ellipse cx="120" cy="210" rx="20" ry="6" fill="#38bdf8" opacity="0.75" className="thruster-glow" />
        </svg>
      </div>

      {/* Dialog Speech Bubble */}
      <div className="guardian-speech-bubble" id="guardianSpeech">
        <i className="bi bi-cpu-fill text-info me-1" />
        <span id="guardianSpeechText">{currentText}</span>
      </div>
    </div>
  );
}
