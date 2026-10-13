/**
 * BrandShield AI - Digital Guardian Universe & Mascot Companion Engine
 * Powers:
 * - Holographic rotating 3D threat globe canvas
 * - Guardian AI mascot animated visor eyes & cursor tracking
 * - 4-Slide Onboarding Tour slider (touch swipe, keyboard, progress dots)
 * - Password visibility toggle and auth submission states
 * - Global Guardian Companion assistant across all dashboard screens
 */

document.addEventListener('DOMContentLoaded', function () {
  // =========================================================================
  // 1. HOLOGRAPHIC THREAT GLOBE CANVAS ANIMATION
  // =========================================================================
  const canvas = document.getElementById('guardianGlobeCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    let width, height;
    let rotation = 0;
    const threatSignals = [
      { lat: 0.3, lon: 0.5, label: "ApexBank Phish", color: "#f43f5e", pulse: 0 },
      { lat: -0.2, lon: 1.8, label: "IG Impersonator", color: "#38bdf8", pulse: 0.5 },
      { lat: 0.6, lon: 3.2, label: "Rogue APK", color: "#fbbf24", pulse: 0.2 },
      { lat: -0.5, lon: 4.5, label: "Telegram Bot", color: "#c084fc", pulse: 0.8 },
      { lat: 0.1, lon: 5.7, label: "Lookalike Domain", color: "#00f2fe", pulse: 0.4 }
    ];

    function resize() {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    function drawHologramGlobe() {
      ctx.clearRect(0, 0, width, height);

      // Center globe slightly to the left on desktop, centered on mobile
      const cx = window.innerWidth > 992 ? width * 0.28 : width * 0.5;
      const cy = window.innerHeight > 992 ? height * 0.52 : height * 0.35;
      const radius = Math.min(width, height) * (window.innerWidth > 992 ? 0.32 : 0.38);

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

      // Outer Equatorial Coordinate Ring
      ctx.strokeStyle = "rgba(56, 189, 248, 0.18)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.12, 0, Math.PI * 2);
      ctx.stroke();

      // Dashed Sensor Orbit Ring
      ctx.save();
      ctx.strokeStyle = "rgba(129, 140, 248, 0.25)";
      ctx.setLineDash([4, 8]);
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.2, rotation * 0.8, rotation * 0.8 + Math.PI * 1.5);
      ctx.stroke();
      ctx.restore();

      // Latitudes (Horizontal ellipse rings)
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

      // Longitudes (Vertical meridian ellipses)
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

      // Render Active Threat Signal Pulse Beacons
      threatSignals.forEach(function (sig) {
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

          // Connecting beacon ray
          ctx.strokeStyle = "rgba(56, 189, 248, 0.15)";
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.lineTo(sx, sy);
          ctx.stroke();
        }
      });

      requestAnimationFrame(drawHologramGlobe);
    }

    drawHologramGlobe();
  }

  // =========================================================================
  // 2. GUARDIAN AI MASCOT: VISOR EYES CURSOR TRACKING & BLINKING
  // =========================================================================
  const mascotContainer = document.getElementById('guardianMascotContainer');
  const pupils = document.querySelectorAll('.eye-pupil');
  const speechBubble = document.getElementById('guardianSpeech');
  const speechText = document.getElementById('guardianSpeechText');

  if (mascotContainer && pupils.length > 0) {
    // Eye tracking on cursor movement
    window.addEventListener('mousemove', function (e) {
      const rect = mascotContainer.getBoundingClientRect();
      const mascotCenterX = rect.left + rect.width / 2;
      const mascotCenterY = rect.top + rect.height / 2;

      const deltaX = (e.clientX - mascotCenterX) / (window.innerWidth / 2);
      const deltaY = (e.clientY - mascotCenterY) / (window.innerHeight / 2);

      const maxOffset = 4.5;
      const offsetX = Math.max(-maxOffset, Math.min(maxOffset, deltaX * maxOffset));
      const offsetY = Math.max(-maxOffset, Math.min(maxOffset, deltaY * maxOffset));

      pupils.forEach(function (pupil, idx) {
        const baseCx = idx === 0 ? 98 : 142;
        pupil.setAttribute('cx', baseCx + offsetX);
        pupil.setAttribute('cy', 92 + offsetY);
      });
    });

    // Natural blinking animation
    function triggerBlink() {
      pupils.forEach(function (pupil) {
        pupil.setAttribute('ry', '1');
      });
      setTimeout(function () {
        pupils.forEach(function (pupil) {
          pupil.setAttribute('ry', '8');
        });
      }, 140);

      // Schedule next random blink (3 to 6 seconds)
      const nextBlink = 3000 + Math.random() * 3000;
      setTimeout(triggerBlink, nextBlink);
    }
    setTimeout(triggerBlink, 3000);

    // Interactive speech messages on mascot hover/click
    const contextualMessages = [
      "Perimeter secure. 5 corporate brands protected against impersonation.",
      "Analyzing neural bot entropy across social networks.",
      "VirusTotal v3 & Gemini explainability modules synchronized.",
      "Drebin permission model active for Android APK verification.",
      "Ready to inspect rogue domains and lookalike profiles, Analyst."
    ];
    let msgIdx = 0;

    mascotContainer.addEventListener('click', function () {
      msgIdx = (msgIdx + 1) % contextualMessages.length;
      if (speechText) {
        speechText.style.opacity = 0;
        setTimeout(function () {
          speechText.textContent = contextualMessages[msgIdx];
          speechText.style.opacity = 1;
        }, 200);
      }
    });
  }

  // =========================================================================
  // 3. PASSWORD VISIBILITY TOGGLES
  // =========================================================================
  function setupPasswordToggle(btnId, inputId) {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (btn && input) {
      btn.addEventListener('click', function () {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.innerHTML = isPassword ? '<i class="bi bi-eye-slash text-info"></i>' : '<i class="bi bi-eye"></i>';
      });
    }
  }

  setupPasswordToggle('toggleLoginPassword', 'loginPassword');
  setupPasswordToggle('toggleSignupPassword', 'signupPassword');

  // =========================================================================
  // 4. QUICK-FILL DEMO CREDENTIALS
  // =========================================================================
  const btnQuickFill = document.getElementById('btnQuickFill');
  if (btnQuickFill) {
    btnQuickFill.addEventListener('click', function () {
      const uInput = document.getElementById('loginUsername');
      const pInput = document.getElementById('loginPassword');
      if (uInput && pInput) {
        uInput.value = 'analyst@brandshield.ai';
        pInput.value = 'CyberShield2026!';
        
        // Highlight inputs with neon feedback
        [uInput, pInput].forEach(function (el) {
          el.style.borderColor = 'var(--bs-neon-cyan)';
          el.style.boxShadow = '0 0 16px rgba(0, 242, 254, 0.4)';
          setTimeout(function () {
            el.style.borderColor = '';
            el.style.boxShadow = '';
          }, 1200);
        });

        if (speechText) {
          speechText.textContent = "Demo credentials loaded: analyst@brandshield.ai. Click Authenticate to enter!";
        }
      }
    });
  }

  // =========================================================================
  // 5. FORM SUBMIT LOADING STATE
  // =========================================================================
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', function () {
      const btn = document.getElementById('btnLoginSubmit');
      if (btn) {
        btn.disabled = true;
        const textSpan = btn.querySelector('.btn-text');
        const spinSpan = btn.querySelector('.btn-spinner');
        if (textSpan && spinSpan) {
          textSpan.classList.add('d-none');
          spinSpan.classList.remove('d-none');
        }
      }
    });
  }

  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', function () {
      const btn = document.getElementById('btnSignupSubmit');
      if (btn) {
        btn.disabled = true;
        const textSpan = btn.querySelector('.btn-text');
        const spinSpan = btn.querySelector('.btn-spinner');
        if (textSpan && spinSpan) {
          textSpan.classList.add('d-none');
          spinSpan.classList.remove('d-none');
        }
      }
    });
  }

  // =========================================================================
  // 6. 4-SLIDE ONBOARDING SLIDER CONTROLLER
  // =========================================================================
  const sliderModalEl = document.getElementById('onboardingModal');
  const slides = document.querySelectorAll('.guardian-slide');
  const dots = document.querySelectorAll('.slider-progress-dots .dot');
  const btnPrev = document.getElementById('btnPrevSlide');
  const btnNext = document.getElementById('btnNextSlide');
  const btnFinish = document.getElementById('btnFinishTour');
  const counterText = document.getElementById('sliderCounter');

  let currentSlide = 1;
  const totalSlides = slides.length || 4;

  function showSlide(index) {
    if (index < 1) index = 1;
    if (index > totalSlides) index = totalSlides;
    currentSlide = index;

    // Update slides visibility
    slides.forEach(function (slide) {
      const slideNum = parseInt(slide.getAttribute('data-slide'), 10);
      slide.classList.toggle('active', slideNum === currentSlide);
    });

    // Update progress dots
    dots.forEach(function (dot) {
      const dotNum = parseInt(dot.getAttribute('data-slide'), 10);
      dot.classList.toggle('active', dotNum === currentSlide);
    });

    // Update counter
    if (counterText) {
      counterText.textContent = `SLIDE ${currentSlide} / ${totalSlides}`;
    }

    // Update navigation button states
    if (btnPrev) btnPrev.disabled = currentSlide === 1;

    if (currentSlide === totalSlides) {
      if (btnNext) btnNext.classList.add('d-none');
      if (btnFinish) btnFinish.classList.remove('d-none');
    } else {
      if (btnNext) btnNext.classList.remove('d-none');
      if (btnFinish) btnFinish.classList.add('d-none');
    }
  }

  if (btnPrev) {
    btnPrev.addEventListener('click', function () {
      showSlide(currentSlide - 1);
    });
  }

  if (btnNext) {
    btnNext.addEventListener('click', function () {
      showSlide(currentSlide + 1);
    });
  }

  dots.forEach(function (dot) {
    dot.addEventListener('click', function () {
      const target = parseInt(this.getAttribute('data-slide'), 10);
      showSlide(target);
    });
  });

  // Keyboard navigation for slider (ArrowLeft, ArrowRight)
  window.addEventListener('keydown', function (e) {
    if (!sliderModalEl || !sliderModalEl.classList.contains('show')) return;
    if (e.key === 'ArrowRight') {
      showSlide(currentSlide + 1);
    } else if (e.key === 'ArrowLeft') {
      showSlide(currentSlide - 1);
    }
  });

  // Touch Swipe Gesture Detection for Mobile Devices
  let touchStartX = 0;
  let touchEndX = 0;
  const sliderWrapper = document.getElementById('guardianSlider');
  if (sliderWrapper) {
    sliderWrapper.addEventListener('touchstart', function (e) {
      touchStartX = e.changedTouches[0].screenX;
    }, { passive: true });

    sliderWrapper.addEventListener('touchend', function (e) {
      touchEndX = e.changedTouches[0].screenX;
      handleSwipe();
    }, { passive: true });

    function handleSwipe() {
      const diff = touchEndX - touchStartX;
      if (Math.abs(diff) > 45) {
        if (diff < 0) {
          // Swipe Left -> Next
          showSlide(currentSlide + 1);
        } else {
          // Swipe Right -> Prev
          showSlide(currentSlide - 1);
        }
      }
    }
  }

  // Tour Triggers
  const tourModal = sliderModalEl ? new bootstrap.Modal(sliderModalEl) : null;
  const btnLaunchTour = document.getElementById('btnLaunchTour');
  const footerTourTrigger = document.getElementById('footerTourTrigger');
  const btnLaunchTourBase = document.getElementById('btnLaunchTourBase');
  const menuTourTrigger = document.getElementById('menuTourTrigger');
  const drawerTourTrigger = document.getElementById('drawerTourTrigger');

  function openTourModal(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (tourModal) {
      showSlide(1);
      tourModal.show();
    }
  }

  if (btnLaunchTour) btnLaunchTour.addEventListener('click', openTourModal);
  if (footerTourTrigger) footerTourTrigger.addEventListener('click', openTourModal);
  if (btnLaunchTourBase) btnLaunchTourBase.addEventListener('click', openTourModal);
  if (menuTourTrigger) menuTourTrigger.addEventListener('click', openTourModal);
  if (drawerTourTrigger) drawerTourTrigger.addEventListener('click', openTourModal);

  // Mark Tour completion in localStorage
  if (btnFinish) {
    btnFinish.addEventListener('click', function () {
      localStorage.setItem('brandshield_onboarded', 'true');
    });
  }
});
