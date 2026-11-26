import { useState, useEffect } from "react";

// ─── Shared primitives ────────────────────────────────────────────────────────

const FlameIcon = ({ size = 16, lit = true }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M12 2C12 2 7 7.5 7 12.5C7 15.5 9.2 18 12 18C14.8 18 17 15.5 17 12.5C17 9.5 14 6 14 6C14 6 13.5 8.5 12 9C12 9 10 7 12 2Z"
      fill={lit ? "#f97316" : "#374151"} stroke={lit ? "#ea580c" : "#4b5563"} strokeWidth="1" />
    <path d="M12 13C12 13 10.5 14 10.5 15.5C10.5 16.6 11.1 17.5 12 17.5C12.9 17.5 13.5 16.6 13.5 15.5C13.5 14 12 13 12 13Z"
      fill={lit ? "#fde68a" : "#6b7280"} />
  </svg>
);

const ShieldIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6L12 2z" fill="#3b82f6" stroke="#2563eb" strokeWidth="1.5" />
    <path d="M9 12l2 2 4-4" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// ─── Step labels ──────────────────────────────────────────────────────────────
const STEPS = [
  { id: "landing",   label: "1. Landing" },
  { id: "playing",   label: "2. Playing" },
  { id: "complete",  label: "3. Complete" },
  { id: "returning", label: "4. Returning user" },
];

// ─── Streak pill (always-visible, unobtrusive) ────────────────────────────────
function StreakPill({ streak, animate = false }) {
  const [pulse, setPulse] = useState(false);
  useEffect(() => {
    if (animate) { setPulse(true); setTimeout(() => setPulse(false), 800); }
  }, [animate]);

  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "4px 10px", borderRadius: 99,
      background: streak > 0 ? "#1c1108" : "#111827",
      border: `1px solid ${streak > 0 ? "#92400e" : "#1f2937"}`,
      transition: "all 0.3s",
      boxShadow: pulse ? "0 0 12px #f9731680" : "none",
    }}>
      <FlameIcon size={14} lit={streak > 0} />
      <span style={{ color: streak > 0 ? "#fb923c" : "#4b5563", fontSize: 12, fontWeight: 700, fontFamily: "monospace" }}>
        {streak > 0 ? `${streak} day streak` : "No streak yet"}
      </span>
    </div>
  );
}

// ─── Mini calendar strip (collapsed, shown after first completion) ────────────
function MiniCalendar({ days }) {
  return (
    <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
      {days.map((d, i) => (
        <div key={i} style={{
          width: 10, height: 10, borderRadius: 2,
          background: d === "done" ? "#16a34a" : d === "missed" ? "#7f1d1d" : d === "today" ? "#1d4ed8" : "#1f2937",
          border: d === "today" ? "1px solid #3b82f6" : "1px solid transparent",
        }} title={d} />
      ))}
    </div>
  );
}

// ─── Toast notification ───────────────────────────────────────────────────────
function Toast({ show, streak }) {
  return (
    <div style={{
      position: "absolute", top: 16, right: 16, left: 16,
      background: streak === 1 ? "#0f172a" : "#1c1108",
      border: `1px solid ${streak === 1 ? "#3b82f6" : "#92400e"}`,
      borderRadius: 10, padding: "12px 14px",
      display: "flex", alignItems: "center", gap: 10,
      opacity: show ? 1 : 0, transform: show ? "translateY(0)" : "translateY(-12px)",
      transition: "all 0.35s cubic-bezier(0.34,1.56,0.64,1)",
      pointerEvents: "none",
      boxShadow: show ? "0 4px 24px #00000060" : "none",
    }}>
      {streak === 1
        ? <><ShieldIcon size={16} /><div><div style={{ color: "#93c5fd", fontSize: 13, fontWeight: 700 }}>Streak started!</div><div style={{ color: "#475569", fontSize: 11 }}>Come back tomorrow to keep it going.</div></div></>
        : <><FlameIcon size={16} lit /><div><div style={{ color: "#fb923c", fontSize: 13, fontWeight: 700 }}>{streak}-day streak! 🔥</div><div style={{ color: "#475569", fontSize: 11 }}>You're on a roll — don't break it.</div></div></>
      }
    </div>
  );
}

// ─── Fake puzzle area ─────────────────────────────────────────────────────────
function PuzzleArea({ solved, onSolve }) {
  return (
    <div style={{ background: "#0f172a", borderRadius: 12, padding: 20, border: "1px solid #1e293b" }}>
      <div style={{ color: "#64748b", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 12 }}>
        Puzzle #14 · Mar 19
      </div>
      {/* Fake clue */}
      <div style={{ color: "#e2e8f0", fontSize: 14, lineHeight: 1.6, marginBottom: 16 }}>
        A threat actor exfiltrated data using DNS TXT record queries every 30 seconds.
        This technique is called <span style={{ color: "#60a5fa" }}>DNS ___________</span>.
      </div>
      {/* Fake answer boxes */}
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {"tunneling".split("").map((ch, i) => (
          <div key={i} style={{
            width: 30, height: 36, borderRadius: 6,
            border: `1px solid ${solved ? "#16a34a" : "#334155"}`,
            background: solved ? "#14532d" : "#1e293b",
            display: "flex", alignItems: "center", justifyContent: "center",
            color: solved ? "#4ade80" : "#475569", fontWeight: 700, fontSize: 14,
            fontFamily: "monospace", textTransform: "uppercase",
            transition: "all 0.3s",
          }}>
            {solved ? ch.toUpperCase() : ""}
          </div>
        ))}
      </div>
      {!solved ? (
        <button onClick={onSolve} style={{
          padding: "10px 20px", borderRadius: 8,
          background: "#1d4ed8", border: "none",
          color: "white", fontWeight: 700, fontSize: 13, cursor: "pointer",
          letterSpacing: 0.5,
        }}>
          Submit Answer
        </button>
      ) : (
        <div style={{ color: "#4ade80", fontSize: 13, fontWeight: 600 }}>
          ✓ Correct — DNS Tunneling
        </div>
      )}
    </div>
  );
}

// ─── Streak detail drawer (expands on tap) ────────────────────────────────────
function StreakDrawer({ open, onClose, streak, days }) {
  return (
    <div style={{
      position: "absolute", bottom: 0, left: 0, right: 0,
      background: "#0f172a", borderTop: "1px solid #1e293b",
      borderRadius: "16px 16px 0 0", padding: 20,
      transform: open ? "translateY(0)" : "translateY(100%)",
      transition: "transform 0.35s cubic-bezier(0.34,1.56,0.64,1)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <span style={{ color: "#e2e8f0", fontWeight: 700, fontSize: 15 }}>Your Streak</span>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "#4b5563", cursor: "pointer", fontSize: 18 }}>✕</button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 16 }}>
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 14, textAlign: "center" }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 4 }}><FlameIcon size={20} lit={streak > 0} /></div>
          <div style={{ color: "#f97316", fontSize: 24, fontWeight: 900 }}>{streak}</div>
          <div style={{ color: "#4b5563", fontSize: 11 }}>current streak</div>
        </div>
        <div style={{ background: "#1e293b", borderRadius: 10, padding: 14, textAlign: "center" }}>
          <div style={{ color: "#34d399", fontSize: 24, fontWeight: 900 }}>{days.filter(d => d === "done" || d === "today-done").length}</div>
          <div style={{ color: "#4b5563", fontSize: 11 }}>puzzles solved</div>
        </div>
      </div>
      <div style={{ color: "#4b5563", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 8 }}>14-day history</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 5 }}>
        {days.map((d, i) => (
          <div key={i} style={{
            height: 28, borderRadius: 6,
            background: d === "done" ? "#14532d" : d === "missed" ? "#1f0a0a" : d === "today-done" ? "#14532d" : "#1e293b",
            border: `1px solid ${d === "done" ? "#16a34a" : d === "missed" ? "#7f1d1d" : d === "today-done" ? "#16a34a" : "#374151"}`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 10, color: "#6b7280", fontFamily: "monospace",
          }}>
            {i + 1}
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
        {[{ c: "#16a34a", l: "Done" }, { c: "#7f1d1d", l: "Missed" }, { c: "#374151", l: "Upcoming" }].map(x => (
          <div key={x.l} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: x.c }} />
            <span style={{ color: "#6b7280", fontSize: 11 }}>{x.l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Screens ──────────────────────────────────────────────────────────────────

function Screen({ children, label }) {
  return (
    <div style={{ position: "relative", overflow: "hidden", background: "#0a0a0f", borderRadius: 16, border: "1px solid #1e293b", minHeight: 460 }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, background: "#111827", borderBottom: "1px solid #1e293b", padding: "8px 14px", display: "flex", alignItems: "center", gap: 8, zIndex: 10 }}>
        {["#ef4444","#f59e0b","#22c55e"].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
        <span style={{ color: "#4b5563", fontSize: 11, marginLeft: 4 }}>{label}</span>
      </div>
      <div style={{ paddingTop: 40 }}>{children}</div>
    </div>
  );
}

// SCREEN 1: First-ever landing
function LandingScreen() {
  return (
    <Screen label="New user — first visit">
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldIcon />
            <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 16, letterSpacing: 2 }}>THREATDLE</span>
          </div>
          {/* Streak pill — unobtrusive, no streak yet */}
          <StreakPill streak={0} />
        </div>
        <PuzzleArea solved={false} onSolve={() => {}} />
        <div style={{ marginTop: 14, color: "#334155", fontSize: 12, textAlign: "center" }}>
          Solve today's puzzle to start your streak
        </div>
      </div>
    </Screen>
  );
}

// SCREEN 2: Mid-puzzle (streak pill visible but dormant)
function PlayingScreen() {
  return (
    <Screen label="Playing — streak pill is passive">
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldIcon />
            <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 16, letterSpacing: 2 }}>THREATDLE</span>
          </div>
          <StreakPill streak={0} />
        </div>
        {/* Fake in-progress state */}
        <div style={{ background: "#0f172a", borderRadius: 12, padding: 20, border: "1px solid #1e293b" }}>
          <div style={{ color: "#64748b", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 12 }}>
            Puzzle #14 · Mar 19
          </div>
          <div style={{ color: "#e2e8f0", fontSize: 14, lineHeight: 1.6, marginBottom: 16 }}>
            A threat actor exfiltrated data using DNS TXT record queries every 30 seconds.
            This technique is called <span style={{ color: "#60a5fa" }}>DNS ___________</span>.
          </div>
          <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
            {[..."tunneli__"].map((ch, i) => (
              <div key={i} style={{
                width: 30, height: 36, borderRadius: 6,
                border: `1px solid ${i < 7 ? "#3b82f6" : "#334155"}`,
                background: i < 7 ? "#172554" : "#1e293b",
                display: "flex", alignItems: "center", justifyContent: "center",
                color: i < 7 ? "#93c5fd" : "#475569", fontWeight: 700, fontSize: 14,
                fontFamily: "monospace", textTransform: "uppercase",
              }}>
                {i < 7 ? ch.toUpperCase() : ""}
              </div>
            ))}
          </div>
          <button style={{ padding: "10px 20px", borderRadius: 8, background: "#1d4ed8", border: "none", color: "white", fontWeight: 700, fontSize: 13, cursor: "default", opacity: 0.6 }}>
            Submit Answer
          </button>
        </div>
        <div style={{ marginTop: 14, color: "#334155", fontSize: 12, textAlign: "center" }}>↑ Streak pill sits quietly in the corner</div>
      </div>
    </Screen>
  );
}

// SCREEN 3: Puzzle solved — toast + streak updates
function CompleteScreen() {
  const [solved, setSolved] = useState(false);
  const [toastVisible, setToastVisible] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [pillAnimate, setPillAnimate] = useState(false);

  const handleSolve = () => {
    setSolved(true);
    setTimeout(() => { setToastVisible(true); setPillAnimate(true); }, 200);
    setTimeout(() => setToastVisible(false), 4000);
  };

  const days = ["done","done","done","done","done","missed","done","done","done","done","done","done","done", solved ? "done" : "upcoming"];

  return (
    <Screen label="Puzzle complete — toast + tap to expand">
      <div style={{ padding: 20 }}>
        <Toast show={toastVisible} streak={1} />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldIcon />
            <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 16, letterSpacing: 2 }}>THREATDLE</span>
          </div>
          {/* Tappable streak pill → opens drawer */}
          <div onClick={() => solved && setDrawerOpen(true)} style={{ cursor: solved ? "pointer" : "default" }}>
            <StreakPill streak={solved ? 1 : 0} animate={pillAnimate} />
          </div>
        </div>
        <PuzzleArea solved={solved} onSolve={handleSolve} />
        {solved && (
          <div style={{ marginTop: 14, textAlign: "center" }}>
            <button onClick={() => setDrawerOpen(true)} style={{ background: "none", border: "none", color: "#3b82f6", fontSize: 12, cursor: "pointer", textDecoration: "underline" }}>
              View your streak history →
            </button>
          </div>
        )}
        {!solved && <div style={{ marginTop: 14, color: "#334155", fontSize: 12, textAlign: "center" }}>← Press "Submit Answer" to see the flow</div>}
      </div>
      <StreakDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} streak={1} days={days} />
    </Screen>
  );
}

// SCREEN 4: Returning user with existing streak
function ReturningScreen() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const streak = 8;
  const days = ["done","done","done","done","done","missed","done","done","done","done","done","done","done","upcoming"];

  return (
    <Screen label="Returning user — 8-day streak at risk">
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldIcon />
            <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 16, letterSpacing: 2 }}>THREATDLE</span>
          </div>
          <div onClick={() => setDrawerOpen(true)} style={{ cursor: "pointer" }}>
            <StreakPill streak={streak} />
          </div>
        </div>
        {/* Subtle "at risk" nudge — only shown if streak is active and today unsolved */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          background: "#1c0a00", border: "1px solid #92400e",
          borderRadius: 8, padding: "8px 12px", marginBottom: 14,
        }}>
          <FlameIcon size={13} lit />
          <span style={{ color: "#fb923c", fontSize: 12 }}>Your 8-day streak resets at midnight</span>
          <div style={{ marginLeft: "auto" }}>
            <MiniCalendar days={["done","done","done","done","done","missed","done","done","done","done","done","done","done","today"]} />
          </div>
        </div>
        <PuzzleArea solved={false} onSolve={() => {}} />
        <div style={{ marginTop: 14, color: "#334155", fontSize: 12, textAlign: "center" }}>Tap flame pill to see full history</div>
      </div>
      <StreakDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} streak={streak} days={days} />
    </Screen>
  );
}

// ─── App shell ────────────────────────────────────────────────────────────────
export default function App() {
  const [activeStep, setActiveStep] = useState(0);

  const screens = [<LandingScreen />, <PlayingScreen />, <CompleteScreen />, <ReturningScreen />];

  return (
    <div style={{ minHeight: "100vh", background: "#050509", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
      <div style={{ width: "100%", maxWidth: 420 }}>

        {/* Step nav */}
        <div style={{ display: "flex", gap: 6, marginBottom: 20, overflowX: "auto" }}>
          {STEPS.map((s, i) => (
            <button key={s.id} onClick={() => setActiveStep(i)} style={{
              padding: "6px 14px", borderRadius: 99, border: "none", cursor: "pointer",
              background: activeStep === i ? "#1d4ed8" : "#111827",
              color: activeStep === i ? "white" : "#4b5563",
              fontSize: 12, fontWeight: 600, whiteSpace: "nowrap",
              transition: "all 0.15s",
            }}>
              {s.label}
            </button>
          ))}
        </div>

        {/* Active screen */}
        {screens[activeStep]}

        {/* Flow description */}
        <div style={{ marginTop: 16, background: "#0f172a", borderRadius: 10, padding: "12px 14px", border: "1px solid #1e293b" }}>
          {activeStep === 0 && <p style={{ color: "#64748b", fontSize: 12, margin: 0, lineHeight: 1.6 }}>
            New users see a <span style={{ color: "#e2e8f0" }}>passive "No streak yet" pill</span> — no modal, no onboarding wall. The puzzle is front and center. Streaks are discoverable, not forced.
          </p>}
          {activeStep === 1 && <p style={{ color: "#64748b", fontSize: 12, margin: 0, lineHeight: 1.6 }}>
            While playing, the streak pill sits quietly in the corner. <span style={{ color: "#e2e8f0" }}>Zero interruption.</span> Nothing pulses or demands attention mid-puzzle.
          </p>}
          {activeStep === 2 && <p style={{ color: "#64748b", fontSize: 12, margin: 0, lineHeight: 1.6 }}>
            On solve: a <span style={{ color: "#e2e8f0" }}>toast slides in briefly</span>, the pill animates once, then both settle. The full calendar is hidden behind a tap — available but not in the way. <span style={{ color: "#4b5563" }}>Press Submit to demo.</span>
          </p>}
          {activeStep === 3 && <p style={{ color: "#64748b", fontSize: 12, margin: 0, lineHeight: 1.6 }}>
            Returning users with an active streak see a <span style={{ color: "#fb923c" }}>single quiet warning bar</span> with a mini calendar dot trail — enough urgency without being annoying. Full detail is one tap away.
          </p>}
        </div>

        {/* Nav arrows */}
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 12 }}>
          <button onClick={() => setActiveStep(s => Math.max(0, s - 1))} disabled={activeStep === 0}
            style={{ background: "none", border: "1px solid #1e293b", borderRadius: 8, padding: "6px 16px", color: activeStep === 0 ? "#1e293b" : "#64748b", cursor: activeStep === 0 ? "default" : "pointer", fontSize: 13 }}>
            ← Prev
          </button>
          <button onClick={() => setActiveStep(s => Math.min(STEPS.length - 1, s + 1))} disabled={activeStep === STEPS.length - 1}
            style={{ background: "none", border: "1px solid #1e293b", borderRadius: 8, padding: "6px 16px", color: activeStep === STEPS.length - 1 ? "#1e293b" : "#64748b", cursor: activeStep === STEPS.length - 1 ? "default" : "pointer", fontSize: 13 }}>
            Next →
          </button>
        </div>
      </div>
    </div>
  );
}
