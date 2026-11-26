import { useState } from "react";

const PUZZLES = [
  { day: 1, label: "Mar 6", completed: true },
  { day: 2, label: "Mar 7", completed: true },
  { day: 3, label: "Mar 8", completed: true },
  { day: 4, label: "Mar 9", completed: true },
  { day: 5, label: "Mar 10", completed: true },
  { day: 6, label: "Mar 11", completed: false }, // missed
  { day: 7, label: "Mar 12", completed: true },
  { day: 8, label: "Mar 13", completed: true },
  { day: 9, label: "Mar 14", completed: true },
  { day: 10, label: "Mar 15", completed: true },
  { day: 11, label: "Mar 16", completed: true },
  { day: 12, label: "Mar 17", completed: true },
  { day: 13, label: "Mar 18", completed: true },
  { day: 14, label: "Mar 19", completed: false }, // today, not yet done
];

function getCurrentStreak(puzzles) {
  let streak = 0;
  // Walk backwards from yesterday (skip today if not done)
  const todayIdx = puzzles.length - 1;
  const startIdx = puzzles[todayIdx].completed ? todayIdx : todayIdx - 1;
  for (let i = startIdx; i >= 0; i--) {
    if (puzzles[i].completed) streak++;
    else break;
  }
  return streak;
}

function getLongestStreak(puzzles) {
  let max = 0, current = 0;
  for (const p of puzzles) {
    if (p.completed) { current++; max = Math.max(max, current); }
    else current = 0;
  }
  return max;
}

const FlameIcon = ({ size = 24, lit = true }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path
      d="M12 2C12 2 7 7.5 7 12.5C7 15.5 9.2 18 12 18C14.8 18 17 15.5 17 12.5C17 9.5 14 6 14 6C14 6 13.5 8.5 12 9C12 9 10 7 12 2Z"
      fill={lit ? "#f97316" : "#374151"}
      stroke={lit ? "#ea580c" : "#4b5563"}
      strokeWidth="1"
    />
    <path
      d="M12 13C12 13 10.5 14 10.5 15.5C10.5 16.6 11.1 17.5 12 17.5C12.9 17.5 13.5 16.6 13.5 15.5C13.5 14 12 13 12 13Z"
      fill={lit ? "#fde68a" : "#6b7280"}
    />
  </svg>
);

const ShieldIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6L12 2z"
      fill="#3b82f6" stroke="#2563eb" strokeWidth="1.5" />
    <path d="M9 12l2 2 4-4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

function DayTile({ puzzle, isToday }) {
  const [hovered, setHovered] = useState(false);

  const base = "relative flex flex-col items-center rounded-lg p-2 cursor-default transition-all duration-150 ";
  let style = {};
  let dotColor = "";

  if (isToday && !puzzle.completed) {
    style = { background: hovered ? "#1e3a5f" : "#172554", border: "2px solid #3b82f6", boxShadow: hovered ? "0 0 12px #3b82f680" : "none" };
    dotColor = "#3b82f6";
  } else if (puzzle.completed) {
    style = { background: "#14532d", border: "2px solid #16a34a" };
    dotColor = "#4ade80";
  } else {
    style = { background: "#1f1f1f", border: "2px solid #374151" };
    dotColor = "#ef4444";
  }

  return (
    <div
      className={base}
      style={style}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span style={{ fontSize: 10, color: "#9ca3af", fontFamily: "monospace" }}>{puzzle.label}</span>
      <div style={{ margin: "6px 0" }}>
        {isToday && !puzzle.completed ? (
          <div style={{ width: 20, height: 20, borderRadius: "50%", border: "2px dashed #3b82f6", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#3b82f6" }} />
          </div>
        ) : puzzle.completed ? (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" fill="#16a34a" />
            <path d="M7 12l4 4 6-6" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" fill="#7f1d1d" />
            <path d="M8 8l8 8M16 8l-8 8" stroke="#fca5a5" strokeWidth="2" strokeLinecap="round" />
          </svg>
        )}
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color: dotColor, fontFamily: "monospace" }}>#{puzzle.day}</span>
    </div>
  );
}

export default function StreakIndicator() {
  const [puzzles, setPuzzles] = useState(PUZZLES);
  const currentStreak = getCurrentStreak(puzzles);
  const longestStreak = getLongestStreak(puzzles);
  const totalCompleted = puzzles.filter(p => p.completed).length;
  const todayDone = puzzles[puzzles.length - 1].completed;

  const toggleToday = () => {
    setPuzzles(prev => prev.map((p, i) => i === prev.length - 1 ? { ...p, completed: !p.completed } : p));
  };

  const getMessage = () => {
    if (todayDone) return { text: "Threat neutralized. Stay sharp.", color: "#4ade80" };
    if (currentStreak >= 7) return { text: `${currentStreak}-day streak! Don't let it die.`, color: "#f97316" };
    if (currentStreak >= 3) return { text: `${currentStreak} days strong — finish today's puzzle!`, color: "#facc15" };
    return { text: "Today's threat is waiting. Are you ready?", color: "#60a5fa" };
  };

  const msg = getMessage();

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0a0f",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "'Segoe UI', system-ui, sans-serif",
      padding: 24,
    }}>
      <div style={{ width: "100%", maxWidth: 560 }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
          <ShieldIcon />
          <span style={{ color: "#e2e8f0", fontWeight: 800, fontSize: 22, letterSpacing: 2, textTransform: "uppercase" }}>
            Threatdle
          </span>
          <span style={{ marginLeft: "auto", color: "#4b5563", fontSize: 12, fontFamily: "monospace" }}>
            STREAK TRACKER
          </span>
        </div>

        {/* Streak Stats */}
        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20
        }}>
          {[
            { label: "Current Streak", value: currentStreak, suffix: currentStreak === 1 ? "day" : "days", icon: <FlameIcon size={20} lit={currentStreak > 0} />, color: currentStreak > 0 ? "#f97316" : "#6b7280" },
            { label: "Longest Streak", value: longestStreak, suffix: longestStreak === 1 ? "day" : "days", icon: <FlameIcon size={20} lit={longestStreak > 0} />, color: "#a78bfa" },
            { label: "Completed", value: `${totalCompleted}/${puzzles.length}`, suffix: "puzzles", icon: <ShieldIcon />, color: "#34d399" },
          ].map(stat => (
            <div key={stat.label} style={{
              background: "#111827", border: "1px solid #1f2937",
              borderRadius: 12, padding: "16px 12px", textAlign: "center"
            }}>
              <div style={{ display: "flex", justifyContent: "center", marginBottom: 6 }}>{stat.icon}</div>
              <div style={{ fontSize: 26, fontWeight: 900, color: stat.color, lineHeight: 1 }}>{stat.value}</div>
              <div style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}>{stat.suffix}</div>
              <div style={{ fontSize: 10, color: "#4b5563", marginTop: 4, textTransform: "uppercase", letterSpacing: 1 }}>{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Motivational message */}
        <div style={{
          background: "#0f172a", border: `1px solid ${msg.color}40`,
          borderRadius: 10, padding: "12px 16px", marginBottom: 20,
          display: "flex", alignItems: "center", gap: 10
        }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: msg.color, flexShrink: 0 }} />
          <span style={{ color: msg.color, fontSize: 14, fontWeight: 600 }}>{msg.text}</span>
        </div>

        {/* Puzzle grid */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: "#6b7280", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 10 }}>
            Puzzle History
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 6 }}>
            {puzzles.map((puzzle, i) => (
              <DayTile key={puzzle.day} puzzle={puzzle} isToday={i === puzzles.length - 1} />
            ))}
          </div>
        </div>

        {/* Legend */}
        <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
          {[
            { color: "#16a34a", label: "Completed" },
            { color: "#ef4444", label: "Missed" },
            { color: "#3b82f6", label: "Today" },
          ].map(l => (
            <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: l.color }} />
              <span style={{ color: "#6b7280", fontSize: 11 }}>{l.label}</span>
            </div>
          ))}
        </div>

        {/* CTA */}
        {!todayDone && (
          <button
            onClick={toggleToday}
            style={{
              width: "100%", padding: "14px 0", borderRadius: 10,
              background: "linear-gradient(135deg, #1d4ed8, #2563eb)",
              border: "none", color: "white", fontWeight: 700, fontSize: 15,
              cursor: "pointer", letterSpacing: 1, textTransform: "uppercase",
              boxShadow: "0 0 20px #3b82f640", transition: "opacity 0.15s"
            }}
            onMouseEnter={e => e.target.style.opacity = 0.85}
            onMouseLeave={e => e.target.style.opacity = 1}
          >
            ⚡ Play Today's Puzzle — #14
          </button>
        )}

        {todayDone && (
          <div style={{
            width: "100%", padding: "14px 0", borderRadius: 10,
            background: "#14532d", border: "1px solid #16a34a",
            color: "#4ade80", fontWeight: 700, fontSize: 15,
            textAlign: "center", letterSpacing: 1, textTransform: "uppercase"
          }}>
            ✓ Today's Puzzle Complete
          </div>
        )}

        {/* Toggle demo note */}
        {todayDone && (
          <button
            onClick={toggleToday}
            style={{
              marginTop: 10, width: "100%", padding: "8px 0", borderRadius: 8,
              background: "transparent", border: "1px dashed #374151",
              color: "#4b5563", fontSize: 12, cursor: "pointer"
            }}
          >
            ↩ Reset today (demo)
          </button>
        )}
      </div>
    </div>
  );
}
