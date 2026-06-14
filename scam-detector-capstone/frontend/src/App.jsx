// App.jsx — Main dashboard for the Scam & Ponzi Detector
import { useState } from "react";
import InputArea from "./components/InputArea";
import TrafficLightResult from "./components/TrafficLightResult";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200 font-sans">
      {/* Subtle grid background */}
      <div
        className="fixed inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(148,163,184,1) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,1) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* ── Header ── */}
      <header className="relative z-10 border-b border-slate-800">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center gap-3">
          {/* Shield icon */}
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center text-xl shadow-lg shadow-sky-500/30">
            🛡️
          </div>
          <div>
            <h1 className="text-lg font-bold leading-none gradient-text">
              ScamGuard AI
            </h1>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Multilingual Investment Scam &amp; Ponzi Scheme Detector
            </p>
          </div>

          {/* Status badge */}
          <div className="ml-auto flex items-center gap-1.5 text-[11px] bg-emerald-900/30 border border-emerald-700/40 text-emerald-400 rounded-full px-3 py-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Live
          </div>
        </div>
      </header>

      {/* ── Main Content ── */}
      <main className="relative z-10 max-w-6xl mx-auto px-6 py-10 grid lg:grid-cols-2 gap-10">

        {/* Left Column (Input) */}
        <div className="space-y-8">

          {/* Hero */}
          <div className="space-y-3">
             <h2 className="text-3xl sm:text-4xl font-extrabold gradient-text leading-tight">
               Is This a Scam?
             </h2>
             <p className="text-slate-400 text-sm leading-relaxed max-w-md">
               Paste any suspicious WhatsApp or Telegram financial message below.
               Our AI analyses urgency signals, scam phrases, and linked domains
               to give you an instant risk score.
             </p>
          </div>

          {/* How it works pills */}
          <div className="flex flex-wrap gap-2 text-[11px] text-slate-400">
            {[
              { icon: "📝", label: "NLP Keyword" },
              { icon: "🌐", label: "WHOIS Domain Check" },
              { icon: "🤖", label: "ML Scoring" },
            ].map(({ icon, label }) => (
              <div
                key={label}
                className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700/50 rounded-full px-3 py-1"
              >
                <span>{icon}</span>
                <span>{label}</span>
              </div>
            ))}
          </div>

          {/* ── Input Card ── */}
          <div className="glass rounded-2xl p-6 space-y-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-300">
              <span>💬</span>
              <span>Paste Your Message</span>
            </div>
            <InputArea onResult={setResult} onLoading={setLoading} />
          </div>

        </div>

        {/* Right Column (Analysis & Output) */}
        <div className="space-y-8 flex flex-col justify-start w-full">
          
          {/* Loading spinner */}
          {loading && (
            <div className="flex flex-col items-center justify-center p-12 min-h-[300px] gap-4 py-8 text-slate-400 bg-slate-800/30 rounded-2xl border border-slate-700/50 shadow-inner">
               <div className="w-12 h-12 rounded-full border-4 border-slate-700 border-t-sky-500 animate-spin" />
               <p className="text-sm font-medium tracking-wide animate-pulse">Analysing threat metrics…</p>
            </div>
          )}

          {/* ── Result Card ── */}
          {!loading && result && (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
              {result.engine_status && (!result.engine_status.engine_a_online || !result.engine_status.engine_b_online) && (
                <div className="bg-amber-900/20 border border-amber-800/40 rounded-xl p-4 flex gap-3 text-amber-300/90 text-sm">
                  <span className="text-xl shrink-0">⚠️</span>
                  <div>
                    <strong className="block font-semibold text-amber-200">System Degradation Notice</strong>
                    {!result.engine_status.engine_a_online && <p className="mt-1">Primary NLP model (Engine A) is offline. Using fallback rule-based analysis.</p>}
                    {!result.engine_status.engine_b_online && <p className="mt-1">Multilingual semantic model (Engine B) is offline. Results are based on English analysis only.</p>}
                  </div>
                </div>
              )}
              <TrafficLightResult result={result} />
            </div>
          )}

          {/* ── Empty-state education block ── */}
          {!loading && !result && (
            <div className="flex flex-col space-y-4">
              <h3 className="text-lg font-bold text-slate-200 mb-1">Analysis Threat Tiers</h3>
              {[
                {
                  icon: "🔴",
                  title: "Red — High Risk Scam",
                  body: "Score 71–100. Strong scam signals: guaranteed returns, new domain, urgent CTAs.",
                  border: "border-red-800/30",
                },
                {
                  icon: "🟡",
                  title: "Yellow — Suspicious",
                  body: "Score 31–70. Some warning signs. Exercise caution before acting on the offer.",
                  border: "border-yellow-800/30",
                },
                {
                  icon: "🟢",
                  title: "Green — Safe",
                  body: "Score 0–30. No significant scam signals detected in this message.",
                  border: "border-green-800/30",
                },
              ].map(({ icon, title, body, border }) => (
                <div
                  key={title}
                  className={`bg-slate-800/30 border ${border} rounded-xl p-5 flex items-start gap-4 transition-colors hover:bg-slate-800/50`}
                >
                  <div className="text-3xl drop-shadow-sm">{icon}</div>
                  <div>
                      <h4 className="text-sm font-bold text-slate-200 tracking-wide">{title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed mt-1.5">{body}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

        </div>

      </main>

      {/* ── Footer ── */}
      <footer className="relative z-10 text-center py-6 text-xs text-slate-600 border-t border-slate-800">
        ScamGuard AI — Capstone Project · For educational purposes only
      </footer>
    </div>
  );
}
