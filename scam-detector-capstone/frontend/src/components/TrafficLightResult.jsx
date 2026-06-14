// TrafficLightResult.jsx
// Renders the Red / Yellow / Green verdict with animated glow and reasons list.

const CONFIG = {
  red: {
    label: "HIGH RISK — Likely Scam",
    emoji: "🔴",
    bg: "bg-red-950/60",
    border: "border-red-500/50",
    pill: "bg-red-500",
    glow: "animate-[glowRed_2s_ease-in-out_infinite]",
    glowStyle: {
      boxShadow: "0 0 32px rgba(239,68,68,0.7)",
    },
    title: "text-red-400",
    bar: "bg-red-500",
    icon: "🚨",
    badge: "bg-red-500/20 text-red-300 border-red-500/30",
  },
  yellow: {
    label: "SUSPICIOUS — Proceed with Caution",
    emoji: "🟡",
    bg: "bg-yellow-950/60",
    border: "border-yellow-500/50",
    pill: "bg-yellow-400",
    glow: "animate-[glowYellow_2s_ease-in-out_infinite]",
    glowStyle: {
      boxShadow: "0 0 32px rgba(250,204,21,0.7)",
    },
    title: "text-yellow-400",
    bar: "bg-yellow-400",
    icon: "⚠️",
    badge: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  },
  green: {
    label: "SAFE — No Scam Signals Detected",
    emoji: "🟢",
    bg: "bg-green-950/60",
    border: "border-green-500/50",
    pill: "bg-green-500",
    glow: "animate-[glowGreen_2s_ease-in-out_infinite]",
    glowStyle: {
      boxShadow: "0 0 32px rgba(34,197,94,0.7)",
    },
    title: "text-green-400",
    bar: "bg-green-500",
    icon: "✅",
    badge: "bg-green-500/20 text-green-300 border-green-500/30",
  },
};

export default function TrafficLightResult({ result }) {
  if (!result) return null;

  const { traffic_light, final_fraud_score, engine_breakdown, reasons } = result;

  // Guard against missing properties while we wait for backend updates to sync
  const safe_traffic_light = traffic_light || result.color || "green";
  const safe_score = final_fraud_score !== undefined ? final_fraud_score : (result.score || 0);

  const cfg = CONFIG[safe_traffic_light] ?? CONFIG.green;

  return (
    <div
      id="result-panel"
      className={`
        rounded-2xl border p-6 space-y-5 transition-all duration-500
        ${cfg.bg} ${cfg.border}
      `}
    >
      {/* — Traffic Light Header — */}
      <div className="flex items-center gap-5">
        {/* Glowing orb */}
        <div
          className={`w-16 h-16 rounded-full ${cfg.pill} flex-shrink-0`}
          style={cfg.glowStyle}
        />

        <div>
          <p className="text-xs font-semibold uppercase tracking-widest text-slate-400 mb-1">
            Analysis Result
          </p>
          <h2 className={`text-xl font-bold leading-tight ${cfg.title}`}>
            {cfg.emoji} {cfg.label}
          </h2>
        </div>
      </div>

      {/* — Score Bar — */}
      <div>
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs text-slate-400 font-medium">Risk Score</span>
          <span className={`text-2xl font-extrabold ${cfg.title}`}>
            {safe_score}<span className="text-sm font-normal text-slate-400">/100</span>
          </span>
        </div>
        <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-700 ease-out ${cfg.bar}`}
            style={{ width: `${safe_score}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-slate-600 mt-1">
          <span>0 Safe</span>
          <span>50 Caution</span>
          <span>100 Scam</span>
        </div>
      </div>

      {/* — Engine Breakdown Cards — */}
      {engine_breakdown && (
        <div className="grid grid-cols-2 gap-4 mt-6">
          <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-4 text-center shadow-inner">
            <div className="text-[11px] uppercase tracking-widest text-sky-400 font-semibold mb-1">Engine A</div>
            <div className="text-[10px] text-slate-400 mb-3">XGBoost Score</div>
            <div className="text-2xl font-bold text-slate-200">{engine_breakdown.engine_a_xgboost}<span className="text-xs text-slate-500 font-normal">/100</span></div>
          </div>
          <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-4 text-center shadow-inner">
            <div className="text-[11px] uppercase tracking-widest text-indigo-400 font-semibold mb-1">Engine B</div>
            <div className="text-[10px] text-slate-400 mb-3">XLM-RoBERTa Score</div>
            <div className="text-2xl font-bold text-slate-200">{engine_breakdown.engine_b_xlm_roberta}<span className="text-xs text-slate-500 font-normal">/100</span></div>
          </div>
        </div>
      )}

      {/* — Detected Signals — */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
          {cfg.icon} Detected Signals
          <span className={`ml-auto text-xs px-2 py-0.5 rounded-full border ${cfg.badge}`}>
            {reasons.length} found
          </span>
        </h3>

        <ul className="space-y-2">
          {reasons.map((reason, i) => (
            <li
              key={i}
              className="text-sm text-slate-300 bg-slate-800/50 rounded-lg px-4 py-2.5 leading-snug border border-slate-700/50"
            >
              {reason}
            </li>
          ))}
        </ul>
      </div>

      {/* — Disclaimer — */}
      <p className="text-[10px] text-slate-600 border-t border-slate-700/50 pt-3">
        ⓘ This analysis is automated and may not be 100% accurate.
        Always verify financial offers with a licensed advisor before investing.
      </p>
    </div>
  );
}
