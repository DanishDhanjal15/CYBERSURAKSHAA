// InputArea.jsx
// Textarea + Analyze button. Sends POST to FastAPI and lifts result to App.

import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/analyze";

const PLACEHOLDER_TEXT =
  `Paste a WhatsApp or Telegram message here…\n\nExample:\n"Join our exclusive crypto trading group! Guaranteed 30% weekly returns. Act now — limited slots. Visit quickprofit123.xyz"`;

export default function InputArea({ onResult, onLoading }) {
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async () => {
    if (!message.trim()) {
      setError("Please enter a message to analyze.");
      return;
    }
    setError("");
    onLoading(true);

    try {
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });

      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail?.detail || `Server error: ${res.status}`);
      }

      const data = await res.json();
      onResult(data);
    } catch (err) {
      setError(
        err.message.includes("Failed to fetch")
          ? "Cannot reach the backend. Make sure FastAPI is running on port 8000."
          : err.message
      );
      onResult(null);
    } finally {
      onLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Textarea */}
      <div className="relative">
        <textarea
          id="message-input"
          className="
            w-full min-h-[160px] rounded-xl px-5 py-4
            bg-slate-800/70 border border-slate-700
            text-slate-200 placeholder-slate-500
            text-sm leading-relaxed
            focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent
            resize-y transition-all duration-200
          "
          placeholder={PLACEHOLDER_TEXT}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          aria-label="Message input"
        />
        {/* Character count */}
        <span className="absolute bottom-3 right-4 text-xs text-slate-500">
          {message.length} chars
        </span>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg bg-red-900/30 border border-red-700/50 px-4 py-3 text-sm text-red-300">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* Actions row */}
      <div className="flex items-center justify-between gap-4">
        <button
          id="clear-btn"
          onClick={() => { setMessage(""); onResult(null); setError(""); }}
          className="text-sm text-slate-400 hover:text-slate-200 transition-colors"
          type="button"
        >
          Clear
        </button>

        <button
          id="analyze-btn"
          onClick={handleSubmit}
          className="
            flex items-center gap-2 px-8 py-3 rounded-xl text-sm font-semibold
            bg-gradient-to-r from-sky-500 to-indigo-600
            hover:from-sky-400 hover:to-indigo-500
            text-white shadow-lg shadow-sky-500/20
            active:scale-95 transition-all duration-150 cursor-pointer
          "
          type="button"
        >
          <span>🔍</span>
          <span>Analyze Message</span>
        </button>
      </div>
    </div>
  );
}
