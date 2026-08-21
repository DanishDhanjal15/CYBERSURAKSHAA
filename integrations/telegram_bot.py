#!/usr/bin/env python3
"""
integrations/telegram_bot.py
----------------------------
Citizen-facing Telegram bot.

Rationale
=========
The analyst console is the wrong shape for the person who is actually being
defrauded. Scam messages arrive on WhatsApp and Telegram, they are forwarded
between family members, and the decision to pay is made within minutes. A
platform that requires the victim to open a browser, register an account and
upload a screenshot has already lost.

Forwarding a message to a bot is the one interaction that fits: it costs the
user nothing, it happens inside the app the scam arrived in, and it takes
seconds.

Dependencies
============
Deliberately none beyond the standard library. This talks to the Telegram Bot
API over plain HTTPS with `urllib`, and to CYBERSURAKSHAA over its own public
API. Adding `python-telegram-bot` would pull a large async stack into a script
whose entire job is two HTTP calls in a loop.

Running it
==========
    export TELEGRAM_BOT_TOKEN=...        # from @BotFather
    export CYBERSURAKSHAA_API_KEY=...    # issued by the platform
    export CYBERSURAKSHAA_URL=http://localhost:5000
    python integrations/telegram_bot.py

What it deliberately does not do
================================
* It does not store chat identifiers, usernames or any other personal data.
  The platform receives the message text and nothing that identifies who sent
  it. A service that helps scam victims must not itself become a database of
  scam victims.
* It does not write to the intelligence graph. Submissions are quarantined by
  the API and promoted by an analyst -- otherwise anyone could forge arbitrary
  links between identifiers simply by messaging the bot.
* It never says "this is safe". The strongest clean result it will report is
  that no scam patterns were found in the text, followed by what that does not
  cover.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TELEGRAM_API = "https://api.telegram.org/bot%s/%s"

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
PLATFORM_URL = os.environ.get("CYBERSURAKSHAA_URL", "http://localhost:5000").rstrip("/")
API_KEY = os.environ.get("CYBERSURAKSHAA_API_KEY", "")

POLL_TIMEOUT = 30          # long-poll; the API holds the connection open
REQUEST_TIMEOUT = 45
MAX_MESSAGE_LENGTH = 8000

BAND_HEADER = {
    "LIKELY_SCAM": "\U0001F6A8 *This looks like a scam.*",
    "UNSURE": "❓ *I cannot tell from the text alone.*",
    "SAFE": "✅ *No scam patterns found in this text.*",
}

WELCOME = (
    "*CYBERSURAKSHAA scam check*\n\n"
    "Forward me any message you are unsure about — an SMS, a WhatsApp "
    "forward, an email, an investment offer — and I will tell you what "
    "patterns it matches and what to do next.\n\n"
    "I do not store who you are. I only look at the text you send.\n\n"
    "*If you have already paid, stop and call 1930 now.* The first hours are "
    "when a transfer can still be held.\n\n"
    "Commands:\n"
    "/help — this message\n"
    "/report — how to file a formal complaint\n"
    "/privacy — what happens to what you send me"
)

REPORT_TEXT = (
    "*Reporting a cyber fraud in India*\n\n"
    "1. *Call 1930* — the national cyber-fraud helpline. Do this first if "
    "money has moved; a transfer reported quickly can sometimes be held.\n"
    "2. *cybercrime.gov.in* — the National Cybercrime Reporting Portal. "
    "File here for a formal complaint and an acknowledgement number.\n"
    "3. *Sanchar Saathi (sancharsaathi.gov.in)* — report the phone number "
    "or SMS sender through Chakshu.\n"
    "4. *Your bank* — report the transaction to your bank's fraud desk in "
    "writing, not only by phone, and keep the reference number.\n\n"
    "Keep the original message. A screenshot showing the sender is worth more "
    "than the text alone."
)

PRIVACY_TEXT = (
    "*What happens to what you send me*\n\n"
    "• The *text* of your message is sent to a CYBERSURAKSHAA server and "
    "checked against scam-pattern rules.\n"
    "• Your Telegram name, username and chat ID are *not* sent and *not* "
    "stored.\n"
    "• The text is held in a quarantine table so an analyst can review "
    "genuinely new scam patterns. It is not automatically added to any "
    "intelligence database.\n"
    "• Nothing you send is shared with the sender of the scam.\n\n"
    "If a message contains your own personal details, remove them before "
    "forwarding — I only need the scam's wording to assess it."
)

DISCLAIMER = (
    "_This is an automated assessment of wording only. It is not legal advice "
    "and not a determination by any authority. A clean result does not mean a "
    "message is genuine._"
)


# ── HTTP helpers ─────────────────────────────────────────────────────────

def _post_json(url, payload, headers=None, timeout=REQUEST_TIMEOUT):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def telegram(method, payload=None, timeout=REQUEST_TIMEOUT):
    try:
        return _post_json(TELEGRAM_API % (BOT_TOKEN, method), payload or {},
                          timeout=timeout)
    except urllib.error.HTTPError as e:
        print("[BOT] Telegram %s failed: %s %s" % (method, e.code, e.reason))
    except Exception as e:
        print("[BOT] Telegram %s failed: %s" % (method, e))
    return None


def send(chat_id, text, reply_to=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    if reply_to:
        payload["reply_to_message_id"] = reply_to
    return telegram("sendMessage", payload)


# ── Platform call ────────────────────────────────────────────────────────

def check_text(text):
    """
    Ask the platform to classify one message.

    Every failure path returns an explicit error rather than a clean verdict.
    A check that did not happen must never be reported as "no problems found":
    that is the one output that could get somebody defrauded.
    """
    try:
        return _post_json(
            PLATFORM_URL + "/api/v1/check",
            {"text": text[:MAX_MESSAGE_LENGTH]},
            headers={"X-API-Key": API_KEY},
        )
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"error": "The bot is not authorised by the platform. "
                             "Its administrator needs to check the API key."}
        if e.code == 429:
            return {"error": "I am handling too many requests right now. "
                             "Please try again in a few minutes."}
        return {"error": "The checking service returned an error (%d)." % e.code}
    except Exception:
        return {"error": "I could not reach the checking service, so your "
                         "message was NOT checked. Please treat it with the "
                         "same caution as before."}


# ── Reply formatting ─────────────────────────────────────────────────────

def format_reply(result):
    if result.get("error"):
        return "⚠️ %s" % result["error"]

    lines = [BAND_HEADER.get(result.get("band"), "*Result*"), ""]

    for advice in result.get("advice", []):
        lines.append("• %s" % advice)

    indicators = result.get("indicators") or []
    if indicators:
        lines.append("")
        lines.append("*Identifiers in this message:*")
        for i in indicators[:8]:
            label = i.get("label") or i.get("kind")
            authority = i.get("report_to")
            entry = "• %s: `%s`" % (label, i.get("value"))
            if authority:
                entry += "\n  _report to: %s_" % authority
            lines.append(entry)
        if len(indicators) > 8:
            lines.append("• …and %d more" % (len(indicators) - 8))

    if result.get("band") == "LIKELY_SCAM":
        lines.append("")
        lines.append("*Report it:* cybercrime.gov.in, or call *1930*.")

    # The score is included, but never without the sentence saying what it is.
    lines.append("")
    if result.get("calibrated"):
        lines.append("_Score %s/100 (calibrated probability)._" % result.get("score"))
    else:
        lines.append("_Score %s/100. This is a raw pattern score, not a "
                     "probability — no calibration set exists for this "
                     "check yet._" % result.get("score"))
    lines.append("")
    lines.append(DISCLAIMER)

    return "\n".join(lines)


# ── Update handling ──────────────────────────────────────────────────────

def handle_message(message):
    chat_id = message.get("chat", {}).get("id")
    message_id = message.get("message_id")
    text = (message.get("text") or message.get("caption") or "").strip()

    if not chat_id:
        return

    if not text:
        send(chat_id,
             "Send me the *text* of the message you want checked. I cannot "
             "read images yet — if it is a screenshot, type or paste the "
             "wording instead.", reply_to=message_id)
        return

    command = text.split()[0].lower().split("@")[0]
    if command in ("/start", "/help"):
        send(chat_id, WELCOME, reply_to=message_id)
        return
    if command == "/report":
        send(chat_id, REPORT_TEXT, reply_to=message_id)
        return
    if command == "/privacy":
        send(chat_id, PRIVACY_TEXT, reply_to=message_id)
        return
    if command.startswith("/"):
        send(chat_id, "I do not know that command. Send /help.",
             reply_to=message_id)
        return

    if len(text) < 15:
        send(chat_id,
             "That is quite short to assess. Forward the whole message — "
             "the wording around the request is what carries the signal.",
             reply_to=message_id)
        return

    send(chat_id, "Checking…", reply_to=message_id)
    result = check_text(text)
    send(chat_id, format_reply(result), reply_to=message_id)


def run():
    if not BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN is not set. Get one from @BotFather.")
        return 1
    if not API_KEY:
        print("CYBERSURAKSHAA_API_KEY is not set. The bot cannot call the "
              "platform without it.")
        return 1

    me = telegram("getMe")
    if not me or not me.get("ok"):
        print("Could not authenticate with Telegram. Check the token.")
        return 1
    print("[BOT] Running as @%s, checking against %s"
          % (me["result"].get("username"), PLATFORM_URL))

    offset = None
    backoff = 1

    while True:
        try:
            payload = {"timeout": POLL_TIMEOUT, "allowed_updates": ["message"]}
            if offset is not None:
                payload["offset"] = offset

            updates = telegram("getUpdates", payload,
                               timeout=POLL_TIMEOUT + 15)
            if not updates or not updates.get("ok"):
                # Exponential backoff, capped. Hammering a failing API is how
                # a bot gets its token rate-limited.
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1

            for update in updates.get("result", []):
                offset = update["update_id"] + 1
                if "message" in update:
                    try:
                        handle_message(update["message"])
                    except Exception as e:
                        # One malformed update must not kill the bot.
                        print("[BOT] handler error: %s" % e)

        except KeyboardInterrupt:
            print("\n[BOT] Stopped.")
            return 0
        except Exception as e:
            print("[BOT] loop error: %s" % e)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    sys.exit(run())
