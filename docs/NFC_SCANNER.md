# NFC Tag Scanner — How It Works, How To Use It, When To Use It

## What this module is

NFC tags are a physical-world scam delivery channel: a sticker pasted over a
shop's real payment QR/NFC plate, a "tap to pay parking fine" card on a
windscreen, a smart poster in transit that opens a phishing page or pre-fills
an SMS. The NFC Scanner reads the **NDEF records** stored on such a tag and
runs them through the same threat heuristics and intelligence graph the rest
of the suite uses.

It does **not** read bank cards. EMV payment cards, metro cards and access
cards do not expose NDEF data, and the Web NFC API deliberately cannot read
them. This tool is for **NDEF tags** (NTAG213/215/216, MIFARE Ultralight and
similar) — the kind scammers actually deploy in public.

## Architecture

```
Android Chrome (Web NFC / NDEFReader)          Desktop (NDEF Simulator tab)
        │  tap → records[]                            │  manual records[]
        └──────────────┬───────────────────────────────┘
                       ▼
      POST /nfc/scan   { records: [{recordType, data}, …] }
                       │   blueprints/nfc_scan.py  (login + rate limit "120/hour")
                       ▼
        services/nfc_analysis.py
          ├─ parse_ndef_record()   url / tel: / sms: / upi:// / text
          ├─ per-type heuristics   (shares QR scanner's reference data:
          │                         NPCI handles, scam VPA words,
          │                         impersonation names, URL shorteners,
          │                         lookalike TLD/brand checks)
          ├─ indicator extraction  services/intel/indicators.py
          ├─ graph cross-reference "seen in N prior flagged artefacts?"
          └─ calibration.assess()  → band (honestly marked uncalibrated)
                       │
                       ├─ graph.ingest()          (analyst scan → entity graph)
                       └─ evidence.append_event() (tamper-evident chain)
                       ▼
      JSON: classification CLEAN / SUSPICIOUS / HIGH_RISK, per-record
            reasons, indicators with reporting authority, payload hash
```

### What each record type is checked for

| Record | Signals scored |
|---|---|
| `upi://` | non-NPCI handle, refund/KYC/lottery vocabulary in the VPA, impersonated payee name, COLLECT intent (tap asks *you* to pay), pre-filled amount |
| `http(s)://` | plain HTTP, URL shorteners, cheap phishing TLDs (.top/.xyz/…), lookalike of a watchlist brand (sbi, paytm, …) |
| `tel:` | number present in the fake-customer-care database; auto-dial risk note |
| `sms:` | auto-send risk, premium-rate/registration patterns, urgency words in the pre-filled body |
| text | Hinglish/English scam keyword banks, spaced-letter obfuscation |
| any | every extracted indicator is looked up in the entity graph — a VPA already seen on a betting poster raises the score and says so |

## How to use it

### Live scan (the real thing — Android only)

1. Deploy the app on HTTPS (Render gives this automatically), or for local
   testing enable `chrome://flags` → *"Insecure origins treated as secure"* →
   add `http://<laptop-ip>:5000` on the phone.
2. On the Android phone: Chrome → open the site → sign in → **NFC** in the
   nav → **Start NFC Scan** (Chrome will ask for NFC permission once).
3. Hold the tag against the back of the phone. The serial number appears in
   the log, records decode, and the analysis renders automatically.
4. **Stop Scanning** actually stops the radio (AbortController — fixed; the
   original version only dropped the JS reference and kept listening).

Requirements and limits, stated plainly:

* Works: Chrome / Edge / Samsung Internet on **Android**, HTTPS, NFC enabled.
* Does not work: any desktop browser (even with NFC hardware), any iPhone.
* Reads: NDEF-formatted tags with data written on them. Write a test payload
  with the "NFC Tools" app first — a factory-blank tag returns no records.
* Will not read: bank/debit cards, metro cards, office badges (no NDEF).

### Simulator (desktop demos, judges, development)

The **NDEF Simulator** tab posts hand-written records through the identical
`/nfc/scan` path — same analysis, same graph writes, same evidence entries.
Presets cover the five demo scenarios (clean site, SBI lookalike, auto-SMS,
flagged helpline, UPI collect trap). Use this whenever there is no Android
phone in the room.

## When is this module the right tool?

* A field report of a suspicious payment sticker, poster or card — tap it
  with the analyst phone instead of paying it.
* Verifying a tag *before* deploying it in a legitimate campaign.
* Cross-referencing: the scanner's real value is the graph lookup — a tag's
  VPA or domain that already appeared in a betting or customer-care scan
  links the physical deployment to a known online operator.
* Demos and training: the simulator reproduces every scenario without
  hardware.

When it is **not** the tool: checking a message or link someone forwarded
(use the Citizen Quick Check `/check`), an image of a QR code (QR / UPI
Scanner — decodes the optical code directly), or anything involving a bank
card (nothing consumer-facing can read those, by design).

## Review status (2026-08-22)

Full server path verified end-to-end with a real registered session:
scam UPI record → SUSPICIOUS (35), clean URL → CLEAN (0), empty records →
400, wrong Content-Type → 400, anonymous → rejected; 428/428 project tests
pass. Bugs found and fixed during review:

1. `submitDetection()` sent the JSON body as `text/plain`, so every scan
   returned "No NFC records provided" — Content-Type now set correctly.
2. Stop button did not stop the radio — AbortController wired in.
3. Every `.com/.org/.in` URL was scored +25 "suspicious TLD" (the check used
   the lookalike *generator's* full TLD list) — now only the cheap tail.
4. `fa-solid fa-nfc` is a Pro icon and rendered blank — replaced with the
   free `fa-brands fa-nfc-symbol`.
5. Missing breadcrumb entry; two-column layouts did not stack on the very
   device the scanner runs on — responsive overrides added.

The physical tap itself can only be verified on an Android phone against an
HTTPS deployment — everything on the server side of that tap is tested.
