# CYBERSURAKSHAA — Problem Statement Brief

---

## In one line

> **India's digital fraud arrives in every format and in every language — our
> defences read only text, only English, and leave no evidence behind.**

---

## In one paragraph

> Fraud in India no longer arrives as a suspicious link. It arrives as a
> betting poster on Instagram, a deepfake video of a celebrity promoting an
> investment scheme, a fake customer-care number on a search result, a voice
> call, a malicious APK — and increasingly from the physical world: a scam QR
> sticker pasted over a shopkeeper's real one, an NFC tag on a windscreen
> claiming a parking fine. The tools meant to stop this are single-format,
> English-only, and siloed — they cannot connect the UPI ID on a poster to the
> same UPI ID on a sticker, they cannot explain why they flagged something, and
> they produce alerts instead of evidence. Meanwhile the citizen, who has two
> minutes to decide whether a message is real, has nowhere to check before
> paying — only somewhere to report after the money is gone.

---

## The four gaps, stated precisely

### 1. Format gap — fraud is multi-modal; defence is not

A scam today is an image, a video, an audio call, an app, a printed QR code, a
physical NFC tag. A URL blocklist sees none of these. Each existing tool
handles one format, so an operator running the same campaign across five
formats is caught in none of them, or caught five separate times as five
unrelated incidents.

### 2. Correlation gap — no tool connects one scan to the next

The same UPI ID appears on a betting poster in March and on a payment sticker
in a market in April. Nothing links them. The poster gets taken down; the
operator does not. Enforcement removes artefacts while the person behind them
keeps working — because no system holds the memory that would identify them.

### 3. Evidence gap — detection stops at the alert

"This is a scam" is not actionable. Enforcement needs the specific identifier,
the authority that can act on it (NPCI for a UPI ID, DoT for a number, the
bank's nodal officer for an account), and a record that survives legal
scrutiny. Today that assembly is manual and slow — and the golden hour, when a
transfer can still be held, is gone before it finishes.

### 4. Trust gap — the verdict cannot be examined or reached

Two failures at once:

- **Unexplainable and uncalibrated.** A model says "87% scam". Eighty-seven
  percent of *what*? Based on which words? An analyst who will testify, and a
  citizen about to send money, both need to see the reasoning and know what
  the number means.
- **Unreachable.** Every check sits behind a login built for analysts. The
  person actually receiving the scam has no way in. Reporting portals exist —
  but they are for *after* the loss.

### And the language gap running through all four

Real Indian scam copy is not English. It is *"aapka account block ho jayega,
turant KYC karo, OTP batao"* — Hinglish, Devanagari, and OCR-mangled spellings
like `1XWIN` read as `IXWIN`. English-trained models score this at zero.

---

## Who is harmed

| Who | What it costs them |
| :--- | :--- |
| **The citizen** — often first-generation internet, often elderly | Savings, in a transfer that could have been held if flagged in the first hour |
| **The investigating officer** | Hours of manual correlation per case, and an evidence file that may not hold up |
| **The bank and the platform** | Mule accounts, chargebacks, regulatory pressure, and no defensible automated screen |
| **The state** | Fraud that scales faster than the enforcement capacity built to answer it |

---

## What CYBERSURAKSHAA is

**A single detection suite that reads every format fraud arrives in, links what
it finds to one operator, explains every verdict, and produces court-ready
evidence — usable by an analyst, a command centre, and a citizen alike.**

| The gap | Our answer |
| :--- | :--- |
| Format | 8 detectors: betting content, deepfake, fake customer care, investment fraud, voice, APK, QR/UPI, NFC tags |
| Correlation | Every scan's indicators enter one entity graph; campaign clustering links artefacts to a common operator |
| Evidence | Tamper-evident hash-chained ledger; one-click court-ready PDF and takedown notice, each naming the authority to send it to |
| Trust — explainability | Grad-CAM for deepfakes; scoring words boxed on the image for betting; a reason list on every verdict; Platt-calibrated probabilities where we have data, and an honest "uncalibrated" label where we do not |
| Trust — reach | A public Citizen Quick Check with no login: paste a message or upload a QR photo, get a plain-language verdict and what to do next |
| Language | Hinglish and Devanagari keyword banks, transliteration, and OCR-confusion folding alongside the English models |

---

## What makes it defensible

1. **It reads the physical world.** The officer's own phone becomes the sensor
   — Web NFC and QR decoding in the browser, no app to install, no reader to
   procure.
2. **It never fabricates a number.** A CI check fails the build if
   fabricated-data markers appear. A fresh install honestly reads zero.
3. **It is measured, not asserted.** Deepfake detection is 97.4% accurate on
   153 held-out clips; calibration reduced expected calibration error from
   0.058 to 0.026; 453 automated tests run on every push.
4. **It is India-first by construction** — UPI rails, NPCI handles, Indian
   reporting authorities, Hinglish — not a foreign tool localised afterwards.

---

## The line that frames it

> **A scam sticker costs ₹10 to print. Our answer costs one tap.**
