# CYBERSURAKSHAA — Round 2 Video Script

**Total runtime: ~5 minutes.** Read the **bold** lines aloud. The `[SCREEN]`
lines are what to show — do not read those.

Sentences are kept short on purpose. Pause where you see `—`. Do not rush the
numbers; they are the strongest thing you have.

---

## 0:00 — 0:30 · Opening

`[SCREEN: the login page of your deployed site]`

**Namaste. I am Danish, and this is CYBERSURAKSHAA — a national threat
detection suite for India.**

**Round two gave us a scenario. A worldwide emergency. A pandemic. And for
ninety days, nobody is allowed to gather.**

**Most projects would treat that as a problem. For us, it is the exact
situation this platform was built for.**

**Let me show you why — and then I will show you it running.**

---

## 0:30 — 1:15 · The problem the emergency creates

`[SCREEN: slide with the three fraud examples, or just talk to camera]`

**When a country locks down, digital crime does not slow down. It becomes the
only crime available.**

**Every payment moves online. Nobody can walk into a bank branch to verify
anything. Relief money is disbursed at speed. People lose jobs.**

**And the scammers move faster than any of us.**

**But here is the key insight. The mechanics of fraud do not change. Urgency,
advance fee, a UPI ID — that stays the same.**

**What changes is the pretext. Relief fund. Oxygen cylinder. Vaccine slot.
E-pass. Work from home.**

**And that change happens in days. Not weeks. Days.**

**No machine learning model can be retrained that fast. So we did not try to.**

---

## 1:15 — 2:30 · Adaptability — the live demo

`[SCREEN: open /round2 — the Business and Resilience page]`

**This is our Business and Resilience page. Everything I am about to show you
is live. Nothing here is a mockup.**

`[SCREEN: scroll to the Adaptability section with the message box]`

**Here is a real scam message.**

`[SCREEN: read it from the box]`

**"Government has approved five thousand rupees covid relief package for you.
Claim your relief fund now, pay processing fee to claim."**

**Right now the system is in normal operations. Watch what it says.**

`[SCREEN: click "Check this message" — wait for the left panel to fill]`

**Low score. And that is correct.**

**Because in normal times, "relief fund" appears in genuine government
circulars. If we flagged every message that mentioned it, we would drown the
analyst in false alarms — and we would frighten the exact citizens we are
trying to protect.**

**Now — let us declare the emergency.**

`[SCREEN: click "Declare emergency" — the banner turns red]`

**One switch.**

`[SCREEN: click "Check this message" again — right panel fills]`

**Same message. Different posture. And now look.**

`[SCREEN: point at the reasons]`

**The score jumps. And it tells us why. Relief fund disbursement lure.
Fabricated government sanction.**

`[SCREEN: point at the delta line at the bottom]`

**Same message. Posture changed. Score plus seventy.**

**Here is what matters. To ship this, we retrained no model. We migrated no
database. We added no route. It was a new keyword bank and one switch — built
in a single afternoon, with eleven tests.**

**That is what adaptability looks like when it is code, not a slide.**

---

## 2:30 — 3:15 · Monetisation — the meter

`[SCREEN: scroll up to the Monetisation section on /round2]`

**Now — money.**

**Every team can put a price on a slide. We built the meter instead.**

`[SCREEN: point at the plan table]`

**Four plans. Free for citizens. A free ninety-day pilot for a district.
Twenty-five thousand a month for banks. Two lakh a month for a state cyber
cell.**

`[SCREEN: point at the revenue tiles]`

**Every billable API call is recorded against the tenant that made it. The
invoice is calculated from that record. The customer can check their own bill
without calling us.**

**And notice — it reads zero. Because we seeded nothing. That zero is the
point. It is what makes the number believable on the day it is not zero.**

**Two rules we enforce in code. A failed call is never billed — you should
never be charged for an error. And a free tenant is never cut off — during an
emergency, silencing a citizen is worse than an unpaid invoice.**

**On revenue — we are honest about the maths. A bank does not send us its
whole volume. It sends what its rules engine flags. About half a percent. That
is fifty thousand calls a day. About one lakh rupees per bank per month.**

**Ten customers is one point two crore a year. That is a small number. But it
is a number that survives a follow-up question.**

---

## 3:15 — 3:50 · Scalability and Feasibility

`[SCREEN: scroll to the Scalability table on /round2]`

**Scalability. We measured it rather than guessed.**

**Today, under ten thousand scans a day, we run on one container for about
three thousand rupees a month. At a lakh scans a day, sixty thousand.**

**And here is the design decision that makes that cheap. Our entire
intelligence layer — the entity graph, campaign clustering, the evidence
chain, and this emergency bank — is pure Python standard library. No machine
learning at all. That half runs on every request for the cost of a regular
expression. Only the vision path is expensive, and it is the first thing we
split off.**

`[SCREEN: scroll to the Feasibility table]`

**Feasibility, under a gathering ban.**

**Teams cannot meet — deployment is one Docker command from a home laptop.**

**No hardware can be bought — the officer's own phone is our NFC and QR
scanner.**

**Offices are closed — our public Citizen Check replaces the complaint
counter. No login. No app.**

**Nobody can be trained in person — every verdict shows its reasons. The
evidence is the training.**

---

## 3:50 — 4:30 · Proof

`[SCREEN: terminal showing `pytest` output, or the numbers on screen]`

**Now, why should you believe any of this?**

**Four hundred and fifty three automated tests, passing.**

**A three-job CI pipeline on every push.**

**Our deepfake detector is ninety seven point four percent accurate — measured
on a hundred and fifty three held-out clips, not on our training data.**

**Its confidence is calibrated. Expected calibration error came down from zero
point zero five eight to zero point zero two six.**

**And where we do not have calibration data, the interface says so. Out loud.**

**We also have a check in our CI that fails the build if fabricated data
markers appear anywhere in the project. We apply that rule to our own
numbers.**

`[SCREEN: optional — /nfc/ page, or a phone tapping an NFC tag]`

**One more thing this platform does that others do not. It reads the physical
world. A scam QR sticker pasted over a shopkeeper's real one. A fake parking
fine NFC tag. The officer taps it with the phone already in their pocket — no
app, just the browser.**

**And if that same UPI ID has appeared before on a betting poster, the system
links them. Same operator. Automatically.**

---

## 4:30 — 5:00 · Close

`[SCREEN: back to the /round2 top, or your logo]`

**So — to summarise.**

**Monetisation: a working meter, not a price on a slide.**

**Scalability: measured, with a migration path we can name.**

**Adaptability: a new threat class shipped in an afternoon, behind a switch,
with tests.**

**Feasibility: already built, already deployed, already verified.**

**A pandemic does not create new fraud. It creates new pretexts — faster than
any retraining cycle can follow.**

**We shipped that answer in an afternoon. Without touching a model.**

**Thank you.**

---

## Recording notes

**Before you hit record**

- [ ] Open the deployed site and **wake it up** — first request after sleep is
      slow. Load `/round2` once and let all four detectors go green.
- [ ] Set the posture to **normal operations** so the demo starts from the
      right state.
- [ ] Clear the two result panels (there is a **Clear results** button).
- [ ] Close other tabs. Full-screen the browser. Hide bookmarks bar.
- [ ] Zoom the page to about 110% so text is readable in the video.

**If something goes wrong mid-recording**

- The check is slow → keep talking: *"the first request loads the model into
  memory — after that it is instant."* That is true and it sounds prepared.
- The emergency toggle does not respond → you are not signed in as admin.
  Sign in first.
- Nothing loads at all → fall back to the `/check` page, which is public and
  needs no login.

**Delivery**

- Read one line, then look at the screen. Do not read continuously.
- Slow down on every number. Numbers are your evidence.
- The strongest moment in the whole video is the second check — when the same
  message scores differently. Let it land. Pause for one full second before
  you say *"Same message. Different posture."*
