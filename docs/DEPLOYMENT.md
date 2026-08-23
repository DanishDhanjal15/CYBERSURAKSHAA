# Deploying CYBERSURAKSHAA

This is the real-deployment guide — not the Cloudflare quick tunnel, which is
a demo convenience that dies with the laptop.

---

## 0. The one number that decides everything: memory

Measured on the running application with all four detector stacks resident:

| Metric | Value |
| :--- | :--- |
| Working set | **1.3 GB** |
| Committed (private bytes) | **3.3 GB** |
| Recommended container limit | **4 GB** |
| Absolute floor (will thrash/OOM) | 2 GB |

Four ML stacks share one process — PyTorch + EfficientNet-B4 + MTCNN,
PaddleOCR, YOLOv8, and XGBoost/XLM-RoBERTa. That is the whole story of the
deployment, and it disqualifies every 512 MB free tier immediately. A crash
loop on Render's free plan is not a misconfiguration; it is arithmetic.

---

## 1. Where to deploy

| Platform | RAM | Cost | Verdict |
| :--- | :--- | :--- | :--- |
| **Hugging Face Spaces** (Docker SDK) | 16 GB | **Free** | ✅ **Recommended.** Free HTTPS, no card, Docker native, built for ML |
| Railway | 8 GB | ~₹500–1700/mo | ✅ Good; simple GitHub deploys, persistent volumes |
| Render (Standard) | 2 GB | ~₹2100/mo | ⚠️ Tight but workable with a disk |
| Fly.io | 2 GB | ~₹1000/mo | ⚠️ Workable; more configuration |
| Any 4–8 GB VPS (Hetzner, DO) | 4–8 GB | ₹600–2000/mo | ✅ Full control; `docker compose up -d` |
| Render / Fly **free** | 512 MB | Free | ❌ **Will OOM.** Do not try |

**For a hackathon: Hugging Face Spaces.** Free, 16 GB, HTTPS, and reviewers
can see the running app without a login.

---

## 2. Before deploying: what had to be fixed

These were real blockers found in a pre-deployment audit. They are already
fixed in the repo — recorded here so the reasoning survives.

| # | Blocker | Why it would have broken production |
| :-- | :--- | :--- |
| 1 | `requirements.txt` said `numpy<2.0.0`; the tested environment runs **2.3.5** | The container would have installed numpy 1.x beside paddlepaddle 3.3.1 and torch 2.13 — a combination never run anywhere. Everything is now pinned to tested versions. |
| 2 | `opencv-python` requested, but `qr_analysis.py` calls `cv2.wechat_qrcode_WeChatQRCode()` | That decoder only exists in **opencv-contrib**. QR codes with a logo in the middle — i.e. real UPI stickers — would silently fail to decode. |
| 3 | Model weights were gitignored (`*.pt`, `*.pth`) | A fresh clone had no `best_model.pth`, so the deepfake module raised `FileNotFoundError` on first use. Now force-added. |
| 4 | `.dockerignore` excluded `evaluation/` | That is where the fitted calibrator lives. The image would have reported **raw scores as if they were probabilities** — the exact dishonesty calibration exists to remove. Now re-included. |
| 5 | Dockerfile installed unpinned CPU torch | The later requirements pass replaced it with the CUDA build, ~2.5 GB of libraries a CPU container cannot use. Both now pin 2.13.0. |
| 6 | `python -m spacy download` failed the build | That command fetches a compatibility table from `raw.githubusercontent.com`, which returned `SSL: UNEXPECTED_EOF_WHILE_READING` on three consecutive builds while github.com stayed reachable. The model now installs from its release wheel URL — one fewer host that has to be up. |
| 7 | Takedown notices and evidence certificates embedded `http://localhost:5000` | Those documents go to a registrar or a court, carrying a verification link and QR code pointing at *their* machine. `services/public_url.py` now resolves `PUBLIC_BASE_URL` → the live request host → the dev fallback, in that order. |

Verified before shipping: `docker build` completes end to end, `pytest tests/`
is 453 green, and `scripts/smoke_test.py` passes against a running instance.

---

## 3. Deploy to Hugging Face Spaces (recommended)

### 3.1 Create the Space

1. Sign in at <https://huggingface.co> and open **New Space**.
2. **SDK: Docker** → *Blank*. Hardware: **CPU basic (free, 16 GB)**.
3. Visibility: Public (so reviewers need no account).

### 3.2 Push the code

A Space is a git repository:

```bash
git remote add space https://huggingface.co/spaces/<user>/<space-name>
git push space main
```

### 3.3 Set the secret

In the Space: **Settings → Variables and secrets**.

**Two secrets are mandatory — the container refuses to boot without either.**

| Secret | Value | What happens without it |
| :--- | :--- | :--- |
| `SECRET_KEY` | 64 hex characters (below) | `app.py` raises on boot. An ephemeral key would sign every user out on each restart |
| `ADMIN_PASSWORD` | a password you choose | `auth_db.init_db()` raises rather than seeding the well-known `admin123` that is published in this repository |

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Then these plain variables:

| Variable | Value | Why |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Turns off debug and enforces the two secrets above |
| `SESSION_COOKIE_SECURE` | `1` | The public URL is HTTPS |
| `ENABLE_CRAWLER` | `0` | No outbound scraping from a shared host |
| `GUNICORN_TIMEOUT` | `900` | The first request per model downloads its weights; 120 s kills it mid-flight |
| `PUBLIC_BASE_URL` | your Space URL, e.g. `https://user-space.hf.space` | Printed and QR-encoded into takedown notices and evidence certificates as the verification link |

The port needs no variable — `app_port: 5000` in the README frontmatter tells
Spaces where to route.

### 3.4 Know this before you demo on Spaces

**Storage on a free Space is ephemeral.** The container filesystem resets when
the Space restarts or rebuilds, which means the SQLite databases go with it:
registered users, scan history, the entity graph and the evidence chain all
return to empty. The seeded `admin` account is recreated from
`ADMIN_PASSWORD`, so you can always get back in.

That is fine for a hackathon — arguably good, since reviewers see the honest
zero-state — but it is not a pilot deployment. For anything where the data has
to survive, either attach Spaces **persistent storage** (paid) or use the VPS
path in section 4, where `docker-compose.yml` already mounts named volumes.

A free Space also **sleeps after inactivity**. The first request after a sleep
pays the cold start again. Wake it a few minutes before presenting.

### 3.5 First boot

The build takes 15–25 minutes (torch, paddle and transformers wheels are
multi-gigabyte). First request to each detector pulls its model into memory
and can take up to a minute — `GUNICORN_TIMEOUT` is already 120 s for this.

Watch `/healthz` until every model reports `ready`.

---

## 4. Deploy on a VPS (full control)

```bash
git clone <repo> && cd cybersurakshaa
printf 'SECRET_KEY=%s\n' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')" > .env
echo 'FLASK_ENV=production' >> .env
docker compose up -d --build
```

`docker-compose.yml` already mounts `/app/data` for the SQLite databases and
saved scan media, so a redeploy does not discard users, scans or the evidence
chain.

Put Caddy or nginx in front for TLS. With Caddy that is two lines:

```
your-domain.in {
    reverse_proxy localhost:5000
}
```

---

## 5. Post-deployment checklist

Run these against the deployed URL — in this order.

```bash
BASE=https://your-deployment

curl -fsS $BASE/healthz        | python -m json.tool   # process + database
curl -fsS $BASE/readyz         | python -m json.tool   # every model loaded
curl -fsS $BASE/api/v1/        | python -m json.tool   # public API + plans
curl -fsSI $BASE/auth/login    | head -1               # 200
curl -fsSI $BASE/check/        | head -1               # 200, no login needed
```

Then, in a browser:

- [ ] Sign in as `admin` with the `ADMIN_PASSWORD` you set. (In production no
      demo `user` account is seeded and `admin123` is never used — the app
      refuses to boot rather than fall back to it.)
- [ ] Hub loads, Quick Launch buttons all resolve.
- [ ] Run one scan per module; confirm each returns a verdict with reasons.
- [ ] `/round2` → declare emergency → re-check the relief-fund message →
      score rises and `emergency_mode: true` is disclosed.
- [ ] `/admin/operations` → provision a tenant → its key appears once.
- [ ] `/tv` renders on a second screen.
- [ ] On an **Android phone**, `/nfc/` → Start NFC Scan → tap an NDEF tag.
      Web NFC needs HTTPS, which is why this only works after deployment.

---

## 6. Operating notes

**Workers stay at one.** Each gunicorn worker loads its own copy of every
model — several GB apiece. Scale by running more containers, not more workers.
`docker-compose.yml` says the same thing next to the setting.

**The database is SQLite on a mounted volume.** That is correct at pilot
scale and the migration path to PostgreSQL is one helper —
`services/intel/db.get_db_connection()` — plus the rate limiter's
`storage_uri`. Do that at roughly 100k scans/day, not before.

**Background monitors are off by default.** `WATCHTOWER_MONITORS=1` enables
Certificate Transparency polling and takedown re-probing; both make outbound
requests on a timer and should be a deliberate choice, not a surprise in
someone's egress logs.

**Emergency posture survives restarts only via the environment.** The
`/admin/operations` toggle is a runtime override. To have a container come up
already in emergency posture, set `EMERGENCY_MODE=1`.
