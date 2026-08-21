# 🔐 How Authentication Works in CYBERSURAKSHAA
### (Simple Version — No Jargon)

---

## Think of It Like a Security Guard at a Building

- The **building** is your app (CYBERSURAKSHAA).
- The **security guard** is the auth system.
- The **ID card** is your username + password.
- The **entry pass** is the session (a small token stored in your browser after login).
- The **VIP badge** is the `admin` role.

When you arrive → guard checks your ID → gives you an entry pass → you use that pass for every room you enter.

---

## Part 1 — The Database (`cybersurakshaa.db`)

This is a **single file** sitting in your project folder. Think of it as an Excel workbook with 3 sheets (tables).

---

### Sheet 1: `users` — The Employee List

Every person who can log in is stored here.

| What's stored | Example | Why |
|---|---|---|
| ID number | `1` | Unique number for each user |
| Username | `"admin"` | Your login name |
| Password (hashed) | `"pbkdf2:sha256:..."` | NOT the real password — a scrambled version |
| Role | `"admin"` or `"user"` | Decides what you're allowed to do |
| Date joined | `2026-06-16 10:00:00` | When the account was made |

> 💡 **What is "hashed"?**  
> The real password `"admin123"` is run through a math formula and turned into a long scrambled string like `pbkdf2:sha256:600000$xyz$abc...`. You **cannot reverse** it back to `"admin123"`. So even if someone steals the database, they can't read the password.

**Default accounts that are created on first run:**
```
Username: admin   Password: admin123   Role: admin
Username: user    Password: user123    Role: user
```

---

### Sheet 2: `scans` — The Scan History Log

Every time anyone runs an AI scan (betting detector, deepfake, etc.), a row is saved here automatically.

| What's stored | Example |
|---|---|
| Who did it | user ID `1`, username `"admin"` |
| When | `2026-06-16 14:30:00` |
| Which tool | `"Betting Detector"` |
| What was scanned | `"screenshot.jpg"` |
| What the AI decided | `"DANGER"` |
| Risk score | `87` (out of 100) |
| Reasons | `["Found betting keywords", "Logo detected"]` |

> 💡 Even if a user is deleted later, their scan history stays in this table (the user ID just becomes blank). History is never lost.

---

### Sheet 3: `alerts` — The Live Threat Feed

This table is filled automatically by a **background crawler** that watches the internet for threats. Users don't write to this — it happens behind the scenes.

| What's stored | Example |
|---|---|
| Threat source | `"Telegram Channel XYZ"` |
| What it found | `"Illegal betting app promoted"` |
| Category | `"BETTING"` |
| Risk score | `92` |
| Link | `"https://t.me/xyz"` |
| Status | `"ACTIVE"` or `"BLOCKED"` |

---

## Part 2 — What Happens When You Log In

Here's the step-by-step in plain English:

```
1. You type your username + password and click Login.

2. Flask takes your username and searches the database:
      "Is there a user called 'admin'?" → Yes, found!

3. Flask takes the password you typed and compares it
   to the scrambled version stored in the database:
      "Does 'admin123' match the stored hash?" → Yes!

4. Flask creates a small note (the SESSION) and saves it in your browser:
      user_id   = 1
      username  = "admin"
      user_role = "admin"

5. Every page you visit after this, Flask reads that note
   to know who you are — without asking you to log in again.
```

> 💡 **The session is like a wristband at an event.** The security guard puts it on once. Every door after that just checks the wristband — they don't ask for your ID again.

---

## Part 3 — How Pages Are Protected

Every page in the app checks your wristband before showing you anything.

### Normal Page (`@login_required`)

```
You visit a page →
  Flask checks: "Do you have a wristband (session)?"
    ✅ YES → Show the page
    ❌ NO  → Send you to the login page
```

### Admin-Only Page (`@admin_required`)

```
You visit /admin/dashboard →
  Flask checks: "Do you have a wristband?"
    ❌ NO  → Send you to login page
    ✅ YES → checks: "Is your role = admin?"
               ❌ NO  → Send you back home (Access Denied)
               ✅ YES → Show the admin dashboard
```

---

## Part 4 — What Each User Type Can Do

| Action | Regular User | Admin |
|---|---|---|
| Login / Logout | ✅ | ✅ |
| Run AI scans | ✅ | ✅ |
| See their own scan history | ✅ | ✅ |
| See EVERYONE's scan history | ❌ | ✅ |
| Delete their own scans | ✅ | ✅ |
| Delete anyone's scans | ❌ | ✅ |
| Manage users (promote/delete) | ❌ | ✅ |
| Block live threat alerts | ✅ | ✅ |
| View admin dashboard | ❌ | ✅ |

---

## Part 5 — The Code Files (What Each File Does)

Think of these 3 files as 3 workers:

```
┌──────────────────────────────────────────────┐
│  app.py  (The Manager)                       │
│  • Starts the app                            │
│  • Creates the database on first run         │
│  • Tells every page who is logged in         │
└──────────────────────────────────────────────┘
              │ talks to ↓
┌──────────────────────────────────────────────┐
│  blueprints/auth.py  (The Security Guard)    │
│  • Handles /login, /register, /logout        │
│  • Protects pages with @login_required       │
│  • Protects admin pages with @admin_required │
│  • Handles scan save/delete/PDF APIs         │
└──────────────────────────────────────────────┘
              │ talks to ↓
┌──────────────────────────────────────────────┐
│  services/auth_db.py  (The Record Keeper)    │
│  • Creates and updates the database          │
│  • Saves and fetches users, scans, alerts    │
│  • Checks if passwords match                 │
└──────────────────────────────────────────────┘
              │ reads/writes ↓
┌──────────────────────────────────────────────┐
│  cybersurakshaa.db  (The Filing Cabinet)     │
│  • The actual data on your hard drive        │
└──────────────────────────────────────────────┘
```

---

## Part 6 — Registration Flow (Simple)

```
1. You fill in: username, password, confirm password
2. App checks:
   - Are all fields filled? If not → error
   - Do passwords match? If not → error
   - Is password at least 6 characters? If not → error
   - Is username already taken? If yes → error
3. Password is scrambled (hashed) and saved to database
4. You are redirected to the login page
```

---

## Part 7 — Logout

Super simple:
```
You click Logout →
  Flask erases your wristband (session) →
  You are sent back to the login page
```

You are no longer recognized. Every protected page will redirect you to login.

---

## Part 8 — The "Block Alert" Feature (Admin/User Action)

When someone clicks **Block** on a live threat alert:

```
1. The alert is marked as BLOCKED in the database (hidden from feed)
2. A scan record is automatically created in the history log
3. A legal recommendation is generated (IT Act §79 notice)
4. The user gets a scan ID they can use to download a takedown PDF
```

---

## Part 9 — Passwords Are Safe (Why You Can't Just Read Them)

```
Real password:   "admin123"
Stored in DB:    "pbkdf2:sha256:600000$rAnDoMsAlT$a9b3c2..."

Even if someone steals the database file:
  - They see the scrambled string, not "admin123"
  - They can't reverse the scramble
  - Every user has a different random salt, so even
    two users with the same password look different in the DB
```

---

## Part 10 — One Weakness to Know About

```python
app.secret_key = secrets.token_hex(24)  # This line in app.py
```

This generates a **new random key every time** the app restarts. That key is used to secure all session wristbands. When the key changes, all old wristbands become invalid.

**Effect:** Every time you restart `python app.py`, all users are automatically logged out.

> ✅ This is fine for development. For a real production server, the secret key should be saved permanently (e.g., in an environment variable).

---

## Quick Reference — All the URLs

| URL | Who can access | What it does |
|---|---|---|
| `/auth/login` | Anyone | Login page |
| `/auth/register` | Anyone | Create account |
| `/auth/logout` | Logged-in | Logs you out |
| `/auth/api/scans` GET | Logged-in | Get scan history |
| `/auth/api/scans` POST | Logged-in | Save a new scan |
| `/auth/api/scans/<id>` DELETE | Logged-in | Delete one scan |
| `/auth/api/scans/<id>/pdf` | Logged-in (own only) | Download scan PDF |
| `/auth/api/alerts` GET | Logged-in | Get live threat alerts |
| `/auth/api/alerts/<id>/block` POST | Logged-in | Block a threat alert |
| `/admin/dashboard` | **Admin only** | User management panel |
| `/admin/user/<id>/role` | **Admin only** | Promote/demote user |
| `/admin/user/<id>/delete` | **Admin only** | Delete a user |
