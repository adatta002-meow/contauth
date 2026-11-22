# Deploy ContAuth live (free, about 10 minutes)

You get a public HTTPS address like `https://contauth-xxxx.onrender.com`.

## 1. Put the code on GitHub

**Option A, browser only:**
1. On github.com, click **New repository**. Name it `contauth` and create it (public or private both work).
2. On the new repo's page, click **uploading an existing file**.
3. Unzip `contauth.zip` and drag in the **contents** of the `contauth` folder (`contauth/`, `data/`, `models/`, `Dockerfile`, `render.yaml` and the rest). Do **not** drag in the outer folder itself.
4. Click **Commit changes**.

**Option B, terminal** (the zip already contains a git repository with one commit):
```bash
cd contauth
git remote add origin https://github.com/<your-username>/contauth.git
git push -u origin main
```

## 2. Deploy on Render
1. Go to render.com and sign up with your GitHub account.
2. Click **New** > **Blueprint**, then connect and pick the `contauth` repository.
3. Render reads `render.yaml` and asks for **CA_ADMIN_PASSWORD**. Pick a strong one (8+ characters).
4. Click **Apply**. The first build takes about 5–8 minutes: it installs packages, retrains the model on the dataset, and runs all 25 tests. The deploy stops if any test fails.
5. Open the URL Render shows. Sign in as `admin` with your password, then open `/admin`. Register a normal user in another browser to try the user side.

## Know before you demo (free tier)
- **It sleeps.** After 15 minutes without visitors the service stops, and the next visit takes about a minute to wake it. Open it a minute before your viva.
- **Data resets.** The free tier has no permanent disk, so users, profiles and logs are wiped whenever it sleeps or redeploys. The admin account is recreated automatically on each start. For data that lasts, add a Render disk (paid) mounted at `/srv/instance`.
- **Mobile networks change IPs.** A phone switching between Wi-Fi and mobile data triggers a password re-check by design. That's the Zero Trust IP rule, not a bug.

## Settings you can change (Render > Environment)
| Variable | Default | Effect |
|---|---|---|
| `CA_WINDOW_MS` | 30000 | Behavior window length in ms. 5000 makes demos faster |
| `CA_ENROLL_WINDOWS` | 20 | Windows needed before a personal profile is built |
| `CA_OPERATING_FAR` | 0.10 | Target false-accept rate for the per-user threshold |
| `CA_LOCK_MINUTES` | 15 | Account lock length after a critical event |
| `CA_REQUIRE_EMAIL_VERIFICATION` | true | New accounts must confirm an emailed code before they can sign in |

## Email (Gmail) verification

New accounts confirm a 6-digit code sent to their email before the system starts
learning them. **Without SMTP configured the app runs in dev mode:** no mail is sent
and the code is shown on the verify page, so the flow works on a laptop immediately.

To send real email (e.g. from a Gmail account), set these — for Gmail, create an
[App Password](https://myaccount.google.com/apppasswords) and use it as `SMTP_PASSWORD`:

| Variable | Example |
|---|---|
| `CA_SMTP_HOST` | `smtp.gmail.com` |
| `CA_SMTP_PORT` | `587` |
| `CA_SMTP_USER` | `you@gmail.com` |
| `CA_SMTP_PASSWORD` | your 16-char Gmail App Password |
| `CA_SMTP_FROM` | `ContAuth <you@gmail.com>` |

To turn the gate off entirely (e.g. for a quick demo), set `CA_REQUIRE_EMAIL_VERIFICATION=false`.
