# SecureVote
Run: `pip install cryptography scikit-learn numpy` then `copy .env.example .env` then `python server.py` -> http://localhost:8000
Admin (dev only): Admin / Admin@123. Voter ID format: ABC1234567. Data: `vote2.db` (created automatically).

## Real SMS (OTP to the actual phone)
Edit `.env`, set DEMO_MODE=false and ONE provider:
- Fast2SMS: SMS_PROVIDER=fast2sms, FAST2SMS_API_KEY=...   (route "otp"; needs wallet balance)
- 2Factor:  SMS_PROVIDER=2factor,  TWOFACTOR_API_KEY=...
- MSG91:    SMS_PROVIDER=msg91,    MSG91_AUTH_KEY=..., MSG91_TEMPLATE_ID=...  (DLT-approved OTP template)
- Twilio:   SMS_PROVIDER=twilio,   TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_PHONE_NUMBER (trial accounts only reach verified numbers)
With no provider and DEMO_MODE=true the code is printed in the SERVER terminal only (never in the browser/API). Provider errors print as [SMS ERROR] in the terminal.

## Account flow
Register -> mobile OTP (UNVERIFIED -> OTP_VERIFIED) -> face enrollment + blink/head-turn (-> FACE_ENROLLED -> ACTIVE) -> sign in.
Login: password -> fresh OTP -> face match -> liveness (2-3 random challenges) -> trust score -> LOW: dashboard, MEDIUM: extra OTP, HIGH: blocked with reasons.
Forgot password: identifier -> OTP -> face -> new password (strength rules) -> sign in. Failures decay after 15 min.
Face engine: face-api.js + models are loaded from cdn.jsdelivr.net in the browser, so the first camera screen needs internet. Camera needs localhost or HTTPS.

## Known limits
Liveness metrics (blink / head turn / smile) are measured in the browser and validated on the server (thresholds, timing, random challenge, face re-match) - this stops casual spoofing but not an attacker who forges API calls; true anti-spoofing needs server-side vision/depth. Admin password reset prints its token on the server console (no email provider). Only Fast2SMS/2Factor/MSG91 request formats were written from provider docs and not tested against live accounts.
