# OnPoint Tech Hub

Cyber services, electronics and gas management for Maseno, Kisumu and Nairobi.
Node.js + PostgreSQL. One server, one database, every branch live.

## Deploy on Render
1. Push this folder to a GitHub repository.
2. In Render choose **New > Blueprint** and select the repository. `render.yaml` creates the web service and the database.
3. When asked for `OWNER_PIN`, enter a private PIN (at least 4 digits). Render generates `JWT_SECRET` and `ENCRYPTION_KEY` for you. Never change `ENCRYPTION_KEY` later or the saved M-Pesa keys become unreadable.
4. Open the Render URL and sign in as Owner. Change the other staff PINs (default 2222, 3333, 4444) under **Audit and staff**.
5. Go to **Settings** and enter your Daraja keys.

## M-Pesa Daraja setup
1. Create an app at developer.safaricom.co.ke and enable Lipa na M-Pesa Online (STK Push).
2. In the app's **Settings** page here, paste Consumer key, Consumer secret, Business shortcode and Passkey. Start with Sandbox, press **Test connection**.
3. Copy the **Callback URL** shown on the Settings page into your Daraja app registration when going live.
4. For real money choose Production. Use a paid Render web plan: a sleeping free service can miss Safaricom's payment confirmations.

## Not included
- KRA eTIMS invoicing needs KRA device or API registration, so it is not wired in. Receipts show VAT 16% only.
- SMS alerts (for example Africa's Talking). WhatsApp uses a click-to-chat link.

## Local run
`DATABASE_URL=postgres://... OWNER_PIN=1234 node server.js`
