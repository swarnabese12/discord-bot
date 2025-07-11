# 📬 Gmail to Discord Bot (Rust)

A Rust-based bot that monitors your Gmail inbox and automatically posts important emails to a Discord channel via a webhook. Designed with async capabilities using `tokio`, OAuth2 authentication, and secret-safe handling with `.env` configuration.

## ✨ Features

- 🔒 Secure OAuth2-based Gmail access
- 🔔 Auto-detect and notify important emails in real-time
- 📎 Filters emails based on sensitive keywords (e.g., payment, verification)
- 📤 Sends formatted email alerts directly to a Discord webhook
- ⚙️ Built with `tokio`, `reqwest`, `warp`, and `dotenvy`

## 🛠️ Environment Setup (.env)

 - Create a `.env` file in the project root with the following keys:
 - CLIENT_ID=your-google-client-id
 - CLIENT_SECRET=your-google-client-secret
 - REDIRECT_URI=http://localhost:3000/oauth2/gmail-bot
 - DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-id

