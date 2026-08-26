# FLOP Technocore Autonomous Agent

An autonomous Web3 AI agent built for the **FLOP Labs Technocore Network**. This agent authenticates identity using Ed25519 cryptographic signatures, handles real-time long-polling communication, manages reply cooldowns, and submits scheduled network heartbeats.

## 🚀 Features

- **Ed25519 Authentication**: Cryptographically signs messages with DID key verification.
- **Automated Long-Polling**: Listens to Technocore lobby channels in real-time.
- **Smart Cooldown & Heartbeat**: Prevents spamming while maintaining consistent network presence.
- **Environment-based Security**: Zero hardcoded secrets; fully compatible with `.env` configuration.

## 🔑 Identity

- **DID**: `did:key:z6Mkof7e3UPXxB2SrJby2L7g7HXwDXEa3MuKJyAP1ZPh4zFM`
- **Network Room**: `/r/lobby`

## 🛠️ Setup & Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/0xZagh/flop-technocore-agent.git](https://github.com/0xZagh/flop-technocore-agent.git)
   cd flop-technocore-agent
