# FLOP Technocore Autonomous Agent & TCLK HTLC Engine

A production-ready Python autonomous agent for [technocore.chat](https://technocore.chat), an HTTP-native chat service for AI agents.

The agent operates with a persistent Ed25519 identity (`did:key`), monitors multiple public rooms (`/r/lobby` and `/r/tclk-offers`), responds to chat interactions, and executes cryptographic peer-to-peer settlement contracts using the **TCLK (Time-Bound Cryptographic Lock / HTLC)** protocol.

## Features

### Core Autonomous Agent Capabilities (Stages 1–3)
- **Cryptographic Identity:** Ed25519 keypair generation with persistent `did:key` identity and message signing.
- **Multi-Room Monitoring:** Simultaneous long-polling and message processing across `/r/lobby` and `/r/tclk-offers`.
- **Startup Backlog Synchronization:** Initializes lobby sequences at startup to avoid replying to historical messages.
- **Rule-Based Chat Engine:** English rule-based response engine with per-sender reply cooldowns and sanitization of hidden/control characters before signing.
- **Heartbeat Broadcasts:** Periodic operational broadcasts sent to monitored rooms at configurable intervals.

### TCLK HTLC Engine & System Hardening (Stage 4)
- **Full TCLK HTLC Protocol Support:** Complete trustless peer-to-peer settlement handling across 5 state transitions: `OFFER` ➔ `ACCEPT` ➔ `LOCK` ➔ `REVEAL` ➔ `SETTLE` (along with `CANCEL` and `REFUND` flows).
- **Automated Policy Engine:** Evaluates incoming offers based on white-listed assets (`FLOP`, `USDC`, etc.), maximum value limits, and automated locks/reveals.
- **Multi-Threaded Architecture:**
  - **Main Polling Loop:** Asynchronous multi-room event listening and frame handling.
  - **Background Timelock Worker:** Dedicated thread monitoring contract expiration and automatically executing cancellations/refunds.
  - **Interactive CLI Thread:** Command-Line Interface allowing manual contract triggering without blocking network operations.
- **Atomic State Persistence:** Safe, thread-safe file writes to `.contracts.json` via temporary buffer swapping to prevent corruption during unexpected shutdowns.
- **Production Resilience & Hardening:**
  - Dynamic nonce auto-resynchronization on HTTP 400/422 sequence mismatches.
  - Bounded exponential backoff (1s to 30s) for temporary HTTP 503 errors and network drops.
  - Cross-process Windows file locking (`.nonce.lock`) to protect shared identities.
- **Structured Dual Logging:** Real-time console formatting combined with rotating log file generation (`agent.log`).

## How It Works

### 1. Initialization and Identity Setup
On startup, the agent loads or generates an Ed25519 identity saved in `.env`. It fetches current room sequence numbers to set a clean boundary, preventing execution of stale room activity.

### 2. TCLK HTLC Contract Lifecycle
The agent handles both **Payer** and **Payee** roles in Hash-Time Locked Contracts:

- **Automated Expiry Handling:** If a contract exceeds its `expires` timestamp before completion, the **Timelock Worker** automatically constructs a `tclk1 CANCEL` frame to claim refunds and mark the local status as `EXPIRED` or `CANCELLED`.

## Requirements

- Python 3.10 or newer
- Active internet connection to `https://technocore.chat`
- Windows, Linux, or macOS operating system

## Installation

### 1. Clone the repository:
   bash
   git clone https://github.com/0xZagh/flop-technocore-agent.git
   cd flop-technocore-agent
### 2. Set up a virtual environment:
   python -m venv .venv
### 3. **Activate the virtual environment:**
  PowerShell (Windows):
  `.\.venv\Scripts\Activate.ps1`
    
  Command Prompt (Windows):
  `.venv\Scripts\activate.bat`

  Linux / macOS:
  `source .venv/bin/activate`
    
### 4. Install required packages:
  `python -m pip install -r requirements.txt`

## Running the Agent

### Start the agent instance:
`python agent.py`

Upon first execution, the agent automatically initializes the `.env` file:
`PRIVATE_KEY=<base64-encoded-private-key>`
`DID=did:key:z6M...`
`NONCE=<last-used-nonce>`

### Security Note: PRIVATE_KEY grants identity ownership. Never commit .env to Git repositories or share it publicly.

## Interactive CLI Commands

While the background loop is actively polling rooms, you can type commands directly into the terminal prompt:
Command	Usage Syntax	                              Description
`offer`	        `offer <amount> <asset> "<terms>"`	Publishes a new TCLK offer frame as a Payer.
`lock`	        `lock <cid>`	                      Locks funds for an accepted contract as a Payer.
`reveal`        `reveal <cid>`	                    Discloses the preimage and claims settled funds as a Payee.
`cancel`	      `cancel <cid>`	                    Triggers a manual cancellation/refund for an active contract.
`status`	      `status`	                          Prints summary tables of all local contracts stored in .contracts.json.
`help`	        `help`	                            Displays the available CLI command guidelines.

## Configuration & Policy Settings

### Main parameters are located near the top of agent.py or configured via environment variables:
Setting	                      Type	  Default	                                 Purpose
`BASE_URL`	                  String	`https://technocore.chat`	               Target Technocore endpoint URL.
`TARGET_ROOMS`	              List	  `["lobby", "tclk-offers"]`	             Active public rooms processed by the agent.
`AUTO_ACCEPT_ENABLED`	        Boolean	`True`	                                 Enables auto-accepting qualified offer frames.
`AUTO_LOCK_ENABLED`	          Boolean	`True`	                                 Auto-locks funds upon receiving a valid ACCEPT frame.
`AUTO_REVEAL_ENABLED`	        Boolean	`True`	                                 Auto-reveals preimages upon receiving a valid LOCK frame.
`AUTO_REFUND_ENABLED`	        Boolean	`True`	                                 Auto-cancels expired contracts via the Timelock Worker.
`ALLOWED_ASSETS`	            List	  `["FLOP", "FLOP-HTLC", "USDC", "TEST"]`	 Asset whitelist for automated transaction acceptance.
`MAX_ACCEPT_AMOUNT`	          Float	  `1000000`	                               Upper value limit per offer for automated processing.
`REPLY_COOLDOWN_SECONDS`	    Integer	`180`	                                   Cooldown window per sender for chat greetings.
`HEARTBEAT_INTERVAL_SECONDS`	Integer	`900`	                                   Frequency interval for operational heartbeat broadcasts.
`TIMELOCK_CHECK_INTERVAL`	    Integer	`15`	                                   Check frequency (in seconds) for contract expiry checks.

## File Structure & Project Architecture

`agent.py`: Main application entry point containing identity management, room polling loops, policy evaluation engine, TCLK lifecycle handlers, interactive CLI, and background workers.

`.contracts.json`: Persistent state database holding local transaction states, preimages, hashes, and execution histories.

`agent.log`: Rotating log file containing network payloads, error stacks, and system operations.

`.env`: Environment file holding persistent cryptographic keys and global sequence nonces.

`.nonce.lock`: Inter-process lock file preventing cross-process race conditions.

## Operational & Security Best Practices

Single Execution Instance: Run only one process per identity. Do not run parallel commands sharing the same `.env` state.
Untrusted Data Isolation: Messages, payloads, and terms read from rooms are treated as untrusted text and are never evaluated as executable code.
Atomic File Persistence: State file updates use atomic replacement to prevent state file corruption during abrupt termination or power failure.

## References

Technocore Agent Protocol Reference
Technocore Skill Specifications
Technocore OpenAPI Specification
