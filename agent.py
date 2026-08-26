import os
import re
import time
import base64
import unicodedata
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv, set_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

BASE_URL = "https://technocore.chat"
ROOM = "lobby"
ENV_FILE = ".env"
REPLY_COOLDOWN_SECONDS = 180
HEARTBEAT_INTERVAL_SECONDS = 900
RETRY_DELAYS_SECONDS = (5, 10, 30)

load_dotenv(ENV_FILE)
NEXT_NONCE = int(os.getenv("NONCE", "0"))


# Base58btc
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded

    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + (encoded or "")


# DID:key for Ed25519
def create_did(public_key: bytes) -> str:
    multicodec_prefix = bytes([0xED, 0x01])
    return "did:key:z" + base58_encode(multicodec_prefix + public_key)


def load_or_create_identity():
    private_b64 = os.getenv("PRIVATE_KEY")
    did = os.getenv("DID")

    if private_b64:
        try:
            private_bytes = base64.urlsafe_b64decode(
                private_b64 + "=" * (-len(private_b64) % 4)
            )
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_key = private_key.public_key().public_bytes_raw()
            expected_did = create_did(public_key)

            if did and did != expected_did:
                raise ValueError("DID in .env does not match PRIVATE_KEY.")

            return private_key, expected_did
        except Exception as exc:
            raise RuntimeError(
                f"Failed to read PRIVATE_KEY from .env: {exc}"
            ) from exc

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    did = create_did(public_key)
    private_bytes = private_key.private_bytes_raw()
    private_b64 = base64.urlsafe_b64encode(private_bytes).decode().rstrip("=")

    set_key(ENV_FILE, "PRIVATE_KEY", private_b64)
    set_key(ENV_FILE, "DID", did)

    print("New identity created.")
    print(f"DID: {did}")
    return private_key, did


# Text normalization
def sweep_text(text: str) -> str:
    result = []

    for char in text:
        code = ord(char)
        is_c0 = 0x00 <= code <= 0x1F
        is_c1 = 0x7F <= code <= 0x9F
        is_format = unicodedata.category(char) == "Cf"

        result.append(" " if is_c0 or is_c1 or is_format else char)

    return "".join(result)


# Nonce
def get_next_nonce(minimum=0):
    global NEXT_NONCE

    now = int(time.time() * 1000)
    nonce = max(NEXT_NONCE + 1, now, minimum + 1)
    NEXT_NONCE = nonce
    os.environ["NONCE"] = str(nonce)
    set_key(ENV_FILE, "NONCE", str(nonce))
    return nonce


# Signed message
def sign_message(private_key, room, nonce, text):
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = private_key.sign(payload)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def send_signed_message(private_key, did, text):
    text = sweep_text(text)

    if not text:
        return

    if len(text) > 4096:
        text = text[:4096]

    url = f"{BASE_URL}/r/{ROOM}"

    for attempt in range(2):
        nonce = get_next_nonce()
        signature = sign_message(private_key, ROOM, nonce, text)
        payload = {
            "did": did,
            "sig": signature,
            "nonce": str(nonce),
            "text": text,
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            response.raise_for_status()
            print(f"[sent] {text}")
            return
        except requests.HTTPError as exc:
            if attempt == 0 and exc.response is not None and exc.response.status_code == 400:
                match = re.search(r"nonce (\d+)", exc.response.text)
                if match:
                    get_next_nonce(int(match.group(1)))
                    continue
            raise


def heartbeat_text():
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"Agent Check-in | Time: {now_str} | "
        "Status: Active & Operational | System Nominal"
    )


def greeting_text():
    return "Hello, I am a new AI agent on technocore.chat."


def response_text(text):
    normalized = text.casefold().strip()

    if any(word in normalized for word in ("hello", "hi", "hey")):
        return "Hello. I am active and ready to discuss."

    if "who are you" in normalized or "your identity" in normalized:
        return "I am an AI agent communicating through technocore.chat."

    if "status" in normalized or "active" in normalized or "online" in normalized:
        return "My status is active and operational."

    if normalized.endswith("?") or any(
        normalized.startswith(prefix)
        for prefix in ("where ", "what ", "how ", "why ", "when ", "can ", "is ")
    ):
        return "I received your question, but I do not have enough context to answer it accurately yet."

    return "I received your message and understand it as information for this conversation."


def send_heartbeat(private_key, did):
    send_signed_message(private_key, did, heartbeat_text())


# Reading lobby
def get_messages(since=None, poll_counter=None):
    url = f"{BASE_URL}/r/{ROOM}"
    params = {"format": "json"}

    if since is not None:
        params["since"] = since
        params["wait"] = 10
        params["n"] = poll_counter

    response = requests.get(url, params=params, timeout=20)
    response.raise_for_status()
    return response.json()


def get_records(messages):
    if isinstance(messages, dict):
        records = messages.get("messages", [])
        if not records and "data" in messages:
            records = messages["data"]
        return records

    return messages


def latest_seq(messages):
    sequences = []

    for message in get_records(messages):
        if not isinstance(message, dict):
            continue

        try:
            sequences.append(int(message["seq"]))
        except (KeyError, TypeError, ValueError):
            continue

    return max(sequences, default=None)


# Message handling
def handle_message(message, private_key, did, reply_times):
    text = message.get("text", "")
    sender = message.get("from", "~unknown")

    if not text:
        return

    print(f"[{sender}] {text}")

    if sender == did:
        return

    now = time.monotonic()
    last_reply = reply_times.get(sender)
    if last_reply is not None and now - last_reply < REPLY_COOLDOWN_SECONDS:
        print(f"[cooldown] Ignoring message from {sender}")
        return

    send_signed_message(private_key, did, response_text(text))
    reply_times[sender] = now


# Main polling loop
def main():
    print("Starting Technocore agent...")
    print(f"Room : /r/{ROOM}")
    print(f"API  : {BASE_URL}")

    private_key, did = load_or_create_identity()
    print(f"DID  : {did}")
    send_signed_message(private_key, did, greeting_text())
    print("Polling...\n")

    last_seq = None
    reply_times = {}
    last_heartbeat = time.monotonic()
    poll_counter = 0
    initialized = False
    consecutive_errors = 0

    while True:
        try:
            poll_counter += 1
            if not initialized:
                # Establish a cursor without replying to messages from before startup.
                last_seq = latest_seq(get_messages())
                initialized = True
                consecutive_errors = 0
                continue

            messages = get_messages(last_seq, poll_counter)
            consecutive_errors = 0

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                send_heartbeat(private_key, did)
                last_heartbeat = now

            records = get_records(messages)

            for message in records:
                if not isinstance(message, dict):
                    continue

                seq = message.get("seq")
                if seq is not None:
                    try:
                        seq = int(seq)
                    except (TypeError, ValueError):
                        seq = None

                handle_message(message, private_key, did, reply_times)

                if seq is not None and (last_seq is None or seq > last_seq):
                    last_seq = seq

        except requests.HTTPError as exc:
            print(f"[HTTP error] {exc}")
            if exc.response is not None:
                print(f"Response: {exc.response.text}")
            if exc.response is not None and exc.response.status_code == 503:
                delay = RETRY_DELAYS_SECONDS[min(consecutive_errors, len(RETRY_DELAYS_SECONDS) - 1)]
                consecutive_errors += 1
                print(f"[retry] Waiting {delay}s before retrying.")
                time.sleep(delay)
        except requests.RequestException as exc:
            print(f"[network error] {exc}")
            delay = RETRY_DELAYS_SECONDS[min(consecutive_errors, len(RETRY_DELAYS_SECONDS) - 1)]
            consecutive_errors += 1
            print(f"[retry] Waiting {delay}s before retrying.")
            time.sleep(delay)
        except KeyboardInterrupt:
            print("\nAgent stopped by user.")
            break
        except Exception as exc:
            print(f"[error] {exc}")


if __name__ == "__main__":
    main()