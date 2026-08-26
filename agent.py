import os
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

load_dotenv(ENV_FILE)


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
                raise ValueError("DID di .env tidak cocok dengan PRIVATE_KEY.")

            return private_key, expected_did
        except Exception as exc:
            raise RuntimeError(
                f"Gagal membaca PRIVATE_KEY dari .env: {exc}"
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
def get_next_nonce():
    current = int(os.getenv("NONCE", "0"))
    now = int(time.time() * 1000)
    nonce = max(current + 1, now)
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

    nonce = get_next_nonce()
    signature = sign_message(private_key, ROOM, nonce, text)
    url = f"{BASE_URL}/r/{ROOM}"
    payload = {
        "did": did,
        "sig": signature,
        "nonce": str(nonce),
        "text": text,
    }

    response = requests.post(url, json=payload, timeout=15)
    response.raise_for_status()
    print(f"[sent] {text}")


def heartbeat_text():
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"Agent Check-in | Time: {now_str} | "
        "Status: Active & Operational | System Nominal"
    )


def send_heartbeat(private_key, did):
    send_signed_message(private_key, did, heartbeat_text())


# Reading lobby
def get_messages(since=None):
    url = f"{BASE_URL}/r/{ROOM}"
    params = {"format": "json"}

    if since is not None:
        params["since"] = since
        params["wait"] = 10

    response = requests.get(url, params=params, timeout=20)
    response.raise_for_status()
    return response.json()


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

    send_signed_message(private_key, did, heartbeat_text())
    reply_times[sender] = now


# Main polling loop
def main():
    print("Starting Technocore agent...")
    print(f"Room : /r/{ROOM}")
    print(f"API  : {BASE_URL}")

    private_key, did = load_or_create_identity()
    print(f"DID  : {did}")
    print("Polling...\n")

    last_seq = None
    reply_times = {}
    last_heartbeat = 0.0

    while True:
        try:
            messages = get_messages(last_seq)

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                send_heartbeat(private_key, did)
                last_heartbeat = now

            if isinstance(messages, dict):
                records = messages.get("messages", [])
                if not records and "data" in messages:
                    records = messages["data"]
            else:
                records = messages

            for message in records:
                if not isinstance(message, dict):
                    continue

                seq = message.get("seq")
                if seq is not None:
                    try:
                        seq = int(seq)
                        if last_seq is None or seq > last_seq:
                            last_seq = seq
                    except (TypeError, ValueError):
                        pass

                handle_message(message, private_key, did, reply_times)

        except requests.HTTPError as exc:
            print(f"[HTTP error] {exc}")
            if exc.response is not None:
                print(f"Response: {exc.response.text}")
        except requests.RequestException as exc:
            print(f"[network error] {exc}")
        except KeyboardInterrupt:
            print("\nAgent stopped.")
            break
        except Exception as exc:
            print(f"[error] {exc}")


if __name__ == "__main__":
    main()