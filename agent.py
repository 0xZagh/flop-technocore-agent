import os
import re
import random
import time
import base64
import json
import logging
import threading
import unicodedata
import secrets
import hashlib
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import requests
from dotenv import dotenv_values, load_dotenv, set_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# ==============================================================================
# KONFIGURASI UMUM & POLICY ENGINE (TAHAP 1 - 4 FINAL)
# ==============================================================================
BASE_URL = "https://technocore.chat"
TARGET_ROOMS = ["lobby", "tclk-offers"]
ENV_FILE = ".env"
CONTRACTS_FILE = ".contracts.json"
REPLY_COOLDOWN_SECONDS = 180
HEARTBEAT_INTERVAL_SECONDS = 900
TIMELOCK_CHECK_INTERVAL = 15  # Cek status timelock setiap 15 detik
NONCE_LOCK_FILE = ".nonce.lock"

# Policy Engine Configurations
AUTO_ACCEPT_ENABLED = os.getenv("AUTO_ACCEPT_ENABLED", "True").lower() in ("true", "1", "yes")
AUTO_LOCK_ENABLED = os.getenv("AUTO_LOCK_ENABLED", "True").lower() in ("true", "1", "yes")
AUTO_REVEAL_ENABLED = os.getenv("AUTO_REVEAL_ENABLED", "True").lower() in ("true", "1", "yes")
AUTO_REFUND_ENABLED = os.getenv("AUTO_REFUND_ENABLED", "True").lower() in ("true", "1", "yes")
ALLOWED_ASSETS = ["FLOP", "FLOP-HTLC", "USDC", "TEST"]
MAX_ACCEPT_AMOUNT = float(os.getenv("MAX_ACCEPT_AMOUNT", "1000000"))

# Setup Logging Real-Time
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logger = logging.getLogger("FlopAgent")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    log_formatter = logging.Formatter(LOG_FORMAT)
    
    # 1. File Handler (Rotating)
    file_handler = RotatingFileHandler(
        "agent.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)

    # 2. Console Handler Real-Time
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

load_dotenv(ENV_FILE)
NEXT_NONCE = int(os.getenv("NONCE", "0"))
NONCE_LOCK = threading.Lock()
CONTRACTS_LOCK = threading.Lock()

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ==============================================================================
# UTILITAS UTAMA & ENKRIPSI DID
# ==============================================================================
def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + (encoded or "")


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
            raise RuntimeError(f"Gagal membaca PRIVATE_KEY dari .env: {exc}") from exc

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    did = create_did(public_key)
    private_bytes = private_key.private_bytes_raw()
    private_b64 = base64.urlsafe_b64encode(private_bytes).decode().rstrip("=")

    set_key(ENV_FILE, "PRIVATE_KEY", private_b64)
    set_key(ENV_FILE, "DID", did)

    logger.info("Identitas baru berhasil dibuat.")
    logger.info("DID: %s", did)
    return private_key, did


def sweep_text(text: str) -> str:
    result = []
    for char in text:
        category = unicodedata.category(char)
        result.append(
            " " if category in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"} else char
        )
    return "".join(result).strip()


def get_next_nonce(minimum=0):
    global NEXT_NONCE
    with NONCE_LOCK:
        with open(NONCE_LOCK_FILE, "a+", encoding="utf-8") as lock_file:
            lock_file.seek(0)
            if not lock_file.read(1):
                lock_file.seek(0)
                lock_file.write("0")
                lock_file.flush()

            lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)

            try:
                values = dotenv_values(ENV_FILE)
                current = int(values.get("NONCE") or 0)
                now = int(time.time() * 1000)
                nonce = max(NEXT_NONCE + 1, current + 1, now, minimum + 1)
                NEXT_NONCE = nonce
                os.environ["NONCE"] = str(nonce)
                set_key(ENV_FILE, "NONCE", str(nonce))
                return nonce
            finally:
                if os.name == "nt":
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


# ==============================================================================
# HASHLOCK & ATOMIC PERSISTENCE STATE ENGINE
# ==============================================================================
def generate_hashlock():
    preimage_bytes = secrets.token_bytes(32)
    preimage_hex = preimage_bytes.hex()
    hash_hex = hashlib.sha256(preimage_bytes).hexdigest()
    return preimage_hex, hash_hex


def load_contracts():
    with CONTRACTS_LOCK:
        if not os.path.exists(CONTRACTS_FILE):
            return {}
        try:
            with open(CONTRACTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}


def save_contract(cid: str, contract_data: dict):
    """Menyimpan data kontrak secara atomic menggunakan file sementara"""
    with CONTRACTS_LOCK:
        contracts = load_contracts()
        contracts[cid] = contract_data
        
        temp_file = f"{CONTRACTS_FILE}.tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(contracts, f, indent=2)
            os.replace(temp_file, CONTRACTS_FILE)
        except Exception as exc:
            logger.error("Gagal menyimpan file kontrak secara atomic: %s", exc)
            if os.path.exists(temp_file):
                os.remove(temp_file)


# ==============================================================================
# HASHLOCK & TIMELOCK PROTOCOL ACTIONS (PAYER & PAYEE)
# ==============================================================================
def publish_tclk_offer(private_key, did: str, amount: str, asset: str, terms: str, payee: str = "*", room: str = "tclk-offers"):
    cid = f"cid-{secrets.token_hex(8)}"
    now_ms = int(time.time() * 1000)
    expires_ms = now_ms + (3600 * 1000)  # Masa berlaku default 1 jam

    offer_frame = {
        "type": "OFFER",
        "cid": cid,
        "payer": did,
        "payee": payee,
        "amount": str(amount),
        "asset": asset.upper(),
        "rail": "flop-htlc",
        "terms": terms,
        "ts": now_ms,
        "expires": expires_ms
    }

    raw_offer_payload = f"tclk1 {json.dumps(offer_frame, separators=(',', ':'))}"

    contract_state = {
        "cid": cid,
        "role": "PAYER",
        "payer": did,
        "payee": payee,
        "amount": amount,
        "asset": asset.upper(),
        "expires": expires_ms,
        "status": "OFFER_SENT",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "offer_frame": offer_frame
    }
    save_contract(cid, contract_state)

    logger.info("==================================================")
    logger.info("  🚀 [PAYER INITIATING OFFER] Mempublikasikan Penawaran...")
    logger.info("  • ContractID: %s", cid)
    logger.info("  • Amount    : %s %s", amount, asset.upper())
    logger.info("  • Terms     : %s", terms)
    logger.info("==================================================")

    send_signed_message(private_key, did, raw_offer_payload, room=room)
    logger.info("  ✅ [OFFER PUBLISHED] Penawaran %s berhasil dikirim ke /r/%s", cid, room)


def publish_tclk_lock(private_key, did: str, cid: str, room: str = "tclk-offers"):
    contracts = load_contracts()
    contract = contracts.get(cid)

    if not contract or contract.get("role") != "PAYER":
        logger.warning("❌ [LOCK FAILED] Kontrak %s tidak ditemukan atau Anda bukan PAYER.", cid)
        return

    payee_hash = contract.get("payee_hash")
    if not payee_hash:
        logger.warning("❌ [LOCK FAILED] Kontrak %s belum di-ACCEPT oleh Payee (Hash belum ada).", cid)
        return

    now_ms = int(time.time() * 1000)
    lock_frame = {
        "type": "LOCK",
        "cid": cid,
        "payer": did,
        "payee": contract.get("payee"),
        "hash": payee_hash,
        "amount": str(contract.get("amount")),
        "asset": str(contract.get("asset")).upper(),
        "ts": now_ms
    }

    raw_payload = f"tclk1 {json.dumps(lock_frame, separators=(',', ':'))}"

    contract["status"] = "LOCKED"
    contract["locked_at"] = datetime.now(timezone.utc).isoformat()
    save_contract(cid, contract)

    logger.info("==================================================")
    logger.info("  🔒 [PAYER LOCKING FUNDS] Mengunci Dana HTLC...")
    logger.info("  • ContractID: %s", cid)
    logger.info("  • Payee     : %s", contract.get("payee"))
    logger.info("  • Hash      : %s...", payee_hash[:16])
    logger.info("==================================================")

    send_signed_message(private_key, did, raw_payload, room=room)
    logger.info("  ✅ [LOCK SENT] Dana untuk %s berhasil dikunci di HTLC!", cid)


def publish_tclk_reveal(private_key, did: str, cid: str, room: str = "tclk-offers"):
    contracts = load_contracts()
    contract = contracts.get(cid)

    if not contract or contract.get("role") != "PAYEE":
        logger.warning("❌ [REVEAL FAILED] Kontrak %s tidak ditemukan atau Anda bukan PAYEE.", cid)
        return

    preimage = contract.get("preimage")
    if not preimage:
        logger.warning("❌ [REVEAL FAILED] Preimage rahasia untuk %s tidak ditemukan.", cid)
        return

    now_ms = int(time.time() * 1000)
    reveal_frame = {
        "type": "REVEAL",
        "cid": cid,
        "payer": contract.get("payer"),
        "payee": did,
        "preimage": preimage,
        "ts": now_ms
    }

    raw_payload = f"tclk1 {json.dumps(reveal_frame, separators=(',', ':'))}"

    contract["status"] = "CLAIMED"
    contract["claimed_at"] = datetime.now(timezone.utc).isoformat()
    save_contract(cid, contract)

    logger.info("==================================================")
    logger.info("  🔓 [PAYEE REVEALING PREIMAGE] Membuka Preimage & Mengklaim Dana...")
    logger.info("  • ContractID: %s", cid)
    logger.info("  • Preimage  : %s...", preimage[:16])
    logger.info("==================================================")

    send_signed_message(private_key, did, raw_payload, room=room)
    logger.info("  ✅ [REVEAL SENT] Frame REVEAL untuk %s berhasil dikirim!", cid)


def publish_tclk_cancel(private_key, did: str, cid: str, reason: str = "Timelock Expired", room: str = "tclk-offers"):
    """Mengirim frame CANCEL / REFUND untuk membatalkan kontrak kadaluwarsa"""
    contracts = load_contracts()
    contract = contracts.get(cid)

    if not contract:
        return

    now_ms = int(time.time() * 1000)
    cancel_frame = {
        "type": "CANCEL",
        "cid": cid,
        "sender": did,
        "reason": reason,
        "ts": now_ms
    }

    raw_payload = f"tclk1 {json.dumps(cancel_frame, separators=(',', ':'))}"

    contract["status"] = "CANCELLED"
    contract["cancel_reason"] = reason
    contract["cancelled_at"] = datetime.now(timezone.utc).isoformat()
    save_contract(cid, contract)

    logger.info("==================================================")
    logger.info("  ⏰ [TIMELOCK CANCEL/REFUND EXECUTED]")
    logger.info("  • ContractID: %s", cid)
    logger.info("  • Reason    : %s", reason)
    logger.info("==================================================")

    send_signed_message(private_key, did, raw_payload, room=room)


# ==============================================================================
# TIMELOCK & REFUND ENGINE (BACKGROUND WORKER THREAD)
# ==============================================================================
def timelock_engine_thread(private_key, did):
    """
    Worker independen yang terus memeriksa timelock pada setiap kontrak.
    Jika masa berlaku habis, otomatis mengubah status & menginisiasi pembatalan/refund.
    """
    while True:
        try:
            time.sleep(TIMELOCK_CHECK_INTERVAL)
            contracts = load_contracts()
            now_ms = int(time.time() * 1000)

            for cid, contract in contracts.items():
                status = contract.get("status")
                expires = contract.get("expires")

                # Lewati jika transaksi sudah selesai/lunas/dibatalkan
                if status in ["SETTLED", "CANCELLED", "EXPIRED"]:
                    continue

                if expires and now_ms > int(expires):
                    logger.warning("  ⌛ [TIMELOCK EXPIRED] Kontrak %s telah melebihi batas waktu!", cid)

                    if AUTO_REFUND_ENABLED and status in ["OFFER_SENT", "ACCEPTED_BY_PAYEE", "LOCKED"]:
                        publish_tclk_cancel(private_key, did, cid, reason="Timelock Expiration Auto-Refund")
                    else:
                        contract["status"] = "EXPIRED"
                        contract["expired_at"] = datetime.now(timezone.utc).isoformat()
                        save_contract(cid, contract)

        except Exception as exc:
            logger.error("[Timelock Engine Error] %s", exc)


# ==============================================================================
# CLI INTERAKTIF PRODUKSI (TAHAP 4)
# ==============================================================================
def cli_input_thread(private_key, did):
    time.sleep(2)
    print("\n" + "="*60)
    print("  🖥️  CLI INTERAKTIF TCLK FULL HTLC (TAHAP 4 FINAL BUILD)")
    print("="*60)
    print("  Perintah yang tersedia:")
    print('  1. offer <amount> <asset> "<terms>"  (Buat Offer - Payer)')
    print('  2. lock <cid>                       (Kunci Dana HTLC - Payer)')
    print('  3. reveal <cid>                     (Buka Preimage/Klaim - Payee)')
    print('  4. cancel <cid>                     (Batal/Refund Manual)')
    print("  5. status                           (Cek Status Kontrak Lokal)")
    print("  6. help                             (Bantuan)")
    print("="*60 + "\n")

    while True:
        try:
            cmd = input().strip()
            if not cmd:
                continue

            parts = cmd.split(maxsplit=3)
            action = parts[0].lower()

            if action == "help":
                print("\n[PANDUAN CLI TCLK - FINAL PRODUCTION]")
                print("• Payer Flow : offer -> lock -> (menunggu reveal payee)")
                print("• Payee Flow : auto-accept -> auto-reveal saat lock diterima")
                print("• Timelock   : Otomatis membatalkan kontrak jika kadaluwarsa")
                print("• Cek Status : status\n")

            elif action == "status":
                contracts = load_contracts()
                print(f"\n[STATUS KONTRAK LOKAL] Total: {len(contracts)}")
                if not contracts:
                    print("  (Belum ada kontrak tersimpan)")
                for cid, data in contracts.items():
                    print(f" • CID: {cid} | Role: {data.get('role', 'N/A')} | Status: {data.get('status')} | {data.get('amount')} {data.get('asset')}")
                print("")

            elif action == "offer":
                if len(parts) < 4:
                    print('❌ Format salah! Gunakan: offer <amount> <asset> "<terms>"')
                    continue
                amount_in = parts[1]
                asset_in = parts[2]
                terms_in = parts[3].strip('"\'')
                publish_tclk_offer(private_key, did, amount_in, asset_in, terms_in)

            elif action == "lock":
                if len(parts) < 2:
                    print("❌ Format salah! Gunakan: lock <cid>")
                    continue
                publish_tclk_lock(private_key, did, parts[1])

            elif action == "reveal":
                if len(parts) < 2:
                    print("❌ Format salah! Gunakan: reveal <cid>")
                    continue
                publish_tclk_reveal(private_key, did, parts[1])

            elif action == "cancel":
                if len(parts) < 2:
                    print("❌ Format salah! Gunakan: cancel <cid>")
                    continue
                publish_tclk_cancel(private_key, did, parts[1], reason="Manual CLI Cancellation")

            else:
                print(f"Perintah '{action}' tidak dikenal. Ketik 'help' untuk panduan.")

        except Exception as exc:
            logger.error("[CLI Error] %s", exc)


# ==============================================================================
# PARSER & LOGIC TCLK PROTOCOL (FULL ENGINE)
# ==============================================================================
def parse_tclk_frame(text: str):
    if not text or not text.startswith("tclk1 "):
        return False, None, None

    raw_json = text[6:].strip()
    try:
        data = json.loads(raw_json)
        if isinstance(data, dict):
            return True, data, None
        return True, None, "Payload JSON bukan objek/dict"
    except json.JSONDecodeError as exc:
        return True, None, f"JSON Decode Error: {exc}"


def log_tclk_frame(room: str, sender: str, frame: dict):
    frame_type = str(frame.get("type", "unknown")).upper()
    contract_id = frame.get("cid") or frame.get("contractId") or "N/A"

    logger.info("==================================================")
    logger.info("  🟢 [TCLK DETECTED] Frame Transaksi Terdeteksi!")
    logger.info("  • Room      : /r/%s", room)
    logger.info("  • Sender    : %s", sender)
    logger.info("  • Frame Type: %s", frame_type)
    logger.info("  • ContractID: %s", contract_id)

    if frame_type == "OFFER":
        logger.info("  • Amount    : %s %s", frame.get("amount", "?"), frame.get("asset", ""))
        logger.info("  • Rail      : %s", frame.get("rail", "N/A"))
        logger.info("  • Terms     : %s", frame.get("terms", "N/A"))
    elif frame_type == "ACCEPT":
        logger.info("  • Hash      : %s...", str(frame.get("hash", ""))[:16])
    elif frame_type == "LOCK":
        logger.info("  • Hash      : %s...", str(frame.get("hash", ""))[:16])
        logger.info("  • Amount    : %s %s", frame.get("amount", "?"), frame.get("asset", ""))
    elif frame_type == "REVEAL":
        logger.info("  • Preimage  : %s...", str(frame.get("preimage", ""))[:16])
    elif frame_type == "CANCEL":
        logger.info("  • Reason    : %s", frame.get("reason", "N/A"))

    logger.info("==================================================")


def process_tclk_offer(frame: dict, sender: str, room: str, private_key, did: str):
    if not AUTO_ACCEPT_ENABLED:
        logger.info("[POLICY] Auto-accept nonaktif via konfigurasi.")
        return

    cid = frame.get("cid") or frame.get("contractId")
    payer = frame.get("payer") or sender
    payee = frame.get("payee")
    amount_str = str(frame.get("amount", "0"))
    asset = str(frame.get("asset", "")).upper()
    expires = frame.get("expires") or frame.get("expiresNs")

    if not cid or cid in load_contracts():
        return

    if payee and payee != "*" and payee != did:
        return

    if asset not in [a.upper() for a in ALLOWED_ASSETS]:
        logger.warning("[POLICY REJECT] Asset '%s' tidak ada dalam daftar izin %s.", asset, ALLOWED_ASSETS)
        return

    try:
        amount_val = float(amount_str)
        if amount_val > MAX_ACCEPT_AMOUNT:
            logger.warning("[POLICY REJECT] Amount %f melebihi batas maks %f.", amount_val, MAX_ACCEPT_AMOUNT)
            return
    except ValueError:
        return

    if expires:
        try:
            exp_ts = int(expires)
            if exp_ts > 10**12:
                exp_ts = exp_ts / 1000.0
            if exp_ts > 10**10:
                exp_ts = exp_ts / 1000.0
            if time.time() > exp_ts:
                return
        except Exception:
            pass

    logger.info("  ⚡ [AUTO-ACCEPT QUALIFIED] Penawaran %s memenuhi kriteria!", cid)
    preimage_hex, hash_hex = generate_hashlock()

    accept_frame = {
        "type": "ACCEPT",
        "cid": cid,
        "payer": payer,
        "payee": did,
        "hash": hash_hex,
        "ts": int(time.time() * 1000)
    }

    raw_accept_payload = f"tclk1 {json.dumps(accept_frame, separators=(',', ':'))}"

    contract_state = {
        "cid": cid,
        "role": "PAYEE",
        "payer": payer,
        "payee": did,
        "amount": amount_str,
        "asset": asset,
        "expires": expires,
        "preimage": preimage_hex,
        "hash": hash_hex,
        "status": "ACCEPTED",
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "offer_frame": frame
    }
    save_contract(cid, contract_state)

    logger.info("  🚀 Mengirim balasan 'tclk1 ACCEPT' ke /r/%s...", room)
    send_signed_message(private_key, did, raw_accept_payload, room=room)
    logger.info("  ✅ [SUCCESS] Contract %s berhasil di-ACCEPT! Hash: %s...", cid, hash_hex[:16])


def process_tclk_accept(frame: dict, sender: str, room: str, private_key, did: str):
    cid = frame.get("cid")
    if not cid:
        return

    contracts = load_contracts()
    if cid in contracts and contracts[cid].get("role") == "PAYER":
        contracts[cid]["status"] = "ACCEPTED_BY_PAYEE"
        contracts[cid]["payee"] = sender
        contracts[cid]["payee_hash"] = frame.get("hash")
        save_contract(cid, contracts[cid])
        logger.info("  🎉 [OFFER ACCEPTED!] Penawaran Anda (%s) telah di-ACCEPT oleh %s!", cid, sender)

        if AUTO_LOCK_ENABLED:
            logger.info("  ⚡ [AUTO-LOCK] Eksekusi penguncian dana otomatis...")
            publish_tclk_lock(private_key, did, cid, room=room)


def process_tclk_lock(frame: dict, sender: str, room: str, private_key, did: str):
    cid = frame.get("cid")
    if not cid:
        return

    contracts = load_contracts()
    if cid in contracts and contracts[cid].get("role") == "PAYEE":
        incoming_hash = frame.get("hash")
        local_hash = contracts[cid].get("hash")

        if incoming_hash == local_hash:
            contracts[cid]["status"] = "LOCKED"
            contracts[cid]["locked_at"] = datetime.now(timezone.utc).isoformat()
            save_contract(cid, contracts[cid])
            logger.info("  🔒 [FUNDS LOCKED BY PAYER] Dana untuk %s telah dikunci oleh Payer!", cid)

            if AUTO_REVEAL_ENABLED:
                logger.info("  ⚡ [AUTO-REVEAL] Menjalankan klaim / pembukaan preimage otomatis...")
                publish_tclk_reveal(private_key, did, cid, room=room)
        else:
            logger.warning("  ⚠️ [HASH MISMATCH] Hash LOCK (%s) tidak cocok dengan hash lokal!", incoming_hash)


def process_tclk_reveal(frame: dict, sender: str):
    cid = frame.get("cid")
    preimage_hex = frame.get("preimage")

    if not cid or not preimage_hex:
        return

    contracts = load_contracts()
    if cid in contracts and contracts[cid].get("role") == "PAYER":
        expected_hash = contracts[cid].get("payee_hash")

        try:
            computed_hash = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()
            if computed_hash == expected_hash:
                contracts[cid]["status"] = "SETTLED"
                contracts[cid]["preimage_revealed"] = preimage_hex
                contracts[cid]["settled_at"] = datetime.now(timezone.utc).isoformat()
                save_contract(cid, contracts[cid])

                logger.info("==================================================")
                logger.info("  🏆 [HTLC SETTLED / TRANSAKSI LUNAS!]")
                logger.info("  • ContractID   : %s", cid)
                logger.info("  • Preimage     : %s", preimage_hex)
                logger.info("  • Hash Verified: TRUE (SHA-256 Match)")
                logger.info("  • Status       : SETTLED (LUNAS & SELESAI)")
                logger.info("==================================================")
            else:
                logger.warning("  ⚠️ [SETTLEMENT FAILED] Preimage tidak cocok dengan Hash! Expected: %s", expected_hash)
        except Exception as exc:
            logger.error("  ❌ [VERIFICATION ERROR] Gagal memverifikasi preimage: %s", exc)


def process_tclk_cancel(frame: dict, sender: str):
    cid = frame.get("cid")
    reason = frame.get("reason", "No reason provided")

    if not cid:
        return

    contracts = load_contracts()
    if cid in contracts:
        contracts[cid]["status"] = "CANCELLED"
        contracts[cid]["cancel_reason"] = reason
        contracts[cid]["cancelled_at"] = datetime.now(timezone.utc).isoformat()
        save_contract(cid, contracts[cid])
        logger.info("  ⛔ [TRANSAKSI DIBATALKAN] Kontrak %s dibatalkan oleh %s. Alasan: %s", cid, sender, reason)


# ==============================================================================
# PENGIRIMAN & PENERIMAAN PESAN HTTP
# ==============================================================================
def sign_message(private_key, room, nonce, text):
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = private_key.sign(payload)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def send_signed_message(private_key, did, text, room="lobby"):
    text = sweep_text(text)
    if not text:
        return

    if len(text) > 4096:
        text = text[:4096]

    url = f"{BASE_URL}/r/{room}"

    for attempt in range(3):
        nonce = get_next_nonce()
        signature = sign_message(private_key, room, nonce, text)
        payload = {
            "did": did,
            "sig": signature,
            "nonce": str(nonce),
            "text": text,
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            response.raise_for_status()
            logger.info("[sent][/r/%s] %s", room, text[:100] + ("..." if len(text) > 100 else ""))
            return
        except requests.HTTPError as exc:
            if (
                exc.response is not None
                and exc.response.status_code == 422
                and "duplicate text" in exc.response.text.lower()
            ):
                logger.warning("[skipped] Server menolak pesan duplikat.")
                return

            if attempt < 2 and exc.response is not None and exc.response.status_code == 400:
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
    return "FLOP agent here (TCLK Production HTLC Settlement Engine Active)"


def response_text(text):
    normalized = text.casefold().strip()

    general_responses = [
        "I received your message and understand it as information for this conversation.",
        "Acknowledged. Processing your input in the current epoch.",
        "Message received. Monitoring lobby signal stability.",
        "Got it! Updating local state with your latest broadcast."
    ]

    greetings = [
        "Hello! I am active and ready to discuss.",
        "Hey there! Node is live and operational.",
        "GM! Active and synced with the Technocore lobby."
    ]

    if any(word in normalized for word in ("hello", "hi", "hey", "gm")):
        return random.choice(greetings)

    return random.choice(general_responses)


def send_heartbeat(private_key, did):
    send_signed_message(private_key, did, heartbeat_text(), room="lobby")


def get_messages(room="lobby", since=None, poll_counter=None):
    url = f"{BASE_URL}/r/{room}"
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


def handle_message(message, private_key, did, reply_times, room):
    text = message.get("text", "")
    sender = message.get("from", "~unknown")

    if not text or sender == did:
        return

    sanitized_text = sweep_text(text)

    is_tclk, frame_data, parse_err = parse_tclk_frame(sanitized_text)
    if is_tclk:
        if frame_data:
            log_tclk_frame(room, sender, frame_data)
            frame_type = str(frame_data.get("type", "")).upper()

            if frame_type == "OFFER":
                process_tclk_offer(frame_data, sender, room, private_key, did)
            elif frame_type == "ACCEPT":
                process_tclk_accept(frame_data, sender, room, private_key, did)
            elif frame_type == "LOCK":
                process_tclk_lock(frame_data, sender, room, private_key, did)
            elif frame_type == "REVEAL":
                process_tclk_reveal(frame_data, sender)
            elif frame_type == "CANCEL":
                process_tclk_cancel(frame_data, sender)
        return

    if room == "tclk-offers":
        return

    logger.info("[%s][/r/%s] %s", sender, room, sanitized_text)

    now = time.monotonic()
    last_reply = reply_times.get(sender)
    if last_reply is not None and now - last_reply < REPLY_COOLDOWN_SECONDS:
        return

    send_signed_message(private_key, did, response_text(text), room=room)
    reply_times[sender] = now


# ==============================================================================
# UTAMA (MAIN EVENT LOOP WITH AUTO-RECOVERY)
# ==============================================================================
def main():
    logger.info("==================================================")
    logger.info("  🤖 FLOP AGENT - PRODUCTION BUILD (TAHAP 4)")
    logger.info("==================================================")
    logger.info("Target Rooms       : %s", [f"/r/{r}" for r in TARGET_ROOMS])
    logger.info("Auto-Accept Policy : %s (Allowed Assets: %s)", AUTO_ACCEPT_ENABLED, ALLOWED_ASSETS)
    logger.info("Auto-Lock Policy   : %s | Auto-Reveal Policy: %s", AUTO_LOCK_ENABLED, AUTO_REVEAL_ENABLED)
    logger.info("Auto-Refund Policy : %s", AUTO_REFUND_ENABLED)

    private_key, did = load_or_create_identity()
    logger.info("DID                : %s", did)

    # Thread 1: CLI Interaktif
    cli_thread = threading.Thread(target=cli_input_thread, args=(private_key, did), daemon=True)
    cli_thread.start()

    # Thread 2: Timelock & Refund Engine
    timelock_thread = threading.Thread(target=timelock_engine_thread, args=(private_key, did), daemon=True)
    timelock_thread.start()

    last_seq_map = {room: None for room in TARGET_ROOMS}
    reply_times = {}
    last_heartbeat = time.monotonic()
    poll_counter = 0
    initialized = False

    backoff = 1

    while True:
        try:
            poll_counter += 1

            if not initialized:
                for room in TARGET_ROOMS:
                    last_seq_map[room] = latest_seq(get_messages(room=room))

                send_signed_message(private_key, did, greeting_text(), room="lobby")
                initialized = True
                backoff = 1
                continue

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                send_heartbeat(private_key, did)
                last_heartbeat = now

            for room in TARGET_ROOMS:
                messages = get_messages(room=room, since=last_seq_map[room], poll_counter=poll_counter)
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

                    handle_message(message, private_key, did, reply_times, room=room)

                    if seq is not None and (last_seq_map[room] is None or seq > last_seq_map[room]):
                        last_seq_map[room] = seq

            # Reset delay exponential backoff saat polling sukses
            backoff = 1

        except requests.HTTPError as exc:
            logger.error("[HTTP Error] %s. Retrying in %ds...", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
        except requests.RequestException as exc:
            logger.error("[Network Error] %s. Retrying in %ds...", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
        except KeyboardInterrupt:
            logger.info("Agen dihentikan oleh pengguna.")
            break
        except Exception as exc:
            logger.exception("[Unexpected Error] %s", exc)
            time.sleep(2)


if __name__ == "__main__":
    main()