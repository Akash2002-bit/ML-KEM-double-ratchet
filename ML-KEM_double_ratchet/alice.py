import asyncio
import binascii
import os
import sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from mlkem import ML_KEM_KEYGEN, ML_KEM_ENCAPS, ML_KEM_DECAPS

HOST = '127.0.0.1'
PORT = 65432
ROOT_KEY_HEX = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"  # example root key
ROOT_KEY = binascii.unhexlify(ROOT_KEY_HEX)
CIPHER_IDENTIFIER = b"cipherkey"
CIPHER_IDENTIFIEREK = b"ekcipherkey"

# ====== Display Helper ======
def show_message(direction, count, kind, text):
    arrow = "→" if direction == "Send" else "←"
    print(f"[{direction} #{count}] {kind} {arrow} \"{text}\"")

# ====== Shared State ======
class State:
    def __init__(self, root_key, ek_a, dk_a, ek_b=None):
        self.root_key = root_key
        self.send_chain_key = None
        self.recv_chain_key = None
        self.ek_a = ek_a
        self.dk_a = dk_a
        self.ek_b = ek_b
        self.received_ekb_flag = False
        self.send_count = 0
        self.recv_count = 0

# ====== Crypto Helpers ======
def hkdf_expand(ikm, info, length=64):
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(ikm)

def derive_root_and_chain_key(root_key, shared_secret):
    output = hkdf_expand(root_key + shared_secret, b"hkdf1")
    return output[:32], output[32:]

def derive_chain_and_message_key(chain_key):
    output = hkdf_expand(chain_key, b"hkdf2")
    return output[:32], output[32:]

def encrypt_message(message_key, plaintext):
    aesgcm = AESGCM(message_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

def decrypt_message(message_key, nonce, ciphertext):
    aesgcm = AESGCM(message_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

async def recv_exact(reader, n):
    data = b''
    while len(data) < n:
        packet = await reader.read(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed")
        data += packet
    return data

# ====== Main Connection Handler ======
async def handle_connection(reader, writer):
    ek_a, dk_a = ML_KEM_KEYGEN()
    state = State(ROOT_KEY, ek_a, dk_a)
    # initial root -> send chain (empty shared secret)
    state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, b"")

    # Send Alice's public key to Bob
    writer.write(len(ek_a).to_bytes(4, 'big') + bytes(ek_a))
    await writer.drain()

    recv_task = asyncio.create_task(receive_messages(reader, state))
    await handle_user_input(writer, state)
    await recv_task

# ====== Input Sender ======
async def handle_user_input(writer, state):
    while True:
        user_input = await asyncio.to_thread(input, "\nSend message to Bob: ")
        if not user_input:
            continue

        # If Bob has sent ek_b and we reset our send chain (after his rekey),
        # we must rekey (cipher-only) before sending again.
        if state.ek_b is not None and state.send_chain_key is None:
            shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_b))
            state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
            next_chain, message_key = derive_chain_and_message_key(state.send_chain_key)
            nonce, ciphertext = encrypt_message(message_key, user_input)

            payload = CIPHER_IDENTIFIER + nonce + ciphertext
            # send: len(payload)|payload ; len(encap)|encap
            writer.write(len(payload).to_bytes(4, 'big') + payload)
            encap_bytes = bytes(encap)
            writer.write(len(encap_bytes).to_bytes(4, 'big') + encap_bytes)
            await writer.drain()

            state.send_chain_key = next_chain
            state.send_count += 1
            show_message("Send", state.send_count, "Cipher-only Rekey", user_input)
            continue

        # Regular chained message
        state.send_chain_key, message_key = derive_chain_and_message_key(state.send_chain_key)
        nonce, ciphertext = encrypt_message(message_key, user_input)
        writer.write(len(nonce + ciphertext).to_bytes(4, 'big') + nonce + ciphertext)
        await writer.drain()
        state.send_count += 1
        show_message("Send", state.send_count, "Regular", user_input)

# ====== Message Receiver ======
async def receive_messages(reader, state):
    while True:
        try:
            # read framed chunk
            len_data = int.from_bytes(await recv_exact(reader, 4), 'big')
            data = await recv_exact(reader, len_data)

            # --- Bob initiated EK + cipher rekey (first send path) ---
            if data.startswith(CIPHER_IDENTIFIEREK):
                nonce = data[len(CIPHER_IDENTIFIEREK):len(CIPHER_IDENTIFIEREK) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIEREK) + 12:]

                # read encap
                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                # read ek_b
                len_ekb = int.from_bytes(await recv_exact(reader, 4), 'big')
                ek_b = await recv_exact(reader, len_ekb)
                state.ek_b = ek_b

                # reset our send chain so next send we will rekey using ek_b
                state.send_chain_key = None

                shared_secret = ML_KEM_DECAPS(state.dk_a, list(encap))
                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                next_chain, message_key = derive_chain_and_message_key(state.recv_chain_key)
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = next_chain
                state.recv_count += 1
                show_message("Recv", state.recv_count, "EK + Cipher Rekey", plaintext)
                continue

            # --- Bob initiated cipher-only rekey (later rekeys) ---
            if data.startswith(CIPHER_IDENTIFIER):
                nonce = data[len(CIPHER_IDENTIFIER):len(CIPHER_IDENTIFIER) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIER) + 12:]

                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                # reset our send chain (we must rekey on next send)
                state.send_chain_key = None

                shared_secret = ML_KEM_DECAPS(state.dk_a, list(encap))
                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                next_chain, message_key = derive_chain_and_message_key(state.recv_chain_key)
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = next_chain
                state.recv_count += 1
                show_message("Recv", state.recv_count, "Cipher-only Rekey", plaintext)
                continue

            # --- Regular chained message ---
            recv_chain_key_before_step = state.recv_chain_key
            state.recv_chain_key, message_key = derive_chain_and_message_key(state.recv_chain_key)
            nonce, ciphertext = data[:12], data[12:]
            try:
                plaintext = decrypt_message(message_key, nonce, ciphertext)
                state.recv_count += 1
                show_message("Recv", state.recv_count, "Regular", plaintext)
            except Exception:
                # revert if failed
                state.recv_chain_key = recv_chain_key_before_step
                # silently continue as per your original style
            continue

        except ConnectionError:
            print("Connection closed.")
            break

# ====== Main Entry ======
async def main():
    reader, writer = await asyncio.open_connection(HOST, PORT)
    await handle_connection(reader, writer)

if __name__ == '__main__':
    asyncio.run(main())
    sys.exit(0)
