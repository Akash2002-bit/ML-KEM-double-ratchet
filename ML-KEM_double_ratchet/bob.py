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
    def __init__(self, root_key, ek_b, dk_b, ek_a=None):
        self.root_key = root_key
        self.send_chain_key = None
        self.recv_chain_key = None
        self.ek_b = ek_b
        self.dk_b = dk_b
        self.ek_a = ek_a
        self.received_eka_flag = False
        self.send_count = 0
        self.recv_count = 0
        self.first_rekey_done = False

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
    print(f'Bob listening on {HOST}:{PORT}')
    ek_b, dk_b = ML_KEM_KEYGEN()
    state = State(ROOT_KEY, ek_b, dk_b)
    # initial root -> recv chain (empty shared secret)
    state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, b"")

    # Receive Alice's EK_a first
    len_ek_a = int.from_bytes(await recv_exact(reader, 4), 'big')
    ek_a = await recv_exact(reader, len_ek_a)
    state.ek_a = ek_a
    state.received_eka_flag = True
    print("Bob: Received Alice's Public Key.")

    recv_task = asyncio.create_task(receive_messages(reader, state))
    await handle_user_input(writer, state)
    await recv_task

# ====== Input Sender ======
async def handle_user_input(writer, state):
    while True:
        user_input = await asyncio.to_thread(input, "\nSend message to Alice: ")
        if not user_input:
            continue

        # First send after receiving EK_a: EK + Cipher Rekey (and include EK_b)
        if state.received_eka_flag and not state.first_rekey_done and state.send_chain_key is None:
            shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_a))
            state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
            next_chain, message_key = derive_chain_and_message_key(state.send_chain_key)

            nonce, ciphertext = encrypt_message(message_key, user_input)

            # send: len(prefix+nonce+ciphertext)|payload ; len(encap)|encap ; len(ek_b)|ek_b
            payload = CIPHER_IDENTIFIEREK + nonce + ciphertext
            writer.write(len(payload).to_bytes(4, 'big') + payload)

            encap_bytes = bytes(encap)
            writer.write(len(encap_bytes).to_bytes(4, 'big') + encap_bytes)

            ek_b_bytes = bytes(state.ek_b)
            writer.write(len(ek_b_bytes).to_bytes(4, 'big') + ek_b_bytes)

            await writer.drain()

            state.send_chain_key = next_chain
            state.send_count += 1
            state.first_rekey_done = True
            show_message("Send", state.send_count, "EK + Cipher Rekey", user_input)
            continue

        # Later: cipher-only rekey (no ek_b)
        if state.first_rekey_done and state.send_chain_key is None:
            shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_a))
            state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
            next_chain, message_key = derive_chain_and_message_key(state.send_chain_key)

            nonce, ciphertext = encrypt_message(message_key, user_input)
            payload = CIPHER_IDENTIFIER + nonce + ciphertext
            writer.write(len(payload).to_bytes(4, 'big') + payload)

            encap_bytes = bytes(encap)
            writer.write(len(encap_bytes).to_bytes(4, 'big') + encap_bytes)

            await writer.drain()

            state.send_chain_key = next_chain
            state.send_count += 1
            show_message("Send", state.send_count, "Cipher-only Rekey", user_input)
            continue

        # Regular chained message
        next_chain, message_key = derive_chain_and_message_key(state.send_chain_key)
        nonce, ciphertext = encrypt_message(message_key, user_input)
        writer.write(len(nonce + ciphertext).to_bytes(4, 'big') + nonce + ciphertext)
        await writer.drain()

        state.send_chain_key = next_chain
        state.send_count += 1
        show_message("Send", state.send_count, "Regular", user_input)

# ====== Message Receiver ======
async def receive_messages(reader, state):
    while True:
        try:
            len_data = int.from_bytes(await recv_exact(reader, 4), 'big')
            data = await recv_exact(reader, len_data)

            # Alice sent cipher-only rekey
            if data.startswith(CIPHER_IDENTIFIER):
                nonce = data[len(CIPHER_IDENTIFIER):len(CIPHER_IDENTIFIER) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIER) + 12:]

                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                # reset our send chain; we must rekey on next send
                state.send_chain_key = None

                shared_secret = ML_KEM_DECAPS(state.dk_b, list(encap))
                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                next_chain, message_key = derive_chain_and_message_key(state.recv_chain_key)
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = next_chain
                state.recv_count += 1
                show_message("Recv", state.recv_count, "Cipher-only Rekey", plaintext)
                continue

            # Regular chained message
            nonce, ciphertext = data[:12], data[12:]
            prev_chain = state.recv_chain_key
            state.recv_chain_key, message_key = derive_chain_and_message_key(state.recv_chain_key)
            try:
                plaintext = decrypt_message(message_key, nonce, ciphertext)
                state.recv_count += 1
                show_message("Recv", state.recv_count, "Regular", plaintext)
            except Exception:
                state.recv_chain_key = prev_chain
            continue

        except ConnectionError:
            print("Connection closed.")
            break

# ====== Main Entry ======
async def main():
    server = await asyncio.start_server(handle_connection, HOST, PORT)
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        server.close()
        await server.wait_closed()
        sys.exit(0)

if __name__ == '__main__':
    asyncio.run(main())
