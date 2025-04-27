# ------------------------------------------------------
 # alice.py

# Proof-of-concept implementation of PQ double ratchet protocol using ML-KEM and AES-GCM.

# Code Writer: "Akash Angom" of National Institute of Technology Agartala


# ------------------------------------------------------

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
ROOT_KEY_HEX = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" # example root key
ROOT_KEY = binascii.unhexlify(ROOT_KEY_HEX)
CIPHER_IDENTIFIER = b"cipherkey" # identify arrival of encapsulated key
CIPHER_IDENTIFIEREK = b"ekcipherkey" # identify arrival of both encapsulated key and encapsulation key

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

# HKDF expand function to derive keys
def hkdf_expand(ikm, info, length=64):
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(ikm)

# Root key and chain key derivation

def derive_root_and_chain_key(root_key, shared_secret):
    output = hkdf_expand(root_key + shared_secret, b"hkdf1")
    return output[:32], output[32:]

# Sending or receiving chain key and message key derivation

def derive_chain_and_message_key(chain_key):
    output = hkdf_expand(chain_key, b"hkdf2")
    return output[:32], output[32:]


# message encryption using AESGCM
def encrypt_message(message_key, plaintext):
    aesgcm = AESGCM(message_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

# message decryption using AESGCM

def decrypt_message(message_key, nonce, ciphertext):
    aesgcm = AESGCM(message_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# to receive data based on exact lengths

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
    print("Alice: Connecting to Bob...")

    ek_a, dk_a = ML_KEM_KEYGEN()
    state = State(ROOT_KEY, ek_a, dk_a)
    state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, b"")

    # Send encapsulated key (ek_a) to Bob
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

        if state.ek_b is not None and state.send_chain_key is None:
            print("\n--- Alice: Rekeying before sending ---")
            shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_b))
            state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
           
            Mchain_key, message_key = derive_chain_and_message_key(state.send_chain_key)
            
            nonce, ciphertext = encrypt_message(message_key, user_input)
            payload = CIPHER_IDENTIFIER + nonce + ciphertext
            writer.write(len(payload).to_bytes(4, 'big') + payload)
            writer.write(len(bytes(encap)).to_bytes(4, 'big') + bytes(encap))
            await writer.drain()
            state.send_chain_key = Mchain_key
            state.send_count += 1
            print("---- Rekeyed ----")
            print(f"--- Alice's message {state.send_count} sent: {user_input} ---")
            continue
        else:

            send_chain_key_before_step = state.send_chain_key
            state.send_chain_key, message_key = derive_chain_and_message_key(state.send_chain_key) # Step first

            nonce, ciphertext = encrypt_message(message_key, user_input)
            writer.write(len(nonce + ciphertext).to_bytes(4, 'big') + nonce + ciphertext)
            await writer.drain()
            state.send_count += 1
            print(f"\n--- Alice's Message {state.send_count} sent: {user_input} ---")
            continue

# ====== Message Receiver ======
async def receive_messages(reader, state):
    while True:

        try:
            len_data = int.from_bytes(await recv_exact(reader, 4), 'big')
            data = await recv_exact(reader, len_data)

            if data.startswith(CIPHER_IDENTIFIEREK):

                print("\n--- Bob initiated rekey with EK ---")
                nonce = data[len(CIPHER_IDENTIFIEREK):len(CIPHER_IDENTIFIEREK) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIEREK) + 12:]

                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                len_ekb = int.from_bytes(await recv_exact(reader, 4), 'big')
                ek_b = await recv_exact(reader, len_ekb)
                state.ek_b = ek_b
                state.send_chain_key = None
                print("Alice: Decapsulating and new receiving chain starts")

                shared_secret = ML_KEM_DECAPS(state.dk_a, list(encap))

                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                Mchain_key, message_key = derive_chain_and_message_key(state.recv_chain_key)
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = Mchain_key
                state.recv_count += 1
                state.received_ekb_flag = True
                print(f"\n--- Bob's Message {state.recv_count}: {plaintext}")
                continue

            elif data.startswith(CIPHER_IDENTIFIER):
                print("\n--- Bob initiated rekey cipher only ---")
                nonce = data[len(CIPHER_IDENTIFIER):len(CIPHER_IDENTIFIER) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIER) + 12:]

                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                state.send_chain_key = None
                print("Alice: Decapsulating and new receiving chain starts")

                shared_secret = ML_KEM_DECAPS(state.dk_a, list(encap))
                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                Mchain_key, message_key = derive_chain_and_message_key(state.recv_chain_key)
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = Mchain_key
                state.recv_count += 1
                print(f"\n--- Bob's Message {state.recv_count}: {plaintext}")
                continue

            else:

                recv_chain_key_before_step = state.recv_chain_key
                state.recv_chain_key, message_key = derive_chain_and_message_key(state.recv_chain_key) 
                nonce = data[:12]
                ciphertext = data[12:]
                try:
                    plaintext = decrypt_message(message_key, nonce, ciphertext)
    
                    state.recv_count += 1
                    state.received_ekb_flag = True
                    print(f"\n--- Bob's Message {state.recv_count}: {plaintext}")
                    continue
                except Exception as e:
                    print(f"Alice: Error decrypting regular message: {e}")
                    state.recv_chain_key = recv_chain_key_before_step
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