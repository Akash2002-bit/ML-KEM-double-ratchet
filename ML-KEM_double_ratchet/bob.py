# ------------------------------------------------------

# bob.py

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
    print("Bob: waiting for Alice's initial messages...")

    ek_b, dk_b = ML_KEM_KEYGEN()
    state = State(ROOT_KEY, ek_b, dk_b)
    state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, b"")

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

        if state.received_eka_flag and not state.send_chain_key:
            if not state.first_rekey_done:
                print("\n--- Bob: Rekey with ek and cipher ---")
                shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_a))
             
                state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
                

                Mchain_key, message_key = derive_chain_and_message_key(state.send_chain_key)
                nonce, ciphertext = encrypt_message(message_key, user_input)
                payload = CIPHER_IDENTIFIEREK + nonce + ciphertext
                writer.write(len(payload).to_bytes(4, 'big') + payload)
                writer.write(len(bytes(encap)).to_bytes(4, 'big') + bytes(encap))
                writer.write(len(bytes(state.ek_b)).to_bytes(4, 'big') + bytes(state.ek_b))
                await writer.drain()
                state.send_chain_key = Mchain_key # Step after sending
                state.send_count += 1
                state.first_rekey_done = True
                print(f"--- Bob's message {state.send_count} sent: {user_input} ---")
                pass
            else:
                print("\n--- Bob: Rekey only cipher ---")
                print(f"Bob: Sending rekey cipher")
                shared_secret, encap = ML_KEM_ENCAPS(list(state.ek_a))
                state.root_key, state.send_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))
               
                Mchain_key, message_key = derive_chain_and_message_key(state.send_chain_key)
            
                nonce, ciphertext = encrypt_message(message_key, user_input)
                payload = CIPHER_IDENTIFIER + nonce + ciphertext
                writer.write(len(payload).to_bytes(4, 'big') + payload)
                writer.write(len(bytes(encap)).to_bytes(4, 'big') + bytes(encap))
                await writer.drain()
                state.send_chain_key = Mchain_key # Step after sending
                state.send_count += 1
                print(f"--- Bob's message {state.send_count} sent: {user_input} ---")
                continue
        else:
            
            message_chain_key, message_key = derive_chain_and_message_key(state.send_chain_key) # Derive first
            
            nonce, ciphertext = encrypt_message(message_key, user_input)
            writer.write(len(nonce + ciphertext).to_bytes(4, 'big') + nonce + ciphertext)
            await writer.drain()
            state.send_chain_key = message_chain_key # Step after sending
            state.send_count += 1
            print(f"\n--- Bob's Message {state.send_count} sent: {user_input} ---")
            continue

# ====== Message Receiver ======
async def receive_messages(reader, state):
    while True:
        try:
            len_data = int.from_bytes(await recv_exact(reader, 4), 'big')
            data = await recv_exact(reader, len_data)
            

            if data.startswith(CIPHER_IDENTIFIER):
                print("\n--- Bob: Received rekey cipher ---")
                nonce = data[len(CIPHER_IDENTIFIER):len(CIPHER_IDENTIFIER) + 12]
                ciphertext = data[len(CIPHER_IDENTIFIER) + 12:]

                len_encap = int.from_bytes(await recv_exact(reader, 4), 'big')
                encap = await recv_exact(reader, len_encap)

                state.send_chain_key = None
                print("Bob: Decapsulating and new receiving chain starts")

                shared_secret = ML_KEM_DECAPS(state.dk_b, list(encap))
                
                state.root_key, state.recv_chain_key = derive_root_and_chain_key(state.root_key, bytes(shared_secret))

                Mchain_key, message_key = derive_chain_and_message_key(state.recv_chain_key)
                
                plaintext = decrypt_message(message_key, nonce, ciphertext)

                state.recv_chain_key = Mchain_key
                state.recv_count += 1
                state.received_eka_flag = True
                print(f"\n--- Alice's Message {state.recv_count}: {plaintext}")
                continue

            # Regular message
            nonce, ciphertext = data[:12], data[12:]
           
            recv_chain_key_before_step = state.recv_chain_key
            state.recv_chain_key, message_key = derive_chain_and_message_key(state.recv_chain_key) # Step first
           
            try:
                plaintext = decrypt_message(message_key, nonce, ciphertext)
                
                state.recv_count += 1
                print(f"\nAlice's Message {state.recv_count}: {plaintext}")
                state.received_since_last_send = True
            except Exception as e:
                print(f"Bob: Error decrypting regular message: {e}")
                state.recv_chain_key = recv_chain_key_before_step # Revert on error
            continue

        except ConnectionError:
            print("Connection closed.")
            break

# ====== Main Entry ======
async def main():
    server = await asyncio.start_server(handle_connection, HOST, PORT)
    print(f'Bob listening on {HOST}:{PORT}')
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        print('Server shutdown.')
        server.close()
        await server.wait_closed()
        sys.exit(0)

if __name__ == '__main__':
    asyncio.run(main())