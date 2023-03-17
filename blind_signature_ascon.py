import os
from hashlib import sha256
import nacl.signing
from nacl.encoding import RawEncoder
from ascon import Ascon128

def generate_key_pair():
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    return sk, vk

def encrypt(plaintext, key):
    ascon = Ascon128(key)
    nonce = os.urandom(16)
    ciphertext = ascon.encrypt(nonce, plaintext, b'')
    return nonce, ciphertext

def decrypt(ciphertext, key, nonce):
    ascon = Ascon128(key)
    plaintext = ascon.decrypt(nonce, ciphertext, b'')
    return plaintext

def blind_message(message, blinding_factor, vk):
    curve_order = 1_267_650_600_228_229_401_496_703_205_376  # Ed25519 curve order
    blind_message = (message * blinding_factor) % curve_order
    return blind_message

def unblind_signature(blind_signature, blinding_factor, vk):
    curve_order = 1_267_650_600_228_229_401_496_703_205_376  # Ed25519 curve order
    unblind_signature = (blind_signature * pow(blinding_factor, -1, curve_order)) % curve_order
    return unblind_signature

try:
    # Generate signing and encryption keys
    sk, vk = generate_key_pair()
    encryption_key = os.urandom(32)

    # Generate a financial transaction message
    transaction = "Alice sends 100 to Bob"
    transaction_hash = int.from_bytes(sha256(transaction.encode()).digest(), byteorder='big')

    # Generate a blinding factor
    blinding_factor = os.urandom(32)
    blinding_factor = int.from_bytes(blinding_factor, byteorder='big')

    # Blind the transaction hash
    blind_transaction_hash = blind_message(transaction_hash, blinding_factor, vk)

    # Encrypt the blind transaction hash
    nonce, ciphertext = encrypt(str(blind_transaction_hash).encode(), encryption_key)

    # Decrypt the blind transaction hash
    blind_transaction_hash_dec = int(decrypt(ciphertext, encryption_key, nonce))

    # Check if decrypted value matches original blind transaction hash
    if blind_transaction_hash_dec != blind_transaction_hash:
        raise ValueError("Decrypted blind transaction hash does not match the original value")

    # Create a blind signature
    blind_signature = sk.sign(str(blind_transaction_hash_dec).encode(), encoder=RawEncoder)

    # Unblind the signature
    signature = unblind_signature(int.from_bytes(blind_signature, byteorder='big'), blinding_factor, vk)

    # Verify the signature
    vk.verify(signature.to_bytes(64, byteorder='big'), str(transaction_hash).encode(), encoder=RawEncoder)
    print("Signature is valid")

except ValueError as ve:
    print(f"Value error occurred: {ve}")
except Exception as e:
    print(f"An error occurred: {e}")
