import unittest
import os
import blind_signature_ascon as bsa

class TestBlindSignatureAscon(unittest.TestCase):

    def test_blind_signature_ascon(self):
        # Generate signing and encryption keys
        sk, vk = bsa.generate_key_pair()
        encryption_key = os.urandom(32)

        # Generate a financial transaction message
        transaction = "Alice sends 100 to Bob"
        transaction_hash = int.from_bytes(bsa.sha256(transaction.encode()).digest(), byteorder='big')

        # Generate a blinding factor
        blinding_factor = os.urandom(32)
        blinding_factor = int.from_bytes(blinding_factor, byteorder='big')

        # Blind the transaction hash
        blind_transaction_hash = bsa.blind_message(transaction_hash, blinding_factor, vk)

        # Encrypt the blind transaction hash
        nonce, ciphertext = bsa.encrypt(str(blind_transaction_hash).encode(), encryption_key)

        # Decrypt the blind transaction hash
        blind_transaction_hash_dec = int(bsa.decrypt(ciphertext, encryption_key, nonce))

        self.assertEqual(blind_transaction_hash, blind_transaction_hash_dec, "Decrypted blind transaction hash does not match the original value")

        # Create a blind signature
        blind_signature = sk.sign(str(blind_transaction_hash_dec).encode(), encoder=bsa.RawEncoder)

        # Unblind the signature
        signature = bsa.unblind_signature(int.from_bytes(blind_signature, byteorder='big'), blinding_factor, vk)

        # Verify the signature
        is_valid = vk.verify(signature.to_bytes(64, byteorder='big'), str(transaction_hash).encode(), encoder=bsa.RawEncoder)
        self.assertIsNotNone(is_valid, "Signature is invalid")

if __name__ == "__main__":
    unittest.main()
