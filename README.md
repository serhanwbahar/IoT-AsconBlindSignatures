# IoT-AsconBlindSignatures

This repository contains an implementation of blind signatures using the Ascon-128 cryptographic algorithm for encryption and Ed25519 signatures. Ascon-128 is a lightweight encryption algorithm suitable for IoT devices with limited CPU and RAM resources. NIST has standardized Ascon cryptographic algorithms for IoT and other lightweight devices.

Please note that this is an experimental repo and has not been audited. Use at your own risk.

## Features

* Ascon-128 encryption
* Ed25519 blind signatures
* Secure and efficient implementation for resource-limited devices

## Installation

To use this implementation, you need to have Python 3.x installed. You can install the required dependencies using the following command:
```
pip install -r requirements.txt
```

## Usage

```
import blind_signature_ascon as bsa

# Generate signing and encryption keys
sk, vk = bsa.generate_key_pair()
encryption_key = os.urandom(32)

# Create a financial transaction message
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

# Create a blind signature
blind_signature = sk.sign(str(blind_transaction_hash_dec).encode(), encoder=bsa.RawEncoder)

# Unblind the signature
signature = bsa.unblind_signature(int.from_bytes(blind_signature, byteorder='big'), blinding_factor, vk)

# Verify the signature
vk.verify(signature.to_bytes(64, byteorder='big'), str(transaction_hash).encode(), encoder=bsa.RawEncoder)
```

# Testing

To run the tests, execute the following command:

```
python -m unittest test_blind_signature_ascon.py
```

# License

This implementation is released under the MIT License. See the [LICENSE](./LICENSE) file for details.
