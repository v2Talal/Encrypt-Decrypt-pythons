import json
import base64
from professional_crypto import ProfessionalCrypto

crypto = ProfessionalCrypto()
password = "Test123!"
input_file = "/workspace/test_sample.py"
encrypted_file = "/workspace/debug_encrypted.enc"

# Encrypt and capture the exact associated data used
print("=== ENCRYPTION ===")

# Read input
with open(input_file, 'rb') as f:
    plaintext = f.read()

import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

salt = secrets.token_bytes(32)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password.encode('utf-8'))

algorithm = 'aes-gcm'
original_size = len(plaintext)
filename = 'test_sample.py'
kdf_method = 'pbkdf2'

# Create metadata EXACTLY as encrypt_file does
metadata_for_ad = {
    'algorithm': algorithm,
    'original_size': original_size,
    'timestamp': datetime.now().isoformat(),
    'version': '2.0.0',
    'filename': filename,
    'kdf': kdf_method
}

associated_data_encrypt = json.dumps(metadata_for_ad, sort_keys=True).encode('utf-8')
print(f"AD (encrypt): {associated_data_encrypt}")

# Encrypt
aesgcm = AESGCM(key)
nonce = secrets.token_bytes(12)
ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data_encrypt)
ciphertext = ciphertext_with_tag[:-16]
tag = ciphertext_with_tag[-16:]

print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext: {len(ciphertext)} bytes")
print(f"Tag: {tag.hex()}")

# Save to file
metadata = dict(metadata_for_ad)
metadata['salt'] = base64.b64encode(salt).decode('utf-8')

enc_data = {
    'algorithm': 'AES-256-GCM',
    'metadata': metadata,
    'nonce': base64.b64encode(nonce).decode('utf-8'),
    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
    'tag': base64.b64encode(tag).decode('utf-8'),
    'integrity': 'dummy'
}

with open(encrypted_file, 'w') as f:
    json.dump(enc_data, f, indent=2)

print("\n=== DECRYPTION ===")

# Load and decrypt
with open(encrypted_file, 'r') as f:
    loaded_data = json.load(f)

loaded_metadata = loaded_data['metadata']
print(f"Loaded metadata: {json.dumps(loaded_metadata, indent=2)}")

# Reconstruct AD exactly as decrypt_file does
assoc_metadata = {k: v for k, v in loaded_metadata.items() if k != 'salt'}
associated_data_decrypt = json.dumps(assoc_metadata, sort_keys=True).encode('utf-8')
print(f"\nAD (decrypt): {associated_data_decrypt}")

print(f"\nADs match: {associated_data_encrypt == associated_data_decrypt}")

# Try decryption
nonce_loaded = base64.b64decode(loaded_data['nonce'])
ct_loaded = base64.b64decode(loaded_data['ciphertext'])
tag_loaded = base64.b64decode(loaded_data['tag'])

try:
    pt = aesgcm.decrypt(nonce_loaded, ct_loaded + tag_loaded, associated_data_decrypt)
    print(f"\n✓ SUCCESS! Decrypted {len(pt)} bytes")
except Exception as e:
    print(f"\n✗ FAILED: {e}")
    
    # Show byte-by-byte comparison
    print("\nByte comparison:")
    print(f"Encrypt AD length: {len(associated_data_encrypt)}")
    print(f"Decrypt AD length: {len(associated_data_decrypt)}")
    
    for i, (a, b) in enumerate(zip(associated_data_encrypt, associated_data_decrypt)):
        if a != b:
            print(f"  Diff at byte {i}: encrypt={a} ({chr(a)}) vs decrypt={b} ({chr(b)})")
