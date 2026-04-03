import json
import base64
from professional_crypto import ProfessionalCrypto

crypto = ProfessionalCrypto()
password = "Test123!"
input_file = "/workspace/test_sample.py"
encrypted_file = "/workspace/debug_encrypted.enc"

# Encrypt
print("=== ENCRYPTION ===")
result = crypto.encrypt_file(input_file, encrypted_file, password, algorithm='aes-gcm', use_argon2=False)
print(f"✓ Encrypted: {result['original_size']} -> {result['encrypted_size']} bytes")

# Load encrypted file
with open(encrypted_file, 'r') as f:
    enc_data = json.load(f)

metadata = enc_data['metadata']
salt = base64.b64decode(metadata['salt'])
nonce = base64.b64decode(enc_data['nonce'])
ciphertext_bin = base64.b64decode(enc_data['ciphertext'])
tag = base64.b64decode(enc_data['tag'])

print(f"\nSalt: {salt.hex()[:32]}...")
print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext ({len(ciphertext_bin)} bytes): {ciphertext_bin.hex()[:64]}...")
print(f"Tag: {tag.hex()}")

# Derive key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password.encode('utf-8'))

# Reconstruct associated data EXACTLY as done in decryption
assoc_metadata = {k: v for k, v in metadata.items() if k != 'salt'}
associated_data = json.dumps(assoc_metadata).encode('utf-8')

print(f"\nAssociated Data: {associated_data}")

# Try to decrypt
aesgcm = AESGCM(key)
full_ct = ciphertext_bin + tag

print(f"\nAttempting decryption...")
print(f"Full ciphertext length: {len(full_ct)} (ct={len(ciphertext_bin)} + tag={len(tag)})")

try:
    plaintext = aesgcm.decrypt(nonce, full_ct, associated_data)
    print(f"✓ SUCCESS! Decrypted {len(plaintext)} bytes")
except Exception as e:
    print(f"✗ FAILED: {type(e).__name__}: {e}")
    
    # Check if timestamps differ
    print("\nDebug: Checking timestamp mismatch...")
    import re
    ts_pattern = r'"timestamp": "([^"]+)"'
    enc_ts = re.search(ts_pattern, associated_data.decode())
    print(f"Timestamp in AD: {enc_ts.group(1) if enc_ts else 'NOT FOUND'}")
    
    # Try with empty AD
    try:
        plaintext = aesgcm.decrypt(nonce, full_ct, b'')
        print("✓ Works with empty AD - timestamp mismatch suspected!")
    except:
        print("✗ Also fails with empty AD")
