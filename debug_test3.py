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
print(f"\nMetadata from file: {json.dumps(metadata, indent=2)}")

salt = base64.b64decode(metadata['salt'])
nonce = base64.b64decode(enc_data['nonce'])
ciphertext_bin = base64.b64decode(enc_data['ciphertext'])
tag = base64.b64decode(enc_data['tag'])

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
associated_data_decrypt = json.dumps(assoc_metadata).encode('utf-8')
print(f"\nAD used in DECRYPTION: {associated_data_decrypt}")

# What was used in encryption?
metadata_for_ad = dict(assoc_metadata)  # Same structure
associated_data_encrypt = json.dumps(metadata_for_ad).encode('utf-8')
print(f"AD used in ENCRYPTION: {associated_data_encrypt}")

# Are they the same?
print(f"\nAre ADs identical? {associated_data_encrypt == associated_data_decrypt}")

# Try to decrypt
aesgcm = AESGCM(key)
full_ct = ciphertext_bin + tag

try:
    plaintext = aesgcm.decrypt(nonce, full_ct, associated_data_decrypt)
    print(f"\n✓ SUCCESS! Decrypted {len(plaintext)} bytes")
    print(f"First line: {plaintext.decode()[:50]}...")
except Exception as e:
    print(f"\n✗ FAILED: {type(e).__name__}: {e}")
    
    # The problem is likely timestamp - let's try encrypting with fixed metadata
    print("\n\n=== TRYING WITH FIXED TIMESTAMP ===")
    # Re-encrypt but capture the exact AD used
    import time
    fixed_ts = "2024-01-01T00:00:00.000000"
    
    # Manually do what encrypt_file does
    import os
    import secrets
    
    plaintext_orig = open(input_file, 'rb').read()
    salt_new = secrets.token_bytes(32)
    
    kdf_new = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_new,
        iterations=100000,
        backend=default_backend()
    )
    key_new = kdf_new.derive(password.encode('utf-8'))
    
    # Create metadata WITHOUT timestamp variation
    metadata_fixed = {
        'algorithm': 'aes-gcm',
        'original_size': len(plaintext_orig),
        'timestamp': fixed_ts,
        'version': '2.0.0',
        'filename': 'test_sample.py',
        'kdf': 'pbkdf2'
    }
    
    ad_fixed = json.dumps(metadata_fixed).encode('utf-8')
    print(f"Fixed AD: {ad_fixed}")
    
    nonce_new = secrets.token_bytes(12)
    aesgcm_new = AESGCM(key_new)
    ct_new = aesgcm_new.encrypt(nonce_new, plaintext_orig, ad_fixed)
    
    ct_bin = ct_new[:-16]
    tag_new = ct_new[-16:]
    
    print(f"Encrypted with fixed AD")
    
    # Now try to decrypt
    try:
        pt_new = aesgcm_new.decrypt(nonce_new, ct_new, ad_fixed)
        print(f"✓ Fixed test SUCCESS! {len(pt_new)} bytes")
    except Exception as e2:
        print(f"✗ Fixed test FAILED: {e2}")
