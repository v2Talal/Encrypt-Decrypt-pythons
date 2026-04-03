import json
import base64
from professional_crypto import ProfessionalCrypto

crypto = ProfessionalCrypto()
password = "Test123!"
input_file = "/workspace/test_sample.py"
encrypted_file = "/workspace/debug_encrypted.enc"

# Encrypt
result = crypto.encrypt_file(input_file, encrypted_file, password, algorithm='aes-gcm', use_argon2=False)
print("Encryption successful!")
print(f"Result: {json.dumps(result, indent=2)}")

# Load and inspect encrypted file
with open(encrypted_file, 'r') as f:
    enc_data = json.load(f)

print("\nEncrypted file structure:")
print(f"Algorithm: {enc_data['algorithm']}")
print(f"Metadata keys: {list(enc_data['metadata'].keys())}")
print(f"Metadata (without salt): { {k:v for k,v in enc_data['metadata'].items() if k != 'salt'} }")

# Try to reconstruct associated data
metadata = enc_data['metadata']
assoc_metadata = {k: v for k, v in metadata.items() if k != 'salt'}
associated_data = json.dumps(assoc_metadata).encode('utf-8')
print(f"\nAssociated data used in decryption: {associated_data[:100]}...")

# Now check what was actually authenticated
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

salt = base64.b64decode(metadata['salt'])
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password.encode('utf-8'))
print(f"\nDerived key (hex): {key.hex()[:32]}...")

nonce = base64.b64decode(enc_data['nonce'])
ciphertext = base64.b64decode(enc_data['ciphertext'])
tag = base64.b64decode(enc_data['tag'])

print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext length: {len(ciphertext)}")
print(f"Tag: {tag.hex()}")

# Try decryption with the exact associated data
aesgcm = AESGCM(key)
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
    print(f"\n✓ Decryption successful!")
    print(f"Plaintext length: {len(plaintext)}")
except Exception as e:
    print(f"\n✗ Decryption failed: {e}")
    
    # Try without associated data
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, b'')
        print(f"✓ Decryption successful WITHOUT associated data!")
    except Exception as e2:
        print(f"✗ Also failed without AD: {e2}")
