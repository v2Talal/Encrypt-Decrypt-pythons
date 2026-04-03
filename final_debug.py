from professional_crypto import ProfessionalCrypto, ColorCodes
import json
import base64

crypto = ProfessionalCrypto()
password = 'Test123!'
input_file = '/workspace/test_sample.py'
enc_file = '/workspace/final_test.enc'
dec_file = '/workspace/final_test_dec.py'

# Encrypt
print(f"{ColorCodes.CYAN}=== ENCRYPTING ==={ColorCodes.RESET}")
result = crypto.encrypt_file(input_file, enc_file, password, algorithm='aes-gcm', use_argon2=False)
print(f"✓ Encrypted successfully")

# Load encrypted file  
with open(enc_file, 'r') as f:
    data = json.load(f)

metadata = data['metadata']
print(f"\nMetadata from file:")
for k, v in metadata.items():
    if k == 'salt':
        print(f"  {k}: {v[:30]}...")
    else:
        print(f"  {k}: {v}")

# Manually reconstruct what decrypt_file does
print(f"\n{ColorCodes.CYAN}=== DECRYPTION ANALYSIS ==={ColorCodes.RESET}")

# Get salt
salt = base64.b64decode(metadata['salt'])
print(f"Salt decoded: {len(salt)} bytes")

# Derive key
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
print(f"Key derived: {key.hex()[:32]}...")

# Get nonce, ciphertext, tag
nonce = base64.b64decode(data['nonce'])
ciphertext = base64.b64decode(data['ciphertext'])
tag = base64.b64decode(data['tag'])
print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext: {len(ciphertext)} bytes")
print(f"Tag: {tag.hex()}")

# Reconstruct associated data EXACTLY as decrypt_file does
assoc_metadata = {k: v for k, v in metadata.items() if k != 'salt'}
associated_data = json.dumps(assoc_metadata, sort_keys=True).encode('utf-8')
print(f"\nAssociated Data (for decryption):")
print(f"  {associated_data}")

# What was used during encryption?
# The encrypt_file creates metadata_for_ad WITHOUT salt, then adds salt to create full metadata
# So the AD used in encryption should match assoc_metadata exactly
print(f"\nExpected AD structure (no salt):")
expected_keys = sorted(['algorithm', 'original_size', 'timestamp', 'version', 'filename', 'kdf'])
actual_keys = sorted(assoc_metadata.keys())
print(f"  Expected keys: {expected_keys}")
print(f"  Actual keys:   {actual_keys}")
print(f"  Match: {expected_keys == actual_keys}")

# Try decryption manually
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = AESGCM(key)

print(f"\n{ColorCodes.CYAN}=== ATTEMPTING DECRYPTION ==={ColorCodes.RESET}")
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
    print(f"✓ SUCCESS! Decrypted {len(plaintext)} bytes")
except Exception as e:
    print(f"✗ FAILED: {type(e).__name__}: {e}")
    
    # Check if maybe the timestamp is different between encrypt and stored metadata
    print("\nChecking timestamp consistency...")
    print(f"Timestamp in metadata: {metadata.get('timestamp')}")
    
    # Let's try with empty AD
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, b'')
        print("✓ Works with empty AD - AD mismatch confirmed!")
    except:
        print("✗ Also fails with empty AD")
