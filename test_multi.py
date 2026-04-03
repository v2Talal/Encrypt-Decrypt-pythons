from professional_crypto import ProfessionalCrypto

crypto = ProfessionalCrypto()
password = "MultiLayer789!"
input_file = "/workspace/test_sample.py"
enc_file = "/workspace/multi_test.enc"
dec_file = "/workspace/multi_test_dec.py"

# Encrypt with 3 layers
print("Encrypting with 3 layers...")
result = crypto.encrypt_file(input_file, enc_file, password, algorithm='multi-layer', layers=3, use_argon2=False)
print(f"✓ Encrypted: {result['algorithm']}")
print(f"  Size: {result['original_size']} -> {result['encrypted_size']} bytes")

# Load and inspect
import json
with open(enc_file, 'r') as f:
    data = json.load(f)

print(f"\nMetadata:")
print(f"  Layers: {data['metadata'].get('layers')}")
print(f"  Layer keys: {len(data['metadata'].get('layer_keys', []))}")

# Decrypt
print("\nDecrypting...")
try:
    dec_result = crypto.decrypt_file(enc_file, dec_file, password)
    print(f"✓ Decrypted successfully!")
    
    # Verify
    with open(input_file, 'rb') as f:
        orig = f.read()
    with open(dec_file, 'rb') as f:
        dec = f.read()
    
    if orig == dec:
        print("✓ Content matches original!")
    else:
        print(f"✗ Content mismatch! orig={len(orig)} dec={len(dec)}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
