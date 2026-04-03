# Professional Cryptography System v2.0

A production-grade file encryption system implementing industry-standard cryptographic algorithms.

## Features

### Encryption Algorithms
- **AES-256-GCM**: Advanced Encryption Standard (NIST approved)
- **ChaCha20-Poly1305**: Modern high-speed cipher
- **Multi-Layer**: Multiple encryption layers for maximum security

### Key Derivation
- **PBKDF2-HMAC-SHA256**: 100,000 iterations
- **Argon2id**: Memory-hard function (recommended)

### Security Features
✓ Authenticated Encryption (AEAD)
✓ Integrity Verification (HMAC)
✓ Tamper Detection
✓ Secure Random Generation
✓ Wrong Password Detection

## Installation

```bash
pip install cryptography argon2-cffi
```

## Usage

### Command Line

```bash
# Encrypt a file
python professional_crypto.py -e myfile.py -o myfile.enc

# Decrypt a file
python professional_crypto.py -d myfile.enc -o myfile_decrypted.py

# Use ChaCha20 algorithm
python professional_crypto.py -e myfile.py -a chacha20

# Multi-layer encryption (3 layers)
python professional_crypto.py -e myfile.py -a multi-layer -l 3

# Use Argon2 key derivation
python professional_crypto.py -e myfile.py --no-argon2  # Disable Argon2, use PBKDF2
```

### Python API

```python
from professional_crypto import ProfessionalCrypto

crypto = ProfessionalCrypto()

# Encrypt
crypto.encrypt_file(
    input_path='myfile.py',
    output_path='myfile.enc',
    password='SecurePassword123!',
    algorithm='aes-gcm',  # or 'chacha20', 'multi-layer'
    layers=1,
    use_argon2=True
)

# Decrypt
crypto.decrypt_file(
    input_path='myfile.enc',
    output_path='myfile_decrypted.py',
    password='SecurePassword123!'
)
```

## Testing

Run the comprehensive test suite:

```bash
python test_crypto.py
```

Tests include:
- AES-256-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption
- Multi-layer encryption
- Argon2id key derivation
- Wrong password detection
- Data integrity & tamper detection

## Security Notes

1. **Password Strength**: Use strong, unique passwords (minimum 12 characters)
2. **Key Derivation**: Argon2id is recommended for maximum security
3. **Backup**: Always keep backups of important encrypted files
4. **Memory**: Multi-layer encryption uses more memory and time

## License

MIT License
