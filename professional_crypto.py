"""
Professional Cryptography System for Python Files
==================================================
A production-grade encryption system implementing multiple
industry-standard cryptographic algorithms.

Features:
---------
- AES-256-GCM (Advanced Encryption Standard)
- ChaCha20-Poly1305 (Modern Stream Cipher)
- RSA-4096 (Asymmetric Key Management)
- PBKDF2/Argon2 Key Derivation
- HMAC Authentication
- Multi-layer Encryption Support
- Integrity Verification
- Secure Key Management

Author: Professional Crypto System
Version: 2.0.0
License: MIT
"""

import sys
import os
import base64
import hashlib
import hmac
import secrets
import json
import argparse
import getpass
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

# Try to import cryptography library
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: 'cryptography' library not found.")
    print("Install it with: pip install cryptography")

# Try to import argon2 for enhanced key derivation
try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class ColorCodes:
    """ANSI Color Codes for Terminal Output"""
    BLACK = '\033[90m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'


class CryptoError(Exception):
    """Custom Exception for Cryptography Operations"""
    pass


class ProfessionalCrypto:
    """
    Professional Cryptography Class

    Implements multiple encryption algorithms with proper key management,
    authentication, and integrity verification.
    """

    # Constants
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12  # 96 bits
    CHACHA_KEY_SIZE = 32
    CHACHA_NONCE_SIZE = 12
    SALT_SIZE = 32
    TAG_SIZE = 16
    PBKDF2_ITERATIONS = 114621
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536
    ARGON2_PARALLELISM = 4

    def __init__(self, password: Optional[str] = None, key_file: Optional[str] = None):
        """
        Initialize the cryptography system

        Args:
            password: Master password for key derivation
            key_file: Path to key file (alternative to password)
        """
        if not CRYPTO_AVAILABLE:
            raise CryptoError("Cryptography library not available. Install with: pip install cryptography")

        self.password = password
        self.key_file = key_file
        self.master_key = None
        self.salt = None

    def derive_key(self, password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
        """
        Derive a cryptographic key from password using PBKDF2-HMAC-SHA256

        Args:
            password: User password
            salt: Random salt
            iterations: Number of iterations (higher = more secure but slower)

        Returns:
            Derived key (32 bytes)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def derive_key_argon2(self, password: str, salt: bytes) -> bytes:
        """
        Derive key using Argon2id (recommended for maximum security)

        Args:
            password: User password
            salt: Random salt

        Returns:
            Derived key (32 bytes)
        """
        if not ARGON2_AVAILABLE:
            return self.derive_key(password, salt)

        ph = argon2.PasswordHasher(
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.AES_KEY_SIZE,
            type=argon2.Type.ID
        )

        # Argon2 expects specific format, we'll use raw derivation
        from argon2.low_level import hash_secret_raw
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.AES_KEY_SIZE,
            type=argon2.Type.ID
        )

    def generate_key_pair(self, key_size: int = 4096) -> Tuple:
        """
        Generate RSA key pair for asymmetric encryption

        Args:
            key_size: Key size in bits (2048, 3072, or 4096)

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_key_pair(self, private_key, public_key, password: str,
                      private_path: str = 'private_key.pem',
                      public_path: str = 'public_key.pem'):
        """
        Save RSA key pair to files

        Args:
            private_key: RSA private key object
            public_key: RSA public key object
            password: Password to encrypt private key
            private_path: Path to save private key
            public_path: Path to save public key
        """
        # Serialize private key with password protection
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(private_path, 'wb') as f:
            f.write(private_pem)

        with open(public_path, 'wb') as f:
            f.write(public_pem)

        return private_path, public_path

    def load_private_key(self, path: str, password: str):
        """Load RSA private key from file"""
        with open(path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode(),
                backend=default_backend()
            )
        return private_key

    def load_public_key(self, path: str):
        """Load RSA public key from file"""
        with open(path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key

    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, associated_data: bytes = b'') -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM

        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            associated_data: Additional authenticated data (optional)

        Returns:
            Dictionary containing nonce, ciphertext, and tag
        """
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(self.AES_NONCE_SIZE)

        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        # Split ciphertext and tag (tag is last 16 bytes)
        actual_ciphertext = ciphertext[:-self.TAG_SIZE]
        tag = ciphertext[-self.TAG_SIZE:]

        return {
            'nonce': nonce,
            'ciphertext': actual_ciphertext,
            'tag': tag,
            'associated_data': associated_data
        }

    def decrypt_aes_gcm(self, encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM

        Args:
            encrypted_data: Dictionary with nonce, ciphertext, and tag
            key: 32-byte decryption key

        Returns:
            Decrypted plaintext
        """
        aesgcm = AESGCM(key)

        # Reconstruct full ciphertext (ciphertext + tag)
        full_ciphertext = encrypted_data['ciphertext'] + encrypted_data['tag']

        try:
            plaintext = aesgcm.decrypt(
                encrypted_data['nonce'],
                full_ciphertext,
                encrypted_data.get('associated_data', b'')
            )
            return plaintext
        except InvalidTag:
            raise CryptoError("Authentication failed! Data may be corrupted or tampered.")

    def encrypt_chacha20(self, plaintext: bytes, key: bytes, associated_data: bytes = b'') -> Dict[str, bytes]:
        """
        Encrypt data using ChaCha20-Poly1305

        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            associated_data: Additional authenticated data (optional)

        Returns:
            Dictionary containing nonce, ciphertext, and tag
        """
        chacha = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(self.CHACHA_NONCE_SIZE)

        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)

        actual_ciphertext = ciphertext[:-self.TAG_SIZE]
        tag = ciphertext[-self.TAG_SIZE:]

        return {
            'nonce': nonce,
            'ciphertext': actual_ciphertext,
            'tag': tag,
            'associated_data': associated_data
        }

    def decrypt_chacha20(self, encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305

        Args:
            encrypted_data: Dictionary with nonce, ciphertext, and tag
            key: 32-byte decryption key

        Returns:
            Decrypted plaintext
        """
        chacha = ChaCha20Poly1305(key)

        full_ciphertext = encrypted_data['ciphertext'] + encrypted_data['tag']

        try:
            plaintext = chacha.decrypt(
                encrypted_data['nonce'],
                full_ciphertext,
                encrypted_data.get('associated_data', b'')
            )
            return plaintext
        except InvalidTag:
            raise CryptoError("Authentication failed! Data may be corrupted or tampered.")

    def compute_hmac(self, data: bytes, key: bytes) -> bytes:
        """Compute HMAC-SHA256 for data integrity"""
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, signature: bytes, key: bytes) -> bool:
        """Verify HMAC signature"""
        expected = self.compute_hmac(data, key)
        return hmac.compare_digest(expected, signature)

    def create_metadata(self, algorithm: str, original_size: int,
                       timestamp: str = None, custom_data: Dict = None) -> Dict:
        """Create metadata dictionary for encrypted file"""
        metadata = {
            'algorithm': algorithm,
            'original_size': original_size,
            'timestamp': timestamp or datetime.now().isoformat(),
            'version': '2.0.0',
            'custom_data': custom_data or {}
        }
        return metadata

    def encrypt_file(self, input_path: str, output_path: str, password: str,
                    algorithm: str = 'aes-gcm', layers: int = 1,
                    use_argon2: bool = True) -> Dict[str, Any]:
        """
        Encrypt a file with professional-grade encryption

        Args:
            input_path: Path to input file
            output_path: Path to save encrypted file
            password: Encryption password
            algorithm: Encryption algorithm ('aes-gcm', 'chacha20', 'multi-layer')
            layers: Number of encryption layers (for multi-layer mode)
            use_argon2: Use Argon2 for key derivation (more secure)

        Returns:
            Dictionary with encryption details
        """
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        original_size = len(plaintext)
        filename = os.path.basename(input_path)

        # Generate random salt
        salt = secrets.token_bytes(self.SALT_SIZE)

        # Derive master key
        if use_argon2 and ARGON2_AVAILABLE:
            master_key = self.derive_key_argon2(password, salt)
            kdf_method = 'argon2id'
        else:
            master_key = self.derive_key(password, salt)
            kdf_method = 'pbkdf2'

        # Create metadata for associated data (excludes salt which is stored separately)
        # IMPORTANT: This must match exactly what will be reconstructed during decryption
        metadata_for_ad = {
            'filename': filename,
            'kdf': kdf_method,
            'original_size': original_size,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0.0'
        }

        # Prepare associated data (this will be authenticated but NOT include salt)
        associated_data = json.dumps(metadata_for_ad, sort_keys=True).encode('utf-8')

        # Create full metadata for storage (includes salt)
        metadata = dict(metadata_for_ad)
        metadata['salt'] = base64.b64encode(salt).decode('utf-8')

        # Perform encryption
        if algorithm == 'aes-gcm':
            encrypted = self.encrypt_aes_gcm(plaintext, master_key, associated_data)
            encryption_result = {
                'algorithm': 'AES-256-GCM',
                'nonce': encrypted['nonce'],
                'ciphertext': encrypted['ciphertext'],
                'tag': encrypted['tag'],
                'metadata': metadata
            }

        elif algorithm == 'chacha20':
            encrypted = self.encrypt_chacha20(plaintext, master_key, associated_data)
            encryption_result = {
                'algorithm': 'ChaCha20-Poly1305',
                'nonce': encrypted['nonce'],
                'ciphertext': encrypted['ciphertext'],
                'tag': encrypted['tag'],
                'metadata': metadata
            }

        elif algorithm == 'multi-layer':
            # Multi-layer encryption with different keys per layer
            current_data = plaintext
            layer_keys = []
            last_nonce = None
            last_tag = None

            for i in range(layers):
                layer_salt = secrets.token_bytes(self.SALT_SIZE)
                layer_key = self.derive_key(f"{password}_layer_{i}", layer_salt)
                layer_keys.append({
                    'salt': base64.b64encode(layer_salt).decode('utf-8'),
                    'key_index': i
                })

                if i % 2 == 0:
                    enc_layer = self.encrypt_aes_gcm(current_data, layer_key, associated_data)
                    current_data = enc_layer['ciphertext'] + enc_layer['tag']
                    last_nonce = enc_layer['nonce']
                    last_tag = enc_layer['tag']
                else:
                    enc_layer = self.encrypt_chacha20(current_data, layer_key, associated_data)
                    current_data = enc_layer['ciphertext'] + enc_layer['tag']
                    last_nonce = enc_layer['nonce']
                    last_tag = enc_layer['tag']

            metadata['layers'] = layers
            metadata['layer_keys'] = layer_keys

            encryption_result = {
                'algorithm': f'Multi-Layer ({layers} layers)',
                'nonce': last_nonce,
                'ciphertext': current_data,
                'tag': last_tag,
                'metadata': metadata
            }

        else:
            raise CryptoError(f"Unknown algorithm: {algorithm}")

        # Compute HMAC for additional integrity (over all binary data)
        hmac_key = self.derive_key(password + '_hmac', salt)
        all_data = (
            encryption_result['nonce'] +
            encryption_result['ciphertext'] +
            encryption_result['tag']
        )
        integrity_hmac = self.compute_hmac(all_data, hmac_key)

        # Serialize everything to JSON
        serializable_result = {
            'algorithm': encryption_result['algorithm'],
            'metadata': {
                'filename': metadata['filename'],
                'original_size': metadata['original_size'],
                'timestamp': metadata['timestamp'],
                'version': metadata['version'],
                'salt': metadata['salt'],
                'kdf': metadata['kdf']
            },
            'nonce': base64.b64encode(encryption_result['nonce']).decode('utf-8'),
            'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('utf-8'),
            'tag': base64.b64encode(encryption_result['tag']).decode('utf-8'),
            'integrity': base64.b64encode(integrity_hmac).decode('utf-8')
        }

        if 'layers' in metadata:
            serializable_result['metadata']['layers'] = metadata['layers']
            serializable_result['metadata']['layer_keys'] = metadata['layer_keys']

        # Write to output file
        output_json = json.dumps(serializable_result, indent=2)
        with open(output_path, 'w') as f:
            f.write(output_json)

        # Return statistics
        encrypted_size = os.path.getsize(output_path)
        return {
            'success': True,
            'input_file': input_path,
            'output_file': output_path,
            'algorithm': encryption_result['algorithm'],
            'original_size': original_size,
            'encrypted_size': encrypted_size,
            'expansion_ratio': round(encrypted_size / original_size, 2) if original_size > 0 else 0,
            'kdf_method': kdf_method,
            'timestamp': datetime.now().isoformat()
        }

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> Dict[str, Any]:
        """
        Decrypt a professionally encrypted file

        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file
            password: Decryption password

        Returns:
            Dictionary with decryption details
        """
        # Read encrypted file
        with open(input_path, 'r') as f:
            encrypted_data = json.load(f)

        # Extract components
        algorithm = encrypted_data['algorithm']
        metadata = encrypted_data['metadata']
        salt = base64.b64decode(metadata['salt'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        integrity_hmac = base64.b64decode(encrypted_data['integrity'])

        # Verify KDF method
        kdf_method = metadata.get('kdf', 'pbkdf2')

        # Derive master key
        if kdf_method == 'argon2id' and ARGON2_AVAILABLE:
            master_key = self.derive_key_argon2(password, salt)
        else:
            master_key = self.derive_key(password, salt)

        # Verify integrity before decryption
        hmac_key = self.derive_key(password + '_hmac', salt)
        all_data = nonce + ciphertext + tag
        if not self.verify_hmac(all_data, integrity_hmac, hmac_key):
            raise CryptoError("Integrity check failed! File may be corrupted or tampered.")

        # Prepare associated data (must match exactly what was used during encryption)
        # Remove salt from metadata for associated data reconstruction
        assoc_metadata = {k: v for k, v in metadata.items() if k != 'salt'}
        associated_data = json.dumps(assoc_metadata, sort_keys=True).encode('utf-8')

        # Handle multi-layer decryption
        if 'layers' in metadata and metadata['layers'] > 1:
            layer_keys = metadata['layer_keys']
            current_data = ciphertext

            # Process layers in reverse order
            for i in range(metadata['layers'] - 1, -1, -1):
                layer_info = layer_keys[i]
                layer_salt = base64.b64decode(layer_info['salt'])
                layer_key = self.derive_key(f"{password}_layer_{i}", layer_salt)

                # Extract ciphertext and tag for this layer
                layer_ct = current_data[:-self.TAG_SIZE]
                layer_tag = current_data[-self.TAG_SIZE:]

                enc_data_layer = {
                    'nonce': nonce,
                    'ciphertext': layer_ct,
                    'tag': layer_tag,
                    'associated_data': associated_data
                }

                if i % 2 == 0:
                    # AES layer
                    current_data = self.decrypt_aes_gcm(enc_data_layer, layer_key)
                else:
                    # ChaCha20 layer
                    current_data = self.decrypt_chacha20(enc_data_layer, layer_key)

            plaintext = current_data

        else:
            # Single layer decryption
            enc_data = {
                'nonce': nonce,
                'ciphertext': ciphertext,
                'tag': tag,
                'associated_data': associated_data
            }

            if 'AES' in algorithm:
                plaintext = self.decrypt_aes_gcm(enc_data, master_key)
            elif 'ChaCha' in algorithm:
                plaintext = self.decrypt_chacha20(enc_data, master_key)
            else:
                # Default to AES
                plaintext = self.decrypt_aes_gcm(enc_data, master_key)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        decrypted_size = len(plaintext)
        return {
            'success': True,
            'input_file': input_path,
            'output_file': output_path,
            'algorithm': algorithm,
            'original_filename': metadata.get('filename', 'unknown'),
            'encrypted_size': os.path.getsize(input_path),
            'decrypted_size': decrypted_size,
            'integrity_verified': True,
            'timestamp': datetime.now().isoformat()
        }


def print_banner():
    """Print application banner"""
    c = ColorCodes
    banner = f"""
{c.CYAN}{c.BOLD}
╔════════════════════════════════════════════════════╗
║     PROFESSIONAL CRYPTOGRAPHY SYSTEM v2.0.0        ║
║           Production-Grade File Encryption         ║
╚════════════════════════════════════════════════════╝ 
{c.RESET}
{c.GREEN}Supported Algorithms:{c.RESET}
  • {c.YELLOW}AES-256-GCM{c.RESET}      - Advanced Encryption Standard (NIST Approved)
  • {c.YELLOW}ChaCha20-Poly1305{c.RESET} - Modern High-Speed Cipher
  • {c.YELLOW}Multi-Layer{c.RESET}       - Multiple Encryption Layers

{c.GREEN}Key Derivation:{c.RESET}
  • {c.MAGENTA}PBKDF2-HMAC-SHA256{c.RESET} (100,000 iterations)
  • {c.MAGENTA}Argon2id{c.RESET}         (Memory-Hard, Recommended)

{c.GREEN}Security Features:{c.RESET}
  ✓ Authenticated Encryption (AEAD)
  ✓ Integrity Verification (HMAC)
  ✓ Tamper Detection
  ✓ Secure Random Generation
"""
    print(banner)


def print_center(text: str, width: int = None):
    """Print centered text"""
    if width is None:
        width = os.get_terminal_size().columns
    padding = max(0, (width - len(text)) // 2)
    print(" " * padding + text)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Professional Cryptography System - Secure File Encryption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -e myfile.py -o myfile_encrypted.enc
  %(prog)s -d myfile_encrypted.enc -o myfile_decrypted.py
  %(prog)s --encrypt script.py --algorithm chacha20
  %(prog)s --decrypt backup.enc --layers 3

Algorithms:
  aes-gcm       : AES-256-GCM (Recommended for most use cases)
  chacha20      : ChaCha20-Poly1305 (Faster on mobile/no AES-NI)
  multi-layer   : Multiple encryption layers (Maximum security)
        """
    )

    parser.add_argument('-e', '--encrypt', metavar='FILE',
                       help='Encrypt the specified file')
    parser.add_argument('-d', '--decrypt', metavar='FILE',
                       help='Decrypt the specified file')
    parser.add_argument('-o', '--output', metavar='FILE',
                       help='Output file path')
    parser.add_argument('-a', '--algorithm', choices=['aes-gcm', 'chacha20', 'multi-layer'],
                       default='aes-gcm', help='Encryption algorithm (default: aes-gcm)')
    parser.add_argument('-l', '--layers', type=int, default=1,
                       help='Number of encryption layers (for multi-layer mode)')
    parser.add_argument('--no-argon2', action='store_true',
                       help='Disable Argon2 (use PBKDF2 instead)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version', version='Professional Crypto v2.0.0')

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Check arguments
    if not args.encrypt and not args.decrypt:
        parser.print_help()
        sys.exit(1)

    # Initialize crypto system
    try:
        crypto = ProfessionalCrypto()
    except CryptoError as e:
        print(f"{ColorCodes.RED}Error: {e}{ColorCodes.RESET}")
        sys.exit(1)

    # Get password securely
    password = getpass.getpass(f"{ColorCodes.CYAN}Enter password: {ColorCodes.RESET}")
    if not password:
        print(f"{ColorCodes.RED}Error: Password cannot be empty{ColorCodes.RESET}")
        sys.exit(1)

    confirm_password = getpass.getpass(f"{ColorCodes.CYAN}Confirm password: {ColorCodes.RESET}")
    if password != confirm_password:
        print(f"{ColorCodes.RED}Error: Passwords do not match{ColorCodes.RESET}")
        sys.exit(1)

    try:
        if args.encrypt:
            input_file = args.encrypt
            output_file = args.output or f"{os.path.splitext(input_file)[0]}_encrypted.enc"

            print(f"\n{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Encrypting: {ColorCodes.WHITE}{input_file}{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Algorithm: {ColorCodes.YELLOW}{args.algorithm.upper()}{ColorCodes.RESET}")
            if args.algorithm == 'multi-layer':
                print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Layers: {ColorCodes.MAGENTA}{args.layers}{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Output: {ColorCodes.WHITE}{output_file}{ColorCodes.RESET}")
            print()

            result = crypto.encrypt_file(
                input_file, output_file, password,
                algorithm=args.algorithm,
                layers=args.layers,
                use_argon2=not args.no_argon2
            )

            print(f"\n{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}✓ ENCRYPTION COMPLETED SUCCESSFULLY{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}")
            print(f"  Input File:     {result['input_file']}")
            print(f"  Output File:    {result['output_file']}")
            print(f"  Algorithm:      {result['algorithm']}")
            print(f"  Original Size:  {result['original_size']:,} bytes")
            print(f"  Encrypted Size: {result['encrypted_size']:,} bytes")
            print(f"  Expansion:      {result['expansion_ratio']}x")
            print(f"  KDF Method:     {result['kdf_method']}")
            print(f"  Timestamp:      {result['timestamp']}")
            print(f"{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}\n")

        elif args.decrypt:
            input_file = args.decrypt
            output_file = args.output or f"{os.path.splitext(input_file)[0]}_decrypted{os.path.splitext(input_file)[1]}"

            print(f"\n{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Decrypting: {ColorCodes.WHITE}{input_file}{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Output: {ColorCodes.WHITE}{output_file}{ColorCodes.RESET}")
            print()

            result = crypto.decrypt_file(input_file, output_file, password)

            print(f"\n{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}✓ DECRYPTION COMPLETED SUCCESSFULLY{ColorCodes.RESET}")
            print(f"{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}")
            print(f"  Input File:       {result['input_file']}")
            print(f"  Output File:      {result['output_file']}")
            print(f"  Original Filename: {result['original_filename']}")
            print(f"  Algorithm:        {result['algorithm']}")
            print(f"  Encrypted Size:   {result['encrypted_size']:,} bytes")
            print(f"  Decrypted Size:   {result['decrypted_size']:,} bytes")
            print(f"  Integrity:        {ColorCodes.GREEN}VERIFIED ✓{ColorCodes.RESET}")
            print(f"  Timestamp:        {result['timestamp']}")
            print(f"{ColorCodes.GREEN}{'═'*60}{ColorCodes.RESET}\n")

    except CryptoError as e:
        print(f"\n{ColorCodes.RED}✗ ERROR: {e}{ColorCodes.RESET}\n")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n{ColorCodes.RED}✗ ERROR: File not found - {e}{ColorCodes.RESET}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{ColorCodes.RED}✗ UNEXPECTED ERROR: {e}{ColorCodes.RESET}\n")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
