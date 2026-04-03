#!/usr/bin/env python3
"""
Test script for Professional Cryptography System
Automated testing without interactive password input
"""

import os
import sys
import json

# Add workspace to path
sys.path.insert(0, '/workspace')

from professional_crypto import ProfessionalCrypto, ColorCodes

def print_section(title):
    """Print section header"""
    c = ColorCodes
    print(f"\n{c.CYAN}{c.BOLD}{'='*60}{c.RESET}")
    print(f"{c.CYAN}{c.BOLD}{title}{c.RESET}")
    print(f"{c.CYAN}{c.BOLD}{'='*60}{c.RESET}\n")

def test_aes_gcm_encryption():
    """Test AES-256-GCM encryption and decryption"""
    print_section("TEST 1: AES-256-GCM Encryption/Decryption")
    
    crypto = ProfessionalCrypto()
    password = "TestPassword123!"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_aes_encrypted.enc"
    decrypted_file = "/workspace/test_aes_decrypted.py"
    
    # Read original file
    with open(input_file, 'rb') as f:
        original_content = f.read()
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Original file size: {len(original_content)} bytes")
    
    # Encrypt
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting with AES-256-GCM...")
    encrypt_result = crypto.encrypt_file(
        input_file, encrypted_file, password,
        algorithm='aes-gcm',
        use_argon2=False  # Use PBKDF2 for faster testing
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Encryption successful!")
    print(f"  - Algorithm: {encrypt_result['algorithm']}")
    print(f"  - Encrypted size: {encrypt_result['encrypted_size']:,} bytes")
    print(f"  - KDF: {encrypt_result['kdf_method']}")
    
    # Verify encrypted file exists
    assert os.path.exists(encrypted_file), "Encrypted file not created!"
    
    # Decrypt
    print(f"\n{ColorCodes.GREEN}[→]{ColorCodes.RESET} Decrypting...")
    decrypt_result = crypto.decrypt_file(encrypted_file, decrypted_file, password)
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Decryption successful!")
    print(f"  - Decrypted size: {decrypt_result['decrypted_size']:,} bytes")
    print(f"  - Integrity verified: {decrypt_result['integrity_verified']}")
    
    # Verify decrypted content matches original
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    assert original_content == decrypted_content, "Decrypted content does not match original!"
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ AES-256-GCM TEST PASSED{ColorCodes.RESET}")
    return True

def test_chacha20_encryption():
    """Test ChaCha20-Poly1305 encryption and decryption"""
    print_section("TEST 2: ChaCha20-Poly1305 Encryption/Decryption")
    
    crypto = ProfessionalCrypto()
    password = "SecurePassword456!"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_chacha_encrypted.enc"
    decrypted_file = "/workspace/test_chacha_decrypted.py"
    
    # Read original file
    with open(input_file, 'rb') as f:
        original_content = f.read()
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Original file size: {len(original_content)} bytes")
    
    # Encrypt
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting with ChaCha20-Poly1305...")
    encrypt_result = crypto.encrypt_file(
        input_file, encrypted_file, password,
        algorithm='chacha20',
        use_argon2=False
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Encryption successful!")
    print(f"  - Algorithm: {encrypt_result['algorithm']}")
    print(f"  - Encrypted size: {encrypt_result['encrypted_size']:,} bytes")
    
    # Decrypt
    print(f"\n{ColorCodes.GREEN}[→]{ColorCodes.RESET} Decrypting...")
    decrypt_result = crypto.decrypt_file(encrypted_file, decrypted_file, password)
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Decryption successful!")
    
    # Verify content
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    assert original_content == decrypted_content, "Decrypted content does not match original!"
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ ChaCha20-Poly1305 TEST PASSED{ColorCodes.RESET}")
    return True

def test_multi_layer_encryption():
    """Test Multi-Layer encryption and decryption"""
    print_section("TEST 3: Multi-Layer Encryption (3 layers)")
    
    crypto = ProfessionalCrypto()
    password = "MultiLayer789!"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_multi_encrypted.enc"
    decrypted_file = "/workspace/test_multi_decrypted.py"
    layers = 3
    
    # Read original file
    with open(input_file, 'rb') as f:
        original_content = f.read()
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Original file size: {len(original_content)} bytes")
    
    # Encrypt with multiple layers
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting with {layers} layers (AES + ChaCha20 alternating)...")
    encrypt_result = crypto.encrypt_file(
        input_file, encrypted_file, password,
        algorithm='multi-layer',
        layers=layers,
        use_argon2=False
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Multi-layer encryption successful!")
    print(f"  - Algorithm: {encrypt_result['algorithm']}")
    print(f"  - Encrypted size: {encrypt_result['encrypted_size']:,} bytes")
    print(f"  - Expansion ratio: {encrypt_result['expansion_ratio']}x")
    
    # Decrypt
    print(f"\n{ColorCodes.GREEN}[→]{ColorCodes.RESET} Decrypting multi-layer encryption...")
    decrypt_result = crypto.decrypt_file(encrypted_file, decrypted_file, password)
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Multi-layer decryption successful!")
    
    # Verify content
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    assert original_content == decrypted_content, "Decrypted content does not match original!"
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ Multi-Layer TEST PASSED{ColorCodes.RESET}")
    return True

def test_argon2_key_derivation():
    """Test Argon2id key derivation"""
    print_section("TEST 4: Argon2id Key Derivation")
    
    crypto = ProfessionalCrypto()
    password = "Argon2Test!@#"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_argon2_encrypted.enc"
    decrypted_file = "/workspace/test_argon2_decrypted.py"
    
    # Read original file
    with open(input_file, 'rb') as f:
        original_content = f.read()
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Testing Argon2id key derivation...")
    
    # Encrypt with Argon2
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting with Argon2id...")
    encrypt_result = crypto.encrypt_file(
        input_file, encrypted_file, password,
        algorithm='aes-gcm',
        use_argon2=True
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Encryption with Argon2id successful!")
    print(f"  - KDF Method: {encrypt_result['kdf_method']}")
    
    # Decrypt
    print(f"\n{ColorCodes.GREEN}[→]{ColorCodes.RESET} Decrypting...")
    decrypt_result = crypto.decrypt_file(encrypted_file, decrypted_file, password)
    
    # Verify content
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    assert original_content == decrypted_content, "Decrypted content does not match original!"
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ Argon2id TEST PASSED{ColorCodes.RESET}")
    return True

def test_wrong_password():
    """Test that wrong password fails decryption"""
    print_section("TEST 5: Wrong Password Detection")
    
    crypto = ProfessionalCrypto()
    correct_password = "CorrectPassword123!"
    wrong_password = "WrongPassword456!"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_wrong_pwd.enc"
    decrypted_file = "/workspace/test_wrong_pwd_decrypted.py"
    
    # Encrypt with correct password
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting with correct password...")
    crypto.encrypt_file(
        input_file, encrypted_file, correct_password,
        algorithm='aes-gcm',
        use_argon2=False
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} File encrypted successfully")
    
    # Try to decrypt with wrong password
    print(f"\n{ColorCodes.YELLOW}[→]{ColorCodes.RESET} Attempting decryption with WRONG password...")
    try:
        crypto.decrypt_file(encrypted_file, decrypted_file, wrong_password)
        print(f"{ColorCodes.RED}[✗]{ColorCodes.RESET} ERROR: Should have failed with wrong password!")
        return False
    except Exception as e:
        print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Correctly rejected wrong password!")
        print(f"  - Error type: {type(e).__name__}")
        print(f"  - Message: {str(e)[:80]}...")
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ Wrong Password Detection TEST PASSED{ColorCodes.RESET}")
    return True

def test_data_integrity():
    """Test tamper detection"""
    print_section("TEST 6: Data Integrity & Tamper Detection")
    
    crypto = ProfessionalCrypto()
    password = "IntegrityTest!@#"
    input_file = "/workspace/test_sample.py"
    encrypted_file = "/workspace/test_integrity.enc"
    decrypted_file = "/workspace/test_integrity_decrypted.py"
    
    # Encrypt file
    print(f"{ColorCodes.GREEN}[→]{ColorCodes.RESET} Encrypting file...")
    crypto.encrypt_file(
        input_file, encrypted_file, password,
        algorithm='aes-gcm',
        use_argon2=False
    )
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} File encrypted")
    
    # Read encrypted file and tamper with it
    print(f"\n{ColorCodes.YELLOW}[→]{ColorCodes.RESET} Tampering with encrypted data...")
    with open(encrypted_file, 'r') as f:
        encrypted_data = json.load(f)
    
    # Tamper with ciphertext (change first character)
    original_ciphertext = encrypted_data['ciphertext']
    tampered_ciphertext = 'X' + original_ciphertext[1:]
    encrypted_data['ciphertext'] = tampered_ciphertext
    
    # Save tampered file
    tampered_file = "/workspace/test_integrity_tampered.enc"
    with open(tampered_file, 'w') as f:
        json.dump(encrypted_data, f)
    
    print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} File tampered")
    
    # Try to decrypt tampered file
    print(f"\n{ColorCodes.YELLOW}[→]{ColorCodes.RESET} Attempting to decrypt tampered file...")
    try:
        crypto.decrypt_file(tampered_file, decrypted_file, password)
        print(f"{ColorCodes.RED}[✗]{ColorCodes.RESET} ERROR: Should have detected tampering!")
        return False
    except Exception as e:
        print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Tampering correctly detected!")
        print(f"  - Error type: {type(e).__name__}")
        print(f"  - Message: {str(e)[:80]}...")
    
    # Clean up tampered file
    os.remove(tampered_file)
    
    print(f"\n{ColorCodes.GREEN}{ColorCodes.BOLD}✓ Data Integrity TEST PASSED{ColorCodes.RESET}")
    return True

def cleanup_test_files():
    """Clean up test files"""
    print_section("Cleaning Up Test Files")
    
    test_files = [
        "/workspace/test_aes_encrypted.enc",
        "/workspace/test_aes_decrypted.py",
        "/workspace/test_chacha_encrypted.enc",
        "/workspace/test_chacha_decrypted.py",
        "/workspace/test_multi_encrypted.enc",
        "/workspace/test_multi_decrypted.py",
        "/workspace/test_argon2_encrypted.enc",
        "/workspace/test_argon2_decrypted.py",
        "/workspace/test_wrong_pwd.enc",
        "/workspace/test_wrong_pwd_decrypted.py",
        "/workspace/test_integrity.enc",
        "/workspace/test_integrity_decrypted.py",
    ]
    
    cleaned = 0
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)
            cleaned += 1
            print(f"{ColorCodes.GREEN}[✓]{ColorCodes.RESET} Removed: {file}")
    
    print(f"\n{ColorCodes.GREEN}Cleaned up {cleaned} test files{ColorCodes.RESET}")

def main():
    """Run all tests"""
    c = ColorCodes
    
    print(f"\n{c.CYAN}{c.BOLD}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   PROFESSIONAL CRYPTOGRAPHY SYSTEM - TEST SUITE         ║")
    print("║           Comprehensive Security Testing                ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{c.RESET}\n")
    
    tests = [
        ("AES-256-GCM", test_aes_gcm_encryption),
        ("ChaCha20-Poly1305", test_chacha20_encryption),
        ("Multi-Layer (3 layers)", test_multi_layer_encryption),
        ("Argon2id KDF", test_argon2_key_derivation),
        ("Wrong Password Detection", test_wrong_password),
        ("Data Integrity & Tamper Detection", test_data_integrity),
    ]
    
    results = []
    total_tests = len(tests)
    
    for i, (test_name, test_func) in enumerate(tests, 1):
        try:
            print(f"\n{c.DIM}Running test {i}/{total_tests}: {test_name}{c.RESET}")
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n{c.RED}[✗] Test '{test_name}' FAILED with exception: {e}{c.RESET}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print_section("TEST SUMMARY")
    
    passed = sum(1 for _, success in results if success)
    failed = total_tests - passed
    
    for test_name, success in results:
        status = f"{c.GREEN}✓ PASSED{c.RESET}" if success else f"{c.RED}✗ FAILED{c.RESET}"
        print(f"  {test_name:.<50} {status}")
    
    print(f"\n{c.BOLD}Total: {passed}/{total_tests} tests passed{c.RESET}")
    
    if failed == 0:
        print(f"\n{c.GREEN}{c.BOLD}🎉 ALL TESTS PASSED! 🎉{c.RESET}")
        print(f"{c.GREEN}The Professional Cryptography System is working correctly!{c.RESET}\n")
        
        # Cleanup
        cleanup_input = input("\nClean up test files? (y/n): ").strip().lower()
        if cleanup_input == 'y':
            cleanup_test_files()
        
        return 0
    else:
        print(f"\n{c.RED}{c.BOLD}⚠ SOME TESTS FAILED ⚠{c.RESET}")
        print(f"{c.RED}Please review the errors above.{c.RESET}\n")
        return 1

if __name__ == '__main__':
    sys.exit(main())
