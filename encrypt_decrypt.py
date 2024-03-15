import sys
import os
import base64
import zlib
import marshal
import shutil

black = '\033[90m'
red = '\033[31m'
green = '\033[32m'
yellow = '\033[33m'
white = '\033[37m'
reset = '\033[0m'
lightred = '\033[91m'
bold = "\033[1m"
cyan = "\033[0;36m"


def print_center(text):
    terminal_width = shutil.get_terminal_size().columns
    
    left_padding = (terminal_width - len(text)) // 15
    
    print(" " * left_padding + text)
def custom_encrypt(content):
    marshaled_content = marshal.dumps(content)
    encoded_content = base64.b64encode(marshaled_content)
    compressed_content = zlib.compress(encoded_content)
    marshaled_content_2 = marshal.dumps(compressed_content)
    encoded_content_2 = base64.b64encode(marshaled_content_2)
    compressed_content_2 = zlib.compress(encoded_content_2)
    marshaled_content_3 = marshal.dumps(compressed_content_2)
    encoded_content_3 = base64.b64encode(marshaled_content_3)
    compressed_content_3 = zlib.compress(encoded_content_3)
    marshaled_content_4 = marshal.dumps(compressed_content_3)
    encoded_content_4 = base64.b64encode(marshaled_content_4)
    compressed_content_4 = zlib.compress(encoded_content_4)
    return compressed_content_4

def custom_decrypt(encrypted_content):
    decompressed_content_4 = zlib.decompress(encrypted_content)
    decoded_content_4 = base64.b64decode(decompressed_content_4)
    unmarshaled_content_4 = marshal.loads(decoded_content_4)
    decompressed_content_3 = zlib.decompress(unmarshaled_content_4)
    decoded_content_3 = base64.b64decode(decompressed_content_3)
    unmarshaled_content_3 = marshal.loads(decoded_content_3)
    decompressed_content_2 = zlib.decompress(unmarshaled_content_3)
    decoded_content_2 = base64.b64decode(decompressed_content_2)
    unmarshaled_content_2 = marshal.loads(decoded_content_2)
    decompressed_content = zlib.decompress(unmarshaled_content_2)
    decoded_content = base64.b64decode(decompressed_content)
    unmarshaled_content = marshal.loads(decoded_content)
    return unmarshaled_content

def encrypt_python_file(input_file):
    try:
        with open(input_file, 'rb') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"{red}Error Input file {black}'{input_file}' {red}not found.{reset}")
        print()
        sys.exit(1)
    except Exception as e:
        print(f"{red}Error An unexpected error occurred:{lightred} {e}{reset}")
        print()
        sys.exit(1)
    
    encrypted_content = custom_encrypt(content)
    
    output_file = os.path.splitext(input_file)[0] + "_encode.py"
    try:
        with open(output_file, 'wb') as file:
            file.write(encrypted_content)
    except Exception as e:
        print(f"{red}Error Unable to write encrypted content to file:{lightred} {e}{reset}")
        print()
        sys.exit(1)
    
    print(f"{green}Python file {black}'{input_file}' {green}encrypted and saved as {white}'{output_file}'.{reset}")

def decrypt_python_file(input_file):
    try:
        with open(input_file, 'rb') as file:
            encrypted_content = file.read()
    except FileNotFoundError:
        print(f"{red}Error Input file {black}'{input_file}' {red}not found.{reset}")
        print()
        sys.exit(1)
    except Exception as e:
        print(f"{red}Error An unexpected error occurred:{lightred} {e}{reset}")
        print()
        sys.exit(1)
    
    decrypted_content = custom_decrypt(encrypted_content)
    
    output_file = os.path.splitext(input_file)[0] + "_decode.py"
    try:
        with open(output_file, 'wb') as file:
            file.write(decrypted_content)
    except Exception as e:
        print(f"{red}Error Unable to write decrypted content to file:{lightred} {e}{reset}")
        print()
        sys.exit(1)
    
    print(f"{green}Python file {black}'{input_file}' {green} decrypted and saved as {white}'{output_file}'.{reset}")
    print()

def Encrypt_Decrypt_Py():
    print()
    print_center(f"{green} Python File {bold}Encryption / Decryption{reset}")
    print()
    if len(sys.argv) != 3 or sys.argv[1] in ['--h', '--help']:
        print(f"{white}|▶ {red}- {green}Option: {black}python encrypt_decrypt.py -e / -d <input_file>{reset}")
        print()
        print(f"{white}|▶ {red}- {yellow}Usages Options:{reset}")
        print()
        print(f"{cyan} python encrypt_decrypt.py --encode <input_file>{reset}")
        print()
        print(f"{cyan} python encrypt_decrypt.py --decode <input_file>{reset}")
        print()
        print(f"{cyan} python encrypt_decrypt.py -e <input_file>{reset}")
        print()
        print(f"{cyan} python encrypt_decrypt.py -d <input_file>{reset}")
        print()
        sys.exit(1)
    
    option = sys.argv[1]
    input_file = sys.argv[2]
    
    if option in ['--encode', '-e']:
        encrypt_python_file(input_file)
    elif option in ['--decode', '-d']:
        decrypt_python_file(input_file)
    else:
        print(f"{red}Invalid option:{lightred} Use '--encode' or '-e' for encryption, or '--decode' or '-d' for decryption.{reset}")
        sys.exit(1)

if __name__ == "__main__":
    Encrypt_Decrypt_Py()
