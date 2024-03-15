layers of decoding and encoding 

- **Multi-Layer Encryption**: used 12 layers of encryption to protect your Python files
- **thorough Encryption Procedures**: detailing  layers of encryption  and decryption  
- **Simple Command-Line Interface**: Python files may be easily encrypted and decrypted with a simple command line.

# The Encryption Process

The encryption process consists of the following steps:

1. **Base64 Encoding**
2. **Zlib Compression**
3. **Marshal Serialization**
4. **Repeatedly the processes 12 time**


- **To encrypt a Python file, perform the following steps:**

### 1. Clone the Repository
`git clone https://github.com/v2Talal/Encrypt_Decrypt_Py`

`cd Encrypt_Decrypt_Py`

#### Options:

- `python encrypt_decrypt.py --encode <input_file>`
  
- Replace `<input_file>` with the path to the Python file you want to encrypt.

To decrypt an encrypted Python file, use the `--decode` option:

- `python encrypt_decrypt.py --decode <input_file>`


**Usages Options** 
````
python encrypt_decrypt.py --encode <input_file>{

python encrypt_decrypt.py --decode <input_file>

python encrypt_decrypt.py -e <input_file>

python encrypt_decrypt.py -d <input_file>
````

> [!NOTE]
You must have python
> 
- Python 3.x 


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
