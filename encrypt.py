from cryptography.fernet import Fernet
import json
import os

def load_key():
    """
    Loads the key from the file 'secret.key'.
    """
    return open("secret.key", "rb").read()

def encrypt_config():
    """
    Reads config.json, loads it as a JSON object, dumps it back to a compact string,
    encrypts it, and saves it to config.json.encrypted.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.json')
    encrypted_config_path = os.path.join(script_dir, 'config.json.encrypted')

    try:
        # 1. Load config.json content as a Python dictionary
        with open(config_path, 'r', encoding='utf-8') as f: # Specify encoding
            config_dict = json.load(f)

        # 2. Dump the dictionary back to a *compact* JSON string.
        #    This removes any extraneous whitespace, newlines, etc.,
        #    which sometimes cause issues with string-based encryption.
        config_json_string = json.dumps(config_dict, separators=(',', ':')) # Use separators for compactness

        # 3. Encrypt the clean, compact JSON string (encoded to bytes)
        fernet = Fernet(load_key())
        encrypted_data = fernet.encrypt(config_json_string.encode('utf-8'))

        # 4. Write the encrypted bytes to the output file
        with open(encrypted_config_path, 'wb') as f:
            f.write(encrypted_data)

        print(f"Configuration file '{config_path}' has been successfully encrypted to '{encrypted_config_path}'")

    except FileNotFoundError:
        print(f"Error: '{config_path}' not found. Please create it with the necessary key-value pairs.")
    except json.JSONDecodeError as e:
        print(f"Error: '{config_path}' contains invalid JSON: {e}")
    except Exception as e:
        print(f"An error occurred during encryption: {e}")

if __name__ == "__main__":
    encrypt_config()
