from cryptography.fernet import Fernet

def generate_key():
    """
    Generates a new Fernet key and saves it to a file named 'secret.key'.
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("A new encryption key has been generated and saved to 'secret.key'")

if __name__ == "__main__":
    generate_key()
