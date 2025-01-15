import os
from blowfish import Blowfish

def read_plaintext():
    """Read plaintext either from a file or user input."""

    choice = input("Enter '1' to read plaintext from a text file, or '2' to input text manually: ")
    if choice == '1':
        file_path = input("Enter file path: ")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:  # Read as text
                plaintext = file.read().encode()  # Convert text to bytes
                return plaintext
            
        except FileNotFoundError:
            print("Error: File not found. Please check the path and try again.")
            return None
        
    elif choice == '2':
        plaintext = input("Enter plaintext: ").encode()  
        return plaintext
    else:
        print("Invalid choice. Please try again.")
        return None

def save_to_file(filename, data, mode='w'):
    """Save data to a specified file."""
    with open(filename, mode, encoding='utf-8') as file:
        file.write(data)
    print(f"Data saved to   {filename}")

def encrypt_data(plaintext, key):
    """Encrypt plaintext using Blowfish."""
    iv = os.urandom(8)      # Generate a random IV
    blowfish = Blowfish(key)
    ciphertext = blowfish.encrypt_cbc(plaintext, iv)
    return ciphertext, iv

def decrypt_data(ciphertext, key, iv):
    """Decrypt ciphertext using Blowfish."""
    blowfish = Blowfish(key)
    decrypted_text = blowfish.decrypt_cbc(ciphertext, iv).decode()
    return decrypted_text

def read_ciphertext(file_path):
    """Read ciphertext and extract IV and ciphertext."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            ciphertext_hex = file.read().strip()  # Read the hex string
            ciphertext_with_iv = bytes.fromhex(ciphertext_hex)

            iv = ciphertext_with_iv[:8]          # Extract the IV (first 8 bytes)
            ciphertext = ciphertext_with_iv[8:]         # Extract the actual ciphertext
            return iv, ciphertext
    except FileNotFoundError:
        print("Error: File not found. Please check the path and try again.")
        return None, None

def main():
    operation = input("Enter '1' to encrypt or '2' to decrypt: ")
    key = input("Enter a key (4 to 56 characters): ").encode()
    
    while len(key) < 4 or len(key) > 56:
        print("Key length must be between 4 and 56 characters.")
        key = input("Enter a key (4 to 56 characters): ").encode()

    if operation == '1':  # Encryption
        plaintext = read_plaintext()
        if plaintext is None:
            return

        ciphertext, iv = encrypt_data(plaintext, key)
        ciphertext_with_iv = iv + ciphertext  # Prepend the IV to the ciphertext
        ciphertext_hex = ciphertext_with_iv.hex()  # Convert to hex string
        print("Ciphertext (hex):", ciphertext_hex)

        # Save ciphertext (with IV) to a text file
        save_choice = input("Do you want to save the ciphertext to a text file? (y/n): ").lower()
        if save_choice == 'y':
            save_to_file("ciphertext.txt", ciphertext_hex)

    elif operation == '2':  # Decryption
        file_path = input("Enter the file path to read the ciphertext from: ")
        iv, ciphertext = read_ciphertext(file_path)
        if iv is None or ciphertext is None:
            return

        decrypted_text = decrypt_data(ciphertext, key, iv)
        print("Decrypted Text:", decrypted_text)

        # Save decrypted text to a file
        save_choice = input("Do you want to save the decrypted text to a file? (y/n): ").lower()
        if save_choice == 'y':
            save_to_file("decrypted_text.txt", decrypted_text)

    else:
        print("Invalid choice. Please choose '1' to encrypt or '2' to decrypt.")

if __name__ == "__main__":
    main()
