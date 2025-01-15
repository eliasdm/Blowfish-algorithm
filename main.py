import os
from blowfish import Blowfish

def read_plaintext():
    """Read plaintext either from a file or user input."""
    choice = input("Enter '1' to read plaintext from a text file, or '2' to input plaintext manually: ")
    if choice == '1':
        file_path = input("Enter the path of the plaintext file: ")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:  # Read as text
                plaintext = file.read().encode()  # Convert text to bytes
                print("Plaintext read from file successfully.")
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
    print(f"Data saved to {filename}")

def main():
    key = input("Enter a key (4 to 56 characters): ").encode()
    while len(key) < 4 or len(key) > 56:
        print("Key length must be between 4 and 56 characters.")
        key = input("Enter a key (4 to 56 characters): ").encode()

    plaintext = read_plaintext()
    if plaintext is None:
        return

    iv = os.urandom(8)  # Generate a random IV
    blowfish = Blowfish(key)

    # Encrypt plaintext
    ciphertext = blowfish.encrypt_cbc(plaintext, iv)
    ciphertext_hex = ciphertext.hex()  # Convert to hex string
    print("Ciphertext (hex):", ciphertext_hex)

    # Save ciphertext to a text file
    save_choice = input("Do you want to save the ciphertext to a text file? (y/n): ").lower()
    if save_choice == 'y':
        save_to_file("ciphertext.txt", ciphertext_hex)

    # Decrypt ciphertext
    decrypted_text = blowfish.decrypt_cbc(bytes.fromhex(ciphertext_hex), iv).decode()
    print("Decrypted Text:", decrypted_text)

    # Save decrypted text to a file
    save_choice = input("Do you want to save the decrypted text to a file? (y/n): ").lower()
    if save_choice == 'y':
        save_to_file("decrypted_text.txt", decrypted_text)

if __name__ == "__main__":
    main()