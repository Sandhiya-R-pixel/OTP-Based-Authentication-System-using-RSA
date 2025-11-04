# OTP-Based Authentication System using RSA
# Author: Sandhiya R
# Year: 2025

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import random
import string
import os
import time


# ----------------------------
# RSA KEY GENERATION SECTION
# ----------------------------
def generate_rsa_keys(username):
    """Generate public and private RSA key pair for a user"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save the keys as files
    with open(f"{username}_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(f"{username}_public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"\n🔑 RSA key pair generated for {username}!")
    print(f"➡️  Public Key: {username}_public_key.pem")
    print(f"➡️  Private Key: {username}_private_key.pem\n")


# ----------------------------
# OTP GENERATION SECTION
# ----------------------------
def generate_otp():
    """Generate a 6-digit random OTP"""
    otp = ''.join(random.choices(string.digits, k=6))
    return otp


# ----------------------------
# RSA ENCRYPTION SECTION
# ----------------------------
def encrypt_otp(public_key_path, otp):
    """Encrypt OTP using public key"""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_otp = public_key.encrypt(
        otp.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return encrypted_otp


def decrypt_otp(private_key_path, encrypted_otp):
    """Decrypt OTP using private key"""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    decrypted_otp = private_key.decrypt(
        encrypted_otp,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return decrypted_otp.decode()


# ----------------------------
# MAIN AUTHENTICATION SYSTEM
# ----------------------------
def user_registration():
    """Register a new user and generate RSA keys"""
    username = input("Enter a username for registration: ").strip()

    # Create key pair for the user
    generate_rsa_keys(username)

    # Save user info
    with open("users.txt", "a") as f:
        f.write(username + "\n")

    print(f"✅ User '{username}' registered successfully!\n")


def user_login():
    """Authenticate user with RSA-encrypted OTP"""
    username = input("Enter your username to login: ").strip()

    if not os.path.exists(f"{username}_public_key.pem") or not os.path.exists(f"{username}_private_key.pem"):
        print("❌ User not found. Please register first.\n")
        return

    print("\nGenerating OTP...")
    otp = generate_otp()
    time.sleep(1)

    encrypted_otp = encrypt_otp(f"{username}_public_key.pem", otp)
    print(f"\n🔒 Encrypted OTP (sent to user): {encrypted_otp}\n")

    # Decrypt OTP using private key (simulation of user side)
    decrypted_otp = decrypt_otp(f"{username}_private_key.pem", encrypted_otp)
    print(f"🧩 Decrypted OTP (user’s private key): {decrypted_otp}")

    entered_otp = input("Enter the OTP you received: ").strip()

    if entered_otp == decrypted_otp:
        print("\n✅ Authentication Successful! Access Granted.")
    else:
        print("\n❌ Authentication Failed. Invalid OTP.")


# ----------------------------
# PROGRAM MENU
# ----------------------------
def main():
    while True:
        print("\n" + "="*50)
        print("🔐 OTP-Based Authentication System using RSA")
        print("="*50)
        print("1. Register New User")
        print("2. Login with OTP")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            user_registration()
        elif choice == "2":
            user_login()
        elif choice == "3":
            print("\n👋 Exiting program. Stay secure!")
            break
        else:
            print("⚠️ Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

