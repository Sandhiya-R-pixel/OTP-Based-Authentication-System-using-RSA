# OTP-Based-Authentication-System-using-RSA
# 🛡️ OTP-Based Authentication System using RSA

## 📘 Overview
The **OTP-Based Authentication System using RSA** is a secure authentication mechanism designed to protect user login processes through the integration of **One-Time Password (OTP)** verification and **RSA encryption**.  
This system ensures that sensitive data such as authentication codes and user credentials remain confidential and tamper-proof during transmission and storage.

The project aims to demonstrate how **public-key cryptography** can be effectively combined with **dynamic password mechanisms (OTP)** to build a strong, secure, and modern authentication framework.  
It is a practical implementation of concepts in **network security**, **data encryption**, and **user authentication** — suitable for academic learning and professional development.

---

## 🎯 Objectives
- To design and implement a **secure authentication system** using RSA encryption.
- To integrate **One-Time Password (OTP)** verification for added security during user login.
- To demonstrate the working of **public-key and private-key** mechanisms in real-time applications.
- To enhance **data confidentiality** and **user identity protection**.
- To provide a **simple yet effective model** for learning about cryptography and authentication.

---

## ⚙️ Features
- 🔑 **RSA Key Generation** — Automatically generates public and private key pairs for encryption and decryption.
- 🔐 **OTP Generation and Validation** — Creates random one-time passwords for every login attempt.
- 📩 **Encrypted OTP Transmission** — OTPs are encrypted using RSA before being sent to the user.
- 👤 **User Registration and Login System** — Secure account creation and verification workflow.
- 🧠 **Secure Data Handling** — Prevents plaintext transmission of sensitive information.
- 💻 **Simple Console Interface** — Easy-to-understand and interactive text-based environment.
- 📊 **Extendable Design** — Can be enhanced to include email/SMS OTP delivery or GUI features.

---

## 🧩 Technologies Used

| Category | Technology |
|-----------|-------------|
| **Programming Language** | Python |
| **Encryption Algorithm** | RSA (Public-Key Cryptography) |
| **OTP Module** | `random`, `secrets`, or `pyotp` |
| **Cryptography Library** | `cryptography` or `PyCrypto` |
| **Email Support (Optional)** | `smtplib` |
| **Database (Optional)** | SQLite or CSV file |
| **IDE/Editor** | Thonny, Visual Studio Code, PyCharm |

---

## 🏗️ System Architecture
The working of the OTP-Based Authentication System using RSA can be summarized as follows:

1. **User Registration**  
   The user registers their details (username, email, etc.). RSA key pairs (public and private) are generated.

2. **Login Attempt**  
   The system verifies the username and generates a one-time password (OTP).

3. **Encryption Process**  
   The OTP is **encrypted using the user’s public key** before being sent to ensure confidentiality.

4. **Decryption and Verification**  
   The user decrypts the OTP using their private key and enters it into the system for verification.

5. **Access Control**  
   If the decrypted OTP matches, access is granted; otherwise, authentication fails.

This flow ensures that even if the transmission channel is compromised, the OTP remains unreadable to attackers due to RSA encryption.

---
## 🧠 Working Example
1. Registration Phase

The user registers for the first time.

RSA public and private keys are generated.

User details are stored securely.

2. Login Phase

The user enters their username.

The system generates a random OTP.

The OTP is encrypted using RSA and displayed (or sent via email).

The user decrypts it using their private key and enters it.

If valid, login is successful.

## 📈 Sample Output
Enter your username: sandhiya
Generating OTP...
Encrypted OTP: b'Q\x8f...\xaf'
Decrypted OTP: 425319
Enter the OTP: 425319
Access Granted ✅

## 🧮 Algorithmic Steps
RSA Algorithm

Choose two distinct prime numbers p and q.

Compute n = p * q.

Calculate Euler’s Totient function: φ(n) = (p - 1)(q - 1).

Choose public key e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1.

Determine private key d such that (d * e) % φ(n) = 1.

Public Key = (e, n), Private Key = (d, n).

Encryption: C = (M^e) % n

Decryption: M = (C^d) % n

OTP Algorithm

Use Python’s secrets or random module to generate a 6-digit OTP.

Encrypt the OTP using RSA.

Send/display the encrypted OTP.

User decrypts and validates the OTP.

## 🧠 Learning Outcomes

Gained understanding of RSA encryption and decryption.

Learned how to generate and validate OTPs securely.

Understood how public-key cryptography ensures confidentiality.

Learned to integrate cryptographic logic into real-world authentication systems.

Developed awareness of cybersecurity practices in application development.

## 🚀 Future Enhancements

✅ Implement a Graphical User Interface (GUI) using Tkinter or Flask.

📧 Add Email or SMS OTP delivery using SMTP or third-party APIs.

🔒 Store user data using encrypted databases.

🔐 Integrate Multi-Factor Authentication (MFA) for enterprise-grade security.

☁️ Deploy on cloud platforms (e.g., AWS, Render, or Heroku).
