# JavaBased-password-manager

It is a secure password manager built using **Java Swing** for the GUI, **MySQL** for backend storage, and **Java Cryptography** for encryption/decryption. It allows users to generate strong passwords, encrypt/decrypt text, and store, retrieve, or delete passwords securely from a MySQL database.

---

## 🧠 Features

- 🔐 **Encrypt & Decrypt** passwords using PBEWithMD5AndDES
- 🧾 **Store passwords** in a MySQL database
- 🔍 **Search saved passwords** by account name
- ❌ **Delete saved passwords**
- ⚙️ **Generate strong passwords** with uppercase, lowercase, digits & special characters
- 🖼️ **User-friendly GUI** built using Java Swing

---

## 📁 Project Structure

- `LockBox.java` – Main GUI class and program entry point
- `HashtablePassword.java` – Custom hash table implementation (Linear Probing)
- `CryptoUtil.java` – Handles encryption and decryption
- `PasswordGenerator.java` – Random password generator
- `hashTableMap.java` – Interface for the custom hash table

---

## 🖼️ Screenshots

> Add GUI screenshots here once available

---

## 💻 Requirements

- Java JDK 8 or above
- MySQL Server
- IntelliJ IDEA / Eclipse or any Java IDE
- JDBC Driver for MySQL (Connector/J)

---

## 🛠️ Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/LockBox-Java.git
   cd LockBox-Java
