# AegisAuth – Privilege-Separated Authentication Framework

## Overview

AegisAuth is a UNIX-based privilege-separated authentication framework developed in C. The project demonstrates secure authentication by separating privileged operations from untrusted user input, following the Principle of Least Privilege.

The system consists of two independent processes:

- **Frontend** – Handles user interaction and forwards authentication requests.
- **Backend** – Loads the protected credential database, performs password verification, and permanently drops root privileges after initialization.

Communication between both processes is implemented using UNIX Domain Sockets.

---

## Features

- Privilege-separated architecture
- UNIX Domain Socket IPC
- SHA-512 password hashing using `crypt()`
- Root-only credential database
- Permanent privilege dropping
- Constant-time password comparison
- Password memory wiping using `explicit_bzero()`
- Secure authentication workflow
- Linux compatible

---

## Project Structure

```
AegisAuth/
│── Backend.c
│── Frontend.c
│── common.h
│── makefile
│── README.md
└── secrets.db (generated locally)
```

---

## Requirements

- Kali Linux or any Linux distribution
- GCC
- GNU Make
- libcrypt-dev

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential libcrypt-dev
```

---

## Build

Compile the project:

```bash
make
```

Clean previous builds:

```bash
make clean
```

---

## Creating a User

Create a new user in the credential database:

```bash
sudo ./Backend adduser jewel password123
```

Passwords are stored as SHA-512 hashes.

---

## Running

Start the authentication service:

```bash
sudo ./Frontend
```

Example:

```
Username: jewel
Password: password123

Access Granted
```

Incorrect password:

```
Access Denied
```

---

## Security Features

- Principle of Least Privilege
- Process Isolation
- Root-only credential storage
- Permanent privilege dropping
- Constant-time password verification
- Password wiping from memory
- Secure UNIX IPC communication

---

## Technologies Used

- C Programming
- UNIX Domain Sockets
- Linux System Programming
- POSIX APIs
- GNU Make
- SHA-512 Crypt Library

---

## Author

**Jewel Thapa**

Coventry University  
BSc (Hons) Ethical Hacking and Cyber Security

---

## License

This project was developed for academic purposes.
