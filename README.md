# CryptKVS: Encrypted Key-Value Store

## Overview

CryptKVS is a simplified implementation of a **secure value recovery** system, inspired by Signal's protocol. This project demonstrates how to build a secure, encrypted key-value store for managing sensitive data in the cloud. The focus is on system programming in **C**, including  cryptographic operations, client-server communication, and secure file handling.

## Features

### Core Functionality
- **Encrypted Key-Value Storage**: Each entry consists of a key, a password, and an encrypted value.
- **Key-Based Decryption**: Allows users to retrieve values using a combination of key and password.
- **Key Creation**: Supports generating new keys dynamically with associated values.
- **Metadata Management**: Provides utilities for listing metadata and database statistics.

### Security Design
The project implements a protocol similar to Signal's **Secure Value Recovery**, including:
- Key derivation using HMAC-SHA256 with unique inputs.
- Randomized entropy (`c2`) for strengthening cryptographic keys.
- Symmetric encryption for secure storage of secrets.

### Client-Server Model
- **HTTP-based Communication**: Exposes functionality via a web server.
- **HTTPS Support**: Uses `libmongoose` for server-side operations and `libcurl` for the client.
- **Dynamic Interaction**: Clients can read, write, and manage data over a secure connection.

### Cryptographic Tools
- Uses the `openssl` library for hashing and encryption.
- Implements secure key stretching and HMAC-based key derivation.

## Implementation Details

1. **Database Management**:
   - A single database file stores metadata and encrypted secrets.
   - Keys are stored in plaintext, while values are encrypted for security.
   
2. **Command-Line Utility**:
   - Provides commands for creating, retrieving, and managing entries in the database.
   - Outputs clear diagnostics for debugging and usage.

3. **Web Server**:
   - A REST-like interface for accessing the encrypted key-value store.
   - Implements commands for reading, writing, and managing entries over HTTPS.


I have completed this project as part of CS-212 at EPFL.
