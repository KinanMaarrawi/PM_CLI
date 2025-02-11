# Password Manager CLI

A simple command-line password manager written in C. It uses OpenSSL for AES encryption, SQLite for storage, and regex for password validation. I don't have any arduinos lying around or operating systems I feel like creating at the moment so I made this to learn C.

## Features

- Secure password storage using AES encryption
- SQLite database for persistent storage
- Password validation with regex
- Random password generator

## Requirements

- GCC (or any C compiler)
- OpenSSL
- SQLite3 library

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/KinanMaarrawi/PM_CLI
   cd PM_CLI
   ```
2. Install dependencies:
   ```sh
   sudo apt install libssl-dev libsqlite3-dev
   ```
3. Compile the program:
   ```sh
   gcc main.c -o pm_cli -lssl -lcrypto -lsqlite3
   ```

## Usage

Run the program:

```sh
./pm_cli
```

## Configuration

- Update `DB_NAME` in `main.c` to change the database file name.
- Modify `KEY_SIZE` for different AES encryption levels.
- Change `REGEX` to adjust password validation rules.

