# Passman: A Secure Rust CLI Password Manager

*This Rust CLI application helps you securely store and manage your passwords.*

## Features

* **Secure Password Storage:**  Passwords are encrypted using a strong algorithm and protected by a master password.
* **Easy to Use:**  Simple and intuitive command-line interface.
* **Cross-Platform:** Works on any system with Rust and SQLite installed.
* **Multiple Options for Adding Passwords:** Generate passwords, import from files, or manually enter them.
* **Backup and Restore:**  Easily create backups and restore your password database.

## Requirements

* Rust
* SQLite

## Installation

```sh

    git clone https://github.com/leonardo-luz/rust-passman-cli.git
    cd rust-passman-cli
    cargo install --path .
    ## Add the cargo build path to your PATH variable, (~/.cargo/bin for linux)

```

## Usage

Passman uses a master password for decryption for each password. This password is never stored directly; only its encrypted derivative is saved. You will be prompted for it securely whenever decryption is necessary.

**Adding Passwords:**

* `passman add --service <SERVICE_NAME>`: Adds a new password entry.  You will be prompted for the password securely.
* `passman add --service <SERVICE_NAME> --description "<DESCRIPTION>"`: Adds a new password with an optional description.
* `passman add --service <SERVICE_NAME> --generate-password`: Generates a strong, random password for the service.
* `passman add --service <SERVICE_NAME> --secret <PASSWORD>`:  Use with caution! This will directly store the provided password.  **Avoid this unless importing from a trusted source.**
* `passman add --service <SERVICE_NAME> --secret @/PATH/TO/YOUR/PASSWORD/FILE`: Reads the password from the specified file.  This file should contain only the password.


**Managing Passwords:**

* `passman list`: Lists all stored passwords (decrypted after master password authentication).
* `passman get --service <SERVICE_NAME>`: Retrieves the password for the specified service (decrypted after master password authentication).
* `passman delete --id <PASSWORD_ID>`: Deletes the password with the given ID (requires master password).  The ID is shown in the output of `passman list`.
* `passman update --id <PASSWORD_ID>`:  Updates the password associated with the given ID (requires master password).


**Backup and Restore:**

* `passman save`: Creates an encrypted backup of your password database. You'll be prompted for your master password to encrypt the backup.
* `passman load`: Loads and decrypts a previously saved backup.  You'll need to provide the master password.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

[MIT License](./LICENSE.md)
