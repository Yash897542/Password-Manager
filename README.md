# Password-Manager
Password manager
# C++ Console Password Manager 🔐

A simple, command-line based password manager written in C++. It allows you to store and retrieve passwords for different services, all saved in a single encrypted file protected by a master password.

This project showcases C++ skills such as file I/O, data structures (`std::map`), string manipulation, and fundamental encryption concepts.

## Features
-   **Master Password Protection:** The entire vault is encrypted with a single master password.
-   **Add & Retrieve:** Easily add new service passwords and look them up later.
-   **List Services:** View all the services you have saved in your vault.
-   **Encrypted Storage:** All data is encrypted using a simple XOR cipher before being saved to a local file (`vault.dat`
