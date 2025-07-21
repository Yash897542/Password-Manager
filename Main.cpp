#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <limits>
#include <sstream>

// --- Global Data Structure ---
std::map<std::string, std::string> password_vault;

// --- Function Prototypes ---
void show_menu();
std::string get_master_password();
std::string encrypt_decrypt(const std::string& data, const std::string& key);
void add_password(const std::string& key);
void get_password(const std::string& key);
void list_all_services();
bool load_vault(const std::string& filename, const std::string& key);
void save_vault(const std::string& filename, const std::string& key);

// --- Main Application Logic ---
int main() {
    const std::string vault_file = "vault.dat";
    std::cout << "--- C++ Console Password Manager ---" << std::endl;
    
    std::string master_key = get_master_password();

    if (!load_vault(vault_file, master_key)) {
        std::cerr << "Failed to load vault. Incorrect password or vault is corrupted." << std::endl;
        return 1;
    }

    int choice = 0;
    while (choice != 4) {
        show_menu();
        std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            choice = 0;
        } else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        switch (choice) {
            case 1:
                add_password(master_key);
                break;
            case 2:
                get_password(master_key);
                break;
            case 3:
                list_all_services();
                break;
            case 4:
                save_vault(vault_file, master_key);
                std::cout << "Vault saved. Exiting." << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
    }

    return 0;
}

// --- Function Implementations ---

void show_menu() {
    std::cout << "\n--- Main Menu ---" << std::endl;
    std::cout << "1. Add a new password" << std::endl;
    std::cout << "2. Retrieve a password" << std::endl;
    std::cout << "3. List all services" << std::endl;
    std::cout << "4. Save and Exit" << std::endl;
    std::cout << "Enter your choice: ";
}

std::string get_master_password() {
    std::cout << "Enter your master password: ";
    std::string pass;
    std::getline(std::cin, pass);
    if (pass.empty()) {
        std::cout << "Password cannot be empty. Using 'default'." << std::endl;
        return "default";
    }
    return pass;
}

// Simple XOR encryption/decryption function
std::string encrypt_decrypt(const std::string& data, const std::string& key) {
    std::string output = data;
    for (size_t i = 0; i < data.size(); ++i) {
        output[i] = data[i] ^ key[i % key.length()];
    }
    return output;
}

void add_password(const std::string& key) {
    std::string service, password;
    std::cout << "Enter service name (e.g., google.com): ";
    std::getline(std::cin, service);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    password_vault[service] = password;
    std::cout << "Password for '" << service << "' added." << std::endl;
}

void get_password(const std::string& key) {
    std::string service;
    std::cout << "Enter service name to retrieve password: ";
    std::getline(std::cin, service);
    if (password_vault.count(service)) {
        std::cout << "Password for '" << service << "': " << password_vault[service] << std::endl;
    } else {
        std::cout << "No password found for '" << service << "'." << std::endl;
    }
}

void list_all_services() {
    if (password_vault.empty()) {
        std::cout << "\nYour vault is empty." << std::endl;
        return;
    }
    std::cout << "\n--- Services in Vault ---" << std::endl;
    for (const auto& pair : password_vault) {
        std::cout << "- " << pair.first << std::endl;
    }
}

bool load_vault(const std::string& filename, const std::string& key) {
    std::ifstream infile(filename);
    if (!infile) {
        std::cout << "No vault file found. Starting a new one." << std::endl;
        // Add a magic string to verify the password later
        password_vault["_VAULT_CHECK_"] = "OK";
        return true;
    }

    std::stringstream buffer;
    buffer << infile.rdbuf();
    std::string encrypted_data = buffer.str();
    infile.close();

    std::string decrypted_data = encrypt_decrypt(encrypted_data, key);
    std::stringstream ss(decrypted_data);
    std::string line;

    // Clear the global vault before loading
    password_vault.clear();
    
    while (std::getline(ss, line)) {
        std::stringstream line_ss(line);
        std::string service, password;
        // Use a delimiter unlikely to be in a service name
        if (std::getline(line_ss, service, ':') && std::getline(line_ss, password)) {
            password_vault[service] = password;
        }
    }

    // Check if the vault was decrypted correctly
    if (password_vault.count("_VAULT_CHECK") && password_vault["VAULT_CHECK_"] == "OK") {
        std::cout << "Vault loaded successfully." << std::endl;
        return true;
    }
    
    return false; // Wrong password or corrupted file
}

void save_vault(const std::string& filename, const std::string& key) {
    std::stringstream ss;
    for (const auto& pair : password_vault) {
        ss << pair.first << ":" << pair.second << "\n";
    }

    std::string data_to_encrypt = ss.str();
    std::string encrypted_data = encrypt_decrypt(data_to_encrypt, key);

    std::ofstream outfile(filename);
    if (!outfile) {
        std::cerr << "Error: Could not save vault to file." << std::endl;
        return;
    }
    outfile << encrypted_data;
    outfile.close();
}
