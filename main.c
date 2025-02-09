#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <regex.h>
#include <sqlite3.h>

#define KEY_SIZE 16               // AES-128 key size, change to 24 or 32 for AES-192 or AES-256 respectively
#define IV_SIZE 16                // AES block size is always 128 bits (16 bytes)
#define DB_NAME "pm_cli.db"       // DB name, change to your liking
#define REGEX "^[a-zA-Z0-9]{8,}$" // Regex pattern for password validation, change to your liking

// Function to get value from DB (master passcode, key, IV)
int get_from_db(sqlite3 *db, const char *table, const char *column, char *result)
{
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT %s FROM %s;", column, table);
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        strcpy(result, (char *)sqlite3_column_text(stmt, 0));
    }
    else
    {
        fprintf(stderr, "Failed to get value: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

// Function to create DB and tables (user accounts, key and iv)
sqlite3 *create_db()
{
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open(DB_NAME, &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    // Create tables
    char *sql = "CREATE TABLE IF NOT EXISTS Accounts ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "account_name TEXT NOT NULL, "
                "password BLOB NOT NULL, "
                "ciphertext_len INTEGER NOT NULL);"

                "CREATE TABLE IF NOT EXISTS Key_IV ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "key BLOB NOT NULL, "
                "iv BLOB NOT NULL, "
                "master_password TEXT NOT NULL);";

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return NULL;
    }

    // Check if key/IV/master password exists
    char *check_sql = "SELECT COUNT(*) FROM Key_IV;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    // If no key, IV, or master password, reset DB and generate new ones
    if (count == 0)
    {
        printf("No encryption key or master password found. Resetting database...\n");

        // Delete all records in both tables
        char *clear_sql = "DELETE FROM Accounts; DELETE FROM Key_IV;";
        sqlite3_exec(db, clear_sql, 0, 0, &err_msg);

        // Generate new key and IV
        unsigned char key[KEY_SIZE], iv[IV_SIZE];
        RAND_bytes(key, KEY_SIZE);
        RAND_bytes(iv, IV_SIZE);

        // Get master password from user
        char master_password[128];
        printf("Enter a new master password: ");
        fgets(master_password, sizeof(master_password), stdin);
        master_password[strcspn(master_password, "\n")] = 0; // Remove newline

        // Insert new key, IV, and master password
        char *insert_sql = "INSERT INTO Key_IV (key, iv, master_password) VALUES (?, ?, ?);";
        sqlite3_stmt *insert_stmt;
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, 0);

        if (rc != SQLITE_OK)
        {
            fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return NULL;
        }

        sqlite3_bind_blob(insert_stmt, 1, key, KEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_blob(insert_stmt, 2, iv, IV_SIZE, SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt, 3, master_password, -1, SQLITE_STATIC);

        rc = sqlite3_step(insert_stmt);
        if (rc != SQLITE_DONE)
        {
            fprintf(stderr, "Failed to insert key & IV: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(insert_stmt);
            sqlite3_close(db);
            return NULL;
        }

        sqlite3_finalize(insert_stmt);
        printf("New key, IV, and master password set successfully.\n");
    }

    return db;
}

// Encryption function
int aes_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx; // context structrure to store all encryption info
    int len;             // temp variable to store length of ciphertext
    int ciphertext_len;  // final length of ciphertext

    // create and initialize context for encryption
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        perror("EVP_CIPHER_CTX failed!");
        return -1;
    }

    // initialize encryption with AES-128
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        perror("EVP_EncryptInit_ex failed");
        return -1;
    }

    // encrypt the plain text
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext)))
    {
        perror("EVP_EncryptUpdate failed");
        return -1;
    }
    ciphertext_len = len; // Store the length of the encrypted data

    // finalise the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        perror("EVP_EncryptFinal_ex failed");
        return -1;
    }
    ciphertext_len += len; // Add padding length to the total ciphertext length

    // clean up after were done with encryption
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Decryption function
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        perror("EVP_DecryptInit_ex failed");
        return -1;
    }

    // Fix: Use ciphertext_len instead of strlen(ciphertext)
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        perror("EVP_DecryptUpdate failed");
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        perror("EVP_DecryptFinal_ex failed");
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function to validate user input for password based on regex pattern
int validate_input(const char *input, const char *pattern)
{
    regex_t regex;
    int result;

    result = regcomp(&regex, pattern, REG_EXTENDED);
    if (result != 0)
    {
        printf("Could not compile regex!");
        return -1;
    }

    result = regexec(&regex, input, 0, NULL, 0);
    if (result != 0)
    {
        printf("Input does not match requirements.\n");
        return -1;
    }

    regfree(&regex);
    return (result == 0);
}

int display_accounts(sqlite3 *db, unsigned char *key, unsigned char *iv)
{
    unsigned char decryptedtext[128]; // Buffer for decrypted data

    char *sql = "SELECT id, account_name, password, ciphertext_len FROM Accounts;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    rc = sqlite3_step(stmt);
    while (rc == SQLITE_ROW)
    {
        int ciphertext_len = sqlite3_column_int(stmt, 3);
        int decryptedtext_len = aes_decrypt((unsigned char *)sqlite3_column_blob(stmt, 2), ciphertext_len, key, iv, decryptedtext);
        if (decryptedtext_len == -1)
        {
            fprintf(stderr, "Decryption failed\n");
            return 1;
        }
        decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text

        printf("ID: %d\nAccount name: %s\nDecrypted Password: %s\n",
               sqlite3_column_int(stmt, 0),
               sqlite3_column_text(stmt, 1),
               decryptedtext);
        rc = sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);
    return 0;
}

int display_specific(sqlite3 *db, unsigned char account_name) {}

// Function to add account to DB
int add_account(unsigned char account_name[128], unsigned char password[128], sqlite3 *db)
{
    unsigned char key[KEY_SIZE], iv[IV_SIZE], ciphertext[128];
    get_from_db(db, "Key_IV", "key", key);
    get_from_db(db, "Key_IV", "iv", iv);

    // Encrypt the plaintext
    int ciphertext_len = aes_encrypt(password, key, iv, ciphertext);
    if (ciphertext_len == -1)
    {
        return 1;
    }

    // insert account into db
    char *sql = "INSERT INTO Accounts (account_name, password, ciphertext_len) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, (char *)account_name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, ciphertext, ciphertext_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, ciphertext_len);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    printf("Password encrypted successfully.\n");
    printf("Account name: %s\nPassword: %s\n", account_name, password);
    sqlite3_finalize(stmt);

    printf("\n");
    return 0;
}

int delete_account(unsigned char account_name[128], unsigned char master[128], sqlite3 *db) {
    // get master passcode from user, if correct search through accounts table for matching account_name, if found delete it

}

// Function to delete DB file (Nuke)
int nuke()
{
    if (remove(DB_NAME) == 0)
    {
        printf("File %s deleted successfully.\n", DB_NAME);
        exit(0);
    }
    else
    {
        printf("Error deleting file %s.\n", DB_NAME);
    }
    return 0;
}

int main()
{
    // define variables
    const char *pattern = REGEX;

    unsigned char master[128], key[KEY_SIZE], iv[IV_SIZE];
    char master_input[16];

    int user_input;

    // Create DB and get master password
    sqlite3 *db = create_db();
    get_from_db(db, "Key_IV", "master_password", master);
    get_from_db(db, "Key_IV", "key", key);
    get_from_db(db, "Key_IV", "iv", iv);

    // Get master password from user
    printf("Enter master password to access. Enter q to quit.\n");
    do
    {
        scanf("%s", master_input);
        if (strcmp(master_input, "q") == 0)
        {
            printf("Exiting...\n");
            exit(0);
        }

        if (strcmp(master_input, master) != 0)
        {
            printf("Incorrect. Try again. Enter q to quit.\n");
        }

    } while (strcmp(master, master_input) != 0);

    // Main menu
    printf("Welcome to the PM_CLI by kinan.\n");

    do
    {
        printf("\n1. Add new account\n2. Manage existing accounts\n3. Nuke\n4. Quit\n");
        printf("Enter choice:\n");
        scanf("%d", &user_input);

        switch (user_input)
        {
        case 1:
            unsigned char account_name[128], password[128];

            printf("Enter account name:\n");
            do
            {
                fgets(account_name, sizeof(account_name), stdin);

                // Remove newline character from fgets input if it exists
                account_name[strcspn((char *)account_name, "\n")] = '\0';

            } while (account_name[0] == '\0');

            printf("Enter password:\n");
            do
            {
                fgets(password, sizeof(password), stdin);

                // Remove newline character from fgets input if it exists
                password[strcspn((char *)password, "\n")] = '\0';

            } while (validate_input(password, pattern) != 1);
            add_account(account_name, password, db);
            break;
        case 2:
            display_accounts(db, key, iv);
            break;
        case 3:
            nuke();
            break;
        case 4:
            exit(0);
        default:
            printf("Invalid input. Please enter a choice from 1-4.\n");
        }
    } while (user_input != 4);

    sqlite3_close(db);
    return 0;

    /*
    unsigned char decryptedtext[128]; // Buffer for decrypted data

    // Decrypt the ciphertext
    int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    if (decryptedtext_len == -1)
    {
        return 1;
    }

    // Null-terminate the decrypted text (make it a valid C string)
    decryptedtext[decryptedtext_len] = '\0';

    // Print the decrypted data
    printf("Decrypted text is: %s\n", decryptedtext);
    */
}

/*
    // Print the encrypted data in hexadecimal format
    printf("Encrypted text is:\n");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x ", ciphertext[i]); // Print each byte in hex format
    }
    */