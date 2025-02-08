#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <regex.h>

// encryption function
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

int access_accounts() {}

int add_account() {}

int delete_account() {}

int nuke() {}

int main()
{
    unsigned char key[16];
    unsigned char iv[16];

    const char master[] = "Dam812";
    char master_input[16];

    const char *pattern = "^[a-zA-Z0-9]{8,}$";

    int user_input;

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

    printf("Welcome to the PM_CLI by kinan. Please enter your choice on what you would like to do:\n");
    printf("1. Add new account\n2. Manage existing accounts\n3. Nuke\n");
    scanf("%d", &user_input);

    switch (user_input)
    {
    case 1:

    case 2:
    case 3:
    default:
    };

    if (1 != RAND_bytes(key, sizeof(key)))
    { // Securely generate a random key
        perror("RAND_bytes failed for key");
        return 1;
    }
    if (1 != RAND_bytes(iv, sizeof(iv)))
    { // Securely generate a random IV
        perror("RAND_bytes failed for IV");
        return 1;
    }

    unsigned char plaintext[128];
    printf("Enter what's to be encrypted: (Please enter at least 8 characters, one of them being a number.)\n");
    do
    {
        fgets(plaintext, sizeof(plaintext), stdin);

        // Remove newline character from fgets input if it exists
        plaintext[strcspn((char *)plaintext, "\n")] = '\0';

    } while (validate_input(plaintext, pattern) != 1);

    unsigned char ciphertext[128]; // Buffer for the encrypted text

    // Encrypt the plaintext
    int ciphertext_len = aes_encrypt(plaintext, key, iv, ciphertext);
    if (ciphertext_len == -1)
    {
        return 1;
    }

    // Print the encrypted data in hexadecimal format
    printf("Encrypted text is:\n");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x ", ciphertext[i]); // Print each byte in hex format
    }
    printf("\n");

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
}
