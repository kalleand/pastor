#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define DEBUG 1
#define BUFFER_SIZE 16
#define KEY_SIZE 16 // We use 128-bit key.

char* key;

/**
 * Initializes the libgcrypt library.
 *
 * Returns 0 on sucess and 1 on error.
 */
int init_libgcrypt()
{
    gcry_error_t error;

    if (!gcry_check_version(GCRYPT_VERSION))
    {
        fprintf(stderr, "Incompatible version of libgcrypt.\n");
        return 1;
    }

    error = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    if (error)
    {
        fprintf(stderr,
                "Could not disable secure memory.\nError string: '%s'\n",
                gcry_strerror(error));
        return 1;
    }
    error = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (error)
    {
        fprintf(stderr,
                "Could not finish initializing memory.\nError string: '%s'\n",
                gcry_strerror(error));
        return 1;
    }
    return 0;
}

/**
 * Reads commandline options given.
 */
int read_options(int argc, char** argv)
{
    return 1;
}

int get_key()
{
    struct termios oldt, newt;
    int i = 0;
    int c;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    printf("Enter key: ");
    while ((c = getchar()) != '\n' && c != EOF && i < KEY_SIZE - 1) {
        key[i++] = c;
    }
    key[i] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    printf("\n");
    for(int it = 0; it < 1000; ++it)
    {
        gcry_md_hash_buffer(GCRY_MD_MD5, key, key, 16);
    }
    return 0;
}

int encrypt(int algorithm, int mode, char* in, char* out)
{
    gcry_cipher_hd_t hd;
    FILE* fpin;
    FILE* fpout;
    char* buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    int nr_bytes;

    fpin = fopen(in, "r");
    fpout = fopen(out, "w");

    gcry_cipher_open(&hd, algorithm, mode, 0);
    gcry_cipher_setkey(hd, key, 16);

    while(!feof(fpin))
    {
        nr_bytes = fread(buffer, 1, BUFFER_SIZE, fpin);
        if (!nr_bytes) break;
        while(nr_bytes < BUFFER_SIZE)
            buffer[nr_bytes++] = 0x0;
        gcry_cipher_encrypt(hd, buffer, BUFFER_SIZE, NULL, 0);
        fwrite(buffer, 1, BUFFER_SIZE, fpout);
    }

    gcry_cipher_close(hd);
    fclose(fpin);
    fclose(fpout);
    free(buffer);
    return 0;
}

int decrypt(int algorithm, int mode, char* in, char* out)
{
    gcry_cipher_hd_t hd;
    FILE* fpin;
    FILE* fpout;
    char* buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    int nr_bytes;

    fpin = fopen(in, "r");
    fpout = fopen(out, "w");

    gcry_cipher_open(&hd, algorithm, mode, 0);
    gcry_cipher_setkey(hd, key, 16);

    while(!feof(fpin))
    {
        nr_bytes = fread(buffer, 1, BUFFER_SIZE, fpin);
        if (!nr_bytes) break;
        gcry_cipher_decrypt(hd, buffer, BUFFER_SIZE, NULL, 0);
        int bytes;
        for(bytes = 0; bytes < BUFFER_SIZE; bytes++)
        {
            if(buffer[bytes] == 0) break;
        }
        fwrite(buffer, 1, bytes, fpout);
    }

    gcry_cipher_close(hd);
    fclose(fpin);
    fclose(fpout);
    free(buffer);
    return 0;
}
/**
 * Main.
 */
int main(int argc, char** argv)
{
    int algorithm = GCRY_CIPHER_BLOWFISH;
    int mode = GCRY_CIPHER_MODE_ECB;

#if DEBUG
    printf("Starting execution.\n");
#endif

    if (init_libgcrypt())
    {
        return EXIT_FAILURE;
    }

    key = malloc(sizeof(char) * 16);
    memset(key, 0, KEY_SIZE);
    if (get_key())
    {
        fprintf(stderr, "Could not get the key.\n");
    }

    if (encrypt(algorithm, mode, "pass.db", "encrypted"))
    {
        fprintf(stderr, "Failed to encrypt the file.\n");
    }
    if (decrypt(algorithm, mode, "encrypted", "decrypted"))
    {
        fprintf(stderr, "Failed to decrypt the file.\n");
    }

    free(key);
    key = NULL;

    return EXIT_SUCCESS;
}
