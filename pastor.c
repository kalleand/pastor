#include <gcrypt.h>
#include <argtable2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define DEBUG 0
#define BUFFER_SIZE 16
#define KEY_SIZE 16 // We use 128-bit key.

char* key;

int algorithm = GCRY_CIPHER_BLOWFISH;
int mode = GCRY_CIPHER_MODE_ECB;
FILE* tmp_file;
struct arg_lit* generate;
struct arg_end* end;
struct arg_file* output_file;
struct arg_str* domain;
struct arg_str* import;

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
int read_commandline(int argc, char** argv)
{
    generate = arg_lit0("gG", "generate", "generate password");
    import = arg_str0("iI", "import", "PASSWORD", "password to import");
    domain = arg_strn(NULL, NULL, "DOMAIN", 1, 1, "domain");
    output_file = arg_filen(NULL, NULL, "DATABASE", 1, 1, "database");
    end = arg_end(20);
    void* argtable[] = {generate, import, domain, output_file, end};

    if (arg_nullcheck(argtable) != 0)
    {
        /* NULL entries were detected, some allocations must have failed */
        printf("Insufficient memory.\n");
        return 1;
    }
    if (arg_parse(argc, argv, argtable))
    {
        arg_print_syntaxv(stdout, argtable, " ");
        printf("\n");
        arg_print_errors(stdout, end,"myprog");
        return 1;
    }
    return 0;
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
    while ((c = getchar()) != '\n' && c != EOF && i < KEY_SIZE) {
        key[i++] = c;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    printf("\n");
    for(int it = 0; it < 1000; ++it)
    {
        gcry_md_hash_buffer(GCRY_MD_MD5, key, key, 16);
    }
    return 0;
}

int encrypt_database()
{
    gcry_cipher_hd_t hd;
    FILE* fpout;
    char* buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    int nr_bytes;

    fpout = fopen(output_file->filename[0], "w");
    rewind(tmp_file);

    gcry_cipher_open(&hd, algorithm, mode, 0);
    gcry_cipher_setkey(hd, key, 16);

    while(!feof(tmp_file))
    {
        nr_bytes = fread(buffer, 1, BUFFER_SIZE, tmp_file);
        if (!nr_bytes) break;
        while(nr_bytes < BUFFER_SIZE)
            buffer[nr_bytes++] = 0x0;
        gcry_cipher_encrypt(hd, buffer, BUFFER_SIZE, NULL, 0);
        fwrite(buffer, 1, BUFFER_SIZE, fpout);
    }

    gcry_cipher_close(hd);
    fclose(fpout);
    free(buffer);
    return 0;
}

int decrypt_database()
{
    gcry_cipher_hd_t hd;
    FILE* fpin;
    char* buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    int nr_bytes;

    fpin = fopen(output_file->filename[0], "r");

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
        fwrite(buffer, 1, bytes, tmp_file);
    }

    gcry_cipher_close(hd);
    fclose(fpin);
    free(buffer);
    return 0;
}

int generate_password()
{
    return 0;
}

int import_password()
{
    return 0;
}

int fetch_password()
{
    decrypt_database();
    rewind(tmp_file);
    char tmp_buffer[1024];
    char* dom;
    char* pass;
#if DEBUG
    printf("\n======\nFile contents:\n");
#endif
    while (fgets(tmp_buffer, 1024, tmp_file))
    {
        dom = strtok(tmp_buffer, " ");
        pass = strtok(NULL, " ");
#if DEBUG
        printf("\n<DEBUG> Domain: %s\n", dom);
        printf("<DEBUG> Password: %s\n", pass);
#endif
        if (!strcmp(dom, domain->sval[0]))
        {
            printf("Password: %s\n", pass);
        }
    }
#if DEBUG
    printf("======\n");
#endif
    return 0;
}

int main(int argc, char** argv)
{
    int return_status = EXIT_SUCCESS;
    if (read_commandline(argc, argv))
    {
        return EXIT_FAILURE;
    }

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

    // Create tmp_file. TODO: make implementation better.
    tmp_file = tmpfile();

    if (generate->count > 0)
    {
#if DEBUG
        printf("Generating new password for %s.\n", domain->sval[0]);
#endif
        if (generate_password())
        {
            return_status = EXIT_FAILURE;
        }
    }
    else if (import->count > 0)
    {
#if DEBUG
        printf("Importing password %s for %s.\n", import->sval[0], domain->sval[0]);
#endif
        if (import_password())
        {
            return_status = EXIT_FAILURE;
        }
    }
    else
    {
#if DEBUG
        printf("Fetching password for %s.\n", domain->sval[0]);
#endif
        if (fetch_password())
        {
            return_status = EXIT_FAILURE;
        }
    }

    free(key);
    fclose(tmp_file);
    key = NULL;

    return return_status;
}
