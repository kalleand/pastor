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
#define VERSION "0.1-dev"

char* key;
int algorithm = GCRY_CIPHER_BLOWFISH;
int mode = GCRY_CIPHER_MODE_ECB;
FILE* tmp_file;
struct arg_lit* generate;
struct arg_lit* help;
struct arg_lit* version;
struct arg_lit* create_new;
struct arg_end* end;
struct arg_file* output_file;
struct arg_str* domain;
struct arg_str* import;

/**
 * Initializes the libgcrypt library.
 *
 * Returns 0 on success and 1 on error.
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
 * Prompts the user for the key to decrypt the database.
 */
int get_key()
{
    struct termios oldt, newt;
    int i = 0;
    int c;

    key = malloc(sizeof(char) * 16);
    memset(key, 0, KEY_SIZE);

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    printf("Enter key: ");
    while ((c = getchar()) != '\n' && c != EOF && i < KEY_SIZE)
    {
        key[i++] = c;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    printf("\n");
    for (int it = 0; it < 1000; ++it)
    {
        gcry_md_hash_buffer(GCRY_MD_MD5, key, key, 16);
    }
    return 0;
}

/**
 * Encrypts the database specified with the key. Reads from the tmp_file and
 * writes to the database.
 */
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

    while (!feof(tmp_file))
    {
        memset(buffer, 0, BUFFER_SIZE);
        nr_bytes = fread(buffer, 1, BUFFER_SIZE, tmp_file);
        if (!nr_bytes)
        {
            break;
        }
        gcry_cipher_encrypt(hd, buffer, BUFFER_SIZE, NULL, 0);
        fwrite(buffer, 1, BUFFER_SIZE, fpout);
    }

    gcry_cipher_close(hd);
    fclose(fpout);
    free(buffer);
    return 0;
}

/**
 * Decrypts the database and stores it in plain_text in the tmp_file.
 */
int decrypt_database()
{
    gcry_cipher_hd_t hd;
    FILE* fpin;
    char* buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    int nr_bytes;

    fpin = fopen(output_file->filename[0], "r");
    if (!fpin)
    {
        printf("Database does not exist.\n");
        return 1;
    }

    gcry_cipher_open(&hd, algorithm, mode, 0);
    gcry_cipher_setkey(hd, key, 16);

    while (!feof(fpin))
    {
        nr_bytes = fread(buffer, 1, BUFFER_SIZE, fpin);
        if (!nr_bytes)
        {
            break;
        }
        gcry_cipher_decrypt(hd, buffer, BUFFER_SIZE, NULL, 0);
        int bytes;
        for (bytes = 0; bytes < BUFFER_SIZE; bytes++)
        {
            if (buffer[bytes] == 0) break;
        }
        fwrite(buffer, 1, bytes, tmp_file);
    }

    gcry_cipher_close(hd);
    fclose(fpin);
    free(buffer);
    return 0;
}

/**
 * Each database should have a header row where the first word should be
 * "pastor" followed by a space and then a random number. The random number
 * ensures a different encrypted value for each database - even when they are
 * empty.
 */
int check_valid_key()
{
    rewind(tmp_file);
    char tmp_buffer[1024];
    fgets(tmp_buffer, 1024, tmp_file);
    strtok(tmp_buffer, " ");
    if (strcmp(tmp_buffer, "pastor"))
    {
        return 1;
    }
    rewind(tmp_file);
    return 0;
}

/**
 * Generates a new password for the specified domain.
 *
 * NOT YET IMPLEMENTED.
 */
int generate_password()
{
    printf("Not yet implemented.\n");
    return 1;
}

/**
 * Imports a password to the database.
 */
int import_password()
{
    int bytes;
    char buffer[1024];
    if (decrypt_database())
    {
        return 1;
    }
    sprintf(buffer, "\n%s %s", domain->sval[0], import->sval[0]);
    for (bytes = 0; bytes < 1024; bytes++)
    {
        if (buffer[bytes] == 0) break;
    }
    fwrite(buffer, 1, bytes, tmp_file);
    if (check_valid_key())
    {
        printf("Wrong key for database.\n");
        return 1;
    }

    if (encrypt_database())
    {
        printf("Could not encrypt database.\n");
        return 1;
    }
    return 0;
}

/**
 * Retrieves the password for the domain specified by the options to the
 * program.
 */
int fetch_password()
{
    char tmp_buffer[1024];
    char* dom;
    char* pass;
    int found = 0;

    if (decrypt_database())
    {
        return 1;
    }

    if (check_valid_key())
    {
        printf("Wrong key for the database.\n");
        return 1;
    }
    // Skip first row.
    fgets(tmp_buffer, 1024, tmp_file);
#if DEBUG
    printf("\n======\nFile contents:\n");
#endif
    while (fgets(tmp_buffer, 1024, tmp_file))
    {
        dom = strtok(tmp_buffer, " ");
        pass = strtok(NULL, " ");

        // Removes the newline.
        for (int i = 0; i < 512; ++i)
        {
            if (pass[i] == '\n')
            {
                pass[i] = 0;
                break;
            }
            else if (pass[i] == 0)
            {
                break;
            }
        }

#if DEBUG
        printf("\n<DEBUG> Domain: %s\n", dom);
        printf("<DEBUG> Password: %s\n", pass);
#endif
        if (!strcmp(dom, domain->sval[0]))
        {
            found = 1;
            break;
        }
    }
#if DEBUG
    printf("======\n");
#endif
    if (found)
    {
        printf("Password: %s\n", pass);
    }
    else
    {
        printf("Could not find password.\n");
    }
    return 0;
}

/**
 * Creates a new empty database with a correct header.
 */
int create_new_database()
{
    int bytes;
    char buffer[1024];
    srand(time(NULL));
    int random = rand();

    sprintf(buffer, "%s %d", "pastor", random);

    for (bytes = 0; bytes < 1024; bytes++)
    {
        if (buffer[bytes] == 0) break;
    }

    fwrite(buffer, 1, bytes, tmp_file);
    if (encrypt_database())
    {
        return 1;
    }

    return 0;
}

/**
 * Main method. Parses input and then executes the desired action by passing to
 * appropriate method.
 */
int main(int argc, char** argv)
{
    int return_status = EXIT_SUCCESS;

    version     = arg_lit0(NULL, "version", "print version");
    help        = arg_lit0("hH", "help", "print help");
    create_new  = arg_lit0("cC", "create", "create new database");
    generate    = arg_lit0("gG", "generate", "generate password");
    import      = arg_str0("iI", "import", "PASSWORD", "import password");
    output_file = arg_file0(NULL, NULL, "DATABASE", "database");
    domain      = arg_str0(NULL, NULL, "DOMAIN", "domain");
    end         = arg_end(20);

    void* argtable[] = {version, help, create_new, generate, import,
        output_file, domain, end};

    if (init_libgcrypt())
    {
        return_status = EXIT_FAILURE;
    }
    else if (arg_nullcheck(argtable))
    {
        printf("Insufficient memory.\n");
        return_status = EXIT_FAILURE;
    }
    else if (arg_parse(argc, argv, argtable))
    {
        arg_print_syntaxv(stdout, argtable, " ");
        printf("\n");
        arg_print_errors(stdout, end, "pastor");
        return_status = EXIT_FAILURE;
    }
    else if (help->count > 0)
    {
        printf("Synopsis:\n");
        arg_print_syntaxv(stdout, argtable, " ");
        printf("\n\n");
        arg_print_glossary(stdout, argtable, " %-25s %s\n");
        return_status = EXIT_SUCCESS;
    }
    else if (version->count > 0)
    {
        printf("Pastor version %s.\n", VERSION);
        return_status = EXIT_SUCCESS;
    }
    else if (generate->count > 0 && output_file->count > 0 &&
            domain->count > 0)
    {
#if DEBUG
        printf("Generating new password for %s.\n", domain->sval[0]);
#endif
        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        tmp_file = tmpfile();

        if (generate_password())
        {
            return_status = EXIT_FAILURE;
        }
        fclose(tmp_file);
        free(key);
        key = NULL;
    }
    else if (import->count > 0 && output_file->count > 0 &&
            domain->count > 0)
    {
#if DEBUG
        printf("Importing password %s for %s.\n", import->sval[0],
                domain->sval[0]);
#endif
        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        tmp_file = tmpfile();

        if (import_password())
        {
            return_status = EXIT_FAILURE;
        }
        fclose(tmp_file);
        free(key);
        key = NULL;
    }
    else if (create_new->count > 0 && output_file->count > 0)
    {
        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        tmp_file = tmpfile();

        if (create_new_database())
        {
            return_status = EXIT_FAILURE;
        }

        fclose(tmp_file);
        free(key);
        key = NULL;
    }
    else if (output_file->count > 0 && domain->count > 0)
    {
#if DEBUG
        printf("Fetching password for %s.\n", domain->sval[0]);
#endif
        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        tmp_file = tmpfile();

        if (fetch_password())
        {
            return_status = EXIT_FAILURE;
        }

        fclose(tmp_file);
        free(key);
        key = NULL;
    }
    else
    {
        printf("Could not find the desired action.\n");
        printf("Synopsis:\n");
        arg_print_syntaxv(stdout, argtable, " ");
        printf("\n\n");
        arg_print_glossary(stdout, argtable, " %-25s %s\n");
        return_status = EXIT_FAILURE;
    }

    arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));

    return return_status;
}
