#include <gcrypt.h>
#include <argtable2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define DEBUG 1
#define BUFFER_SIZE 16
#define KEY_SIZE 16 // We use 128-bit key.
#define VERSION "0.1-dev"
#define MIN_LENGTH 48
#define MAX_LENGTH 64

// The key which are used for symmetrical encryption/decryption
char* key;

// Blow fish to maybe provide editing via vim
// TODO: Make this changeable.
int algorithm = GCRY_CIPHER_BLOWFISH;
int mode = GCRY_CIPHER_MODE_ECB;
FILE* tmp_file;

// Here follows the input arguments that are provided by the user.
//
// The reason we define them here is that this way we can use them in all
// methods. (Was specified in the library as an example use case.)
struct arg_lit* generate;
struct arg_lit* help;
struct arg_lit* version;
struct arg_lit* create_new;
struct arg_end* end;
struct arg_file* output_file;
struct arg_str* domain;
struct arg_str* import;
struct arg_str* allowed_special_characters;
struct arg_int* min;
struct arg_int* max;
struct arg_int* number_of_uppercase;
struct arg_int* number_of_lowercase;
struct arg_int* number_of_digits;
struct arg_int* number_of_special_characters;

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

    key = (char*) malloc(sizeof(char) * 16);
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
    char* buffer = (char*) malloc(BUFFER_SIZE);
    int nr_bytes = 0;
    memset(buffer, 0, BUFFER_SIZE);

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
    char* buffer = (char*) malloc(BUFFER_SIZE);
    int nr_bytes = 0;
    memset(buffer, 0, BUFFER_SIZE);

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
int generate_password(int min_size,
        int max_size,
        int number_of_uppercase,
        int number_of_lowercase,
        int number_of_digits,
        int number_of_special_characters,
        int len_of_special_chars,
        char* input_special_characters)
{
    srand(time(NULL));

    // Planning.
    //
    // Define the allowed characters.
    //  * a-zA-Z0-9 - are given
    //  * !"#$%&/()[]={}?+-_'`^~'*@£€ - should be alright
    //  * åäöÅÄÖéèíìÌÍÈÉ - now it's getting fishy.
    //  TODO: Find all the characters allowed in passwords.
    //  TODO: Implement a way to set a maximum and minimum size of password.
    //        ^ Through flags e.g. -min=8 -max=16
    //  TODO: Implement a way to specify which characters are allowed.
    //        ^ This should be done through flags.
    //          e.g. -nodigits -nospecial
    //  TODO: Ensure that there are certain number of digits, uppercase,
    //        lowercase, and/or special characters
    //
    //  Then we construct a loop that iterates through an array with all the
    //  characters that are allowed and randomize which password we generate.
    //  TODO: How to get random data in a secure way? Does it matter _that_ much
    //        if we use rand() as this happens once when the user requests it?
    //        How do we seed the randomizer if that is the case?
    char valid_characters[256];
    char special_characters[256];
    if (len_of_special_chars == -1)
    {
        strcpy(special_characters, "[](){}~&\"!?%/");
    }
    else if (len_of_special_chars < 256)
    {
        strcpy(special_characters, input_special_characters);
    }
    else
    {
        fprintf(stderr, "Too long array of special characters.\n");
    }

    strcpy(valid_characters, "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789");
    strcat(valid_characters, special_characters);

    int a = number_of_digits;
    a = number_of_uppercase;
    a = number_of_lowercase;
    a = number_of_special_characters;

    int password_length = max_size - min_size;
    password_length = min_size + (rand() % password_length);


    // Find the length pf the valid characters  through iterating until '\0' is found.
    int length = -1;
    while (valid_characters[++length] != '\0') {}


    char password[(password_length + 1)];
    for(int i = 0; i < password_length; i++) {
        char c = valid_characters[rand() % length];
        password[i] = c;
    }

    // Terminate the string with '\0' (NULL)
    password[password_length] = '\0';

#if DEBUG
    printf("=DEBUG= Password: %s\n", password);
#endif

    return 0;
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
    printf("\n=DEBUG= File contents:\n");
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
        printf("\n=DEBUG= Domain: %s\n", dom);
        printf("=DEBUG= Password: %s\n", pass);
#endif
        if (!strcmp(dom, domain->sval[0]))
        {
            found = 1;
            break;
        }
    }
#if DEBUG
    printf("=DEBUG=\n");
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
    allowed_special_characters
                = arg_str0(NULL, "special-characters", "CHARS",
                        "allowed special characters");
    min         = arg_int0(NULL, "min", "MINIMUM",
                        "minimum number of allowed characters in password");
    max         = arg_int0(NULL, "max", "MAXIMUM",
                        "maximum number of allowed characters in password");
    number_of_uppercase
                = arg_int0(NULL, "number-of-uppercase", "NUMBER",
                        "required number of uppercase letters in password");
    number_of_lowercase
                = arg_int0(NULL, "number-of-lowercase", "NUMBER",
                        "required number of lowercase letters in password");
    number_of_digits
                = arg_int0(NULL, "number-of-digits", "NUMBER",
                        "required number of digits in password");
    number_of_special_characters
                = arg_int0(NULL, "number-of-special-character", "NUMBER",
                        "required number of special characters in password");
    end         = arg_end(20);

    void* argtable[] = {version, help, create_new, generate,
                        allowed_special_characters, min, max,
                        number_of_uppercase, number_of_lowercase,
                        number_of_digits, number_of_special_characters,
                        import, output_file, domain, end};

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
        arg_print_glossary(stdout, argtable, " %-50s %s\n");
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
        printf("=DEBUG= Generating new password for %s.\n", domain->sval[0]);
#endif
        /* TODO: Uncomment
        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        tmp_file = tmpfile();
        */

        int min_pass_size, max_pass_size, required_lowercase,
            required_uppercase, required_digits, required_special_characters;
        /*char special_characters[64];*/

        min_pass_size = MIN_LENGTH;
        max_pass_size = MAX_LENGTH;
        required_lowercase = required_uppercase = required_digits =
            required_special_characters = 0;

        if (min->count > 0) {
            min_pass_size = min->ival[0];
        }
        if (max->count > 0) {
            max_pass_size = max->ival[0];
        }
        if (number_of_uppercase->count > 0)
        {
            required_uppercase = number_of_uppercase->ival[0];
        }
        if (number_of_lowercase->count > 0)
        {
            required_lowercase = number_of_lowercase->ival[0];
        }
        if (number_of_digits->count > 0)
        {
            required_digits = number_of_digits->ival[0];
        }
        if (number_of_special_characters->count > 0)
        {
            required_special_characters = number_of_special_characters->ival[0];
        }


        if (generate_password(
                    min_pass_size,
                    max_pass_size,
                    required_uppercase,
                    required_lowercase,
                    required_digits,
                    required_special_characters,
                    -1,
                    NULL))
        {
            return_status = EXIT_FAILURE;
        }
        /* TODO: Uncomment
        fclose(tmp_file);
        free(key);
        key = NULL;
        */
    }
    else if (import->count > 0 && output_file->count > 0 &&
            domain->count > 0)
    {
#if DEBUG
        printf("=DEBUG= Importing password %s for %s.\n", import->sval[0],
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
        printf("=DEBUG= Fetching password for %s.\n", domain->sval[0]);
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
        arg_print_glossary(stdout, argtable, " %-50s %s\n");
        return_status = EXIT_FAILURE;
    }

    arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));

    return return_status;
}
