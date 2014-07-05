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
#define MIN_LENGTH 48
#define MAX_LENGTH 64
#define NO_DIGIT_FLAG 0b01
#define NO_SPECIAL_CHARACTER_FLAG 0b10

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
struct arg_lit* no_digits;
struct arg_lit* no_special_characters;
struct arg_end* end;

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
 * Assigns the characters available in available_chars to empty slots in
 * password number_of_times number of times.
 *
 * It accomplish this through randomizing an index and then taking the next
 * unused slot after this index. This does make unused slot right next to an
 * used slot have a twice as high chance of getting assigned. This is deemed ok
 * to make the algorithm run in O(n).
 *
 * Another approach would be to fill the password and then scramble it.
 */
void assign_required(char* password, int password_length,
        char* available_chars, int number_of_times)
{
    int available_chars_length = strlen(available_chars);
    for (int i = 0; i < number_of_times; i++)
    {
        int index = rand() % password_length;
        while (password[(++index) % password_length] != '\0');
        index %= password_length;
        password[index] = available_chars[rand() % available_chars_length];
    }
}

/**
 * Generates a new password for the specified domain.
 *
 */
int generate_password(int min_size,
        int max_size,
        int number_of_uppercase,
        int number_of_lowercase,
        int number_of_digits,
        int number_of_special_characters,
        int len_of_special_chars,
        char* input_special_characters,
        int flag)
{
    if ((flag & NO_DIGIT_FLAG && number_of_digits > 0) ||
            (flag & NO_SPECIAL_CHARACTER_FLAG &&
             number_of_special_characters > 0))
    {
        fprintf(stderr, "Input to generate password does not make any sense, "
                "digits or special characters cannot be both disallowed and "
                "required.\n");
        return 1;
    }
    srand(time(NULL));

    char* valid_characters = calloc(512, sizeof(char));
    char* special_characters = calloc(256, sizeof(char));
    char* lowercase = calloc(27, sizeof(char));
    char* uppercase = calloc(27, sizeof(char));
    char* digits = calloc(11, sizeof(char));
    strcpy(lowercase, "abcdefghijklmnopqrstuvwxyz");
    strcpy(uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    strcpy(digits, "0123456789");
    if (len_of_special_chars < 1)
    {
        strcpy(special_characters, "<>[](){}~&\"!?%/");
        len_of_special_chars = strlen(special_characters);
    }
    else if (len_of_special_chars < 256)
    {
        strncpy(special_characters,
                input_special_characters,
                len_of_special_chars);
    }
    else
    {
        fprintf(stderr, "Too long array of special characters.\nThere is a"
                "limit of 255 special characters(+ NULL).");
        free(valid_characters);
        free(special_characters);
        free(lowercase);
        free(uppercase);
        free(digits);
        return 1;
    }

    strcpy(valid_characters, lowercase);
    strcat(valid_characters, uppercase);
    if (!(flag & NO_DIGIT_FLAG))
    {
        strcat(valid_characters, digits);
    }
    if (!(flag & NO_SPECIAL_CHARACTER_FLAG))
    {
        strncat(valid_characters, special_characters, len_of_special_chars);
    }

    int total_requirement = number_of_digits + number_of_uppercase +
                            number_of_lowercase + number_of_special_characters;
    if (min_size == -1)
    {
        min_size = (total_requirement > MIN_LENGTH) ? total_requirement :
            MIN_LENGTH;
    }
    else 
    {
        min_size = (total_requirement > min_size) ? total_requirement :
            min_size;
    }

    if (max_size == -1)
    {
        max_size = (total_requirement > MAX_LENGTH) ? total_requirement :
            MAX_LENGTH;
    }


    int password_length = max_size - min_size;
    if (password_length > 0)
    {
        password_length = min_size + (rand() % password_length);
    }
    else if (password_length == 0)
    {
        password_length = max_size;
    }
    else
    {
        fprintf(stderr, "Not enough characters in password for all requirements.\n");
        free(valid_characters);
        free(special_characters);
        free(lowercase);
        free(uppercase);
        free(digits);
        return 1;
    }

    int length = strlen(valid_characters);

    char* password = calloc(password_length + 1, sizeof(char));

    assign_required(password, password_length, uppercase, number_of_uppercase);
    assign_required(password, password_length, lowercase, number_of_lowercase);
    assign_required(password, password_length, digits, number_of_digits);
    assign_required(password, password_length, special_characters,
            number_of_special_characters);

    for(int i = 0; i < password_length; i++) {
        if (password[i] == '\0')
        {
            char c = valid_characters[rand() % length];
            password[i] = c;
        }
    }

#if DEBUG
    printf("=DEBUG= Password: %s\n", password);
#endif

    int bytes;
    char buffer[1024];
    if (decrypt_database())
    {
        return 1;
    }
    sprintf(buffer, "\n%s %s", domain->sval[0], password);
    bytes = strlen(buffer);
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

    free(lowercase);
    free(uppercase);
    free(digits);
    free(special_characters);
    free(valid_characters);
    free(password);
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
    bytes = strlen(buffer);
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
                = arg_int0(NULL, "number-of-special-characters", "NUMBER",
                        "required number of special characters in password");
    no_digits   = arg_lit0(NULL, "no-digits", "do not use digits in password");
    no_special_characters
                = arg_lit0(NULL, "no-special-characters",
                        "do not use special characters in password");
    end         = arg_end(20);

    void* argtable[] = {version, help, create_new, generate,
                        allowed_special_characters, min, max,
                        number_of_uppercase, number_of_lowercase,
                        number_of_digits, number_of_special_characters,
                        no_digits, no_special_characters,
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
        int min_pass_size, max_pass_size, required_lowercase,
            required_uppercase, required_digits, required_special_characters,
            len_of_special_chars, flag;
        char* special_characters = NULL;

        required_lowercase = required_uppercase = required_digits =
            required_special_characters = flag = 0;
        max_pass_size = min_pass_size = len_of_special_chars = -1;

        tmp_file = tmpfile();

        if (min->count > 0) {
            min_pass_size = min->ival[0];
        }
        if (max->count > 0) {
            max_pass_size = max->ival[0];
            if (min->count == 0)
            {
                min_pass_size = max_pass_size / 2;
            }
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
        if (allowed_special_characters->count > 0)
        {
            len_of_special_chars = strlen(allowed_special_characters->sval[0]);
            special_characters = calloc(len_of_special_chars, sizeof(char));
            memcpy(special_characters,
                    allowed_special_characters->sval[0],
                    len_of_special_chars * sizeof(char));
        }
        if (no_digits->count > 0)
        {
            flag |= NO_DIGIT_FLAG;
        }
        if (no_special_characters->count > 0)
        {
            flag |= NO_SPECIAL_CHARACTER_FLAG;
        }

        if (get_key())
        {
            fprintf(stderr, "Could not get the key.\n");
        }

        if (generate_password(
                    min_pass_size,
                    max_pass_size,
                    required_uppercase,
                    required_lowercase,
                    required_digits,
                    required_special_characters,
                    len_of_special_chars,
                    special_characters,
                    flag))
        {
            return_status = EXIT_FAILURE;
        }

        if (len_of_special_chars != -1)
        {
            free(special_characters);
        }
        fclose(tmp_file);
        free(key);
        key = NULL;
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
