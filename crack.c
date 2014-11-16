/**
 * crack.c
 * pset2, hacker edition
 * CSCI-E50
 *
 * a password cracker for the supplied hash.  uses a dictionary
 * attack followed by a brute force attack if needed.
 *
 * Bryan Jackson <bryanjackson@g.harvard.edu>
 * created 20140923
 */

#define _XOPEN_SOURCE

/* In an attempt to limit literals in my code ("magic numbers"), I prefer
 * to be rather liberal with my use of constants.  This also enables me to
 * easily change ranges and values without fear of overlooking duplicate
 * literals in the code.  Plus, compiled constant literals will execute faster
 * than referencing variable values at runtime.
 */
// main() return values
#define SUCCESS                 0
#define ERR_INVALID_ARG         1
#define ERR_INVALID_HASH_LEN    2

// limits for hash/password length
#define SALT_BYTES              2
#define MIN_HASH_LEN            (SALT_BYTES + 1)
#define MAX_PWD_LEN             8

// range of ASCII values to be used for word generation (brute force)
#define CHARPOOL_MIN            32
#define CHARPOOL_MAX            126
#define MAX_CHARPOOL_SIZE       (CHARPOOL_MAX - CHARPOOL_MIN + 1)

// path/filename of dictionary file
#define DICT_FILENAME           "/usr/share/dict/words"
#define DICT_REC_LEN            30

#include <stdio.h>
#include <cs50.h>
#include <string.h>
#include <unistd.h>

// prototypes
void dict_attack(char dict_passwd[], string hash);
void get_salt(char salt[], string hash);
void brute_attack(char brute_passwd[], string hash);
void brute_force(
    string hash, char brute_passwd[], char word[], int pos, int max_len, 
    char char_pool[]);


int main(int argc, string argv[])
{
    // I try to adhere to having only one entry and one exit point in a
    // function when feasable.  Thus, I set an errorcode variable to be
    // sent back by a single return statement at the end of main()
    int err;

    // I prefer to check for "happy path", or most likely condition first,
    // rather than have the exception condition at the top.  I want to see the
    // meat of what the program is supposed to do without having to dig for it.
    if (argc == 2)
    {
        // check for minimum hash length of (salt length) + at least one char
        if (strlen(argv[1]) >= MIN_HASH_LEN)
        {
            string hash = argv[1];

            // perform dictionary attack to attempt to crack the password
            // quickly using known words before resorting to brute force
            char dict_passwd[DICT_REC_LEN + 1] = "";
            dict_attack(dict_passwd, hash);

            if (strlen(dict_passwd) > 0)
            {
                printf("%s\n", dict_passwd);
            }
            else
            {
                // dictionary attack unsuccessful; now we
                // can resort to a brute force attack
                char brute_passwd[MAX_PWD_LEN + 1] = "";
                brute_attack(brute_passwd, hash);
                printf("%s\n", brute_passwd);
            }
            
            err = SUCCESS;
        }
        else
        {
            // hash value too short to include both the salt and a value
            printf("crack: invalid hash length. Too short to include salt\n");
            err = ERR_INVALID_HASH_LEN;
        }
    }
    else
    {
        // user did not supply correct number of arguments
        printf("crack: invalid arguments\nUsage: crack <password hash>\n");
        err = ERR_INVALID_ARG;
    }

    // this was cs50 pset2.
    return err;
}


/**
 * perform dictionary attack to attempt to crack
 * the password quickly from known words
 *
 * @arg     char[]  dict_passwd     variable array to capture cracked password
 * @arg     string  hash            hash of password to be cracked
 * @return  void
 */
void dict_attack(char dict_passwd[], string hash)
{
    // while this is a trivial operation requiring only
    // a few lines of code, I chose to create a separate function
    // since brute_force() will also need this functionality
    char salt[3];
    get_salt(salt, hash);
    
    // open the dictionary file
    FILE* dict_file = fopen(DICT_FILENAME, "r");

    // make sure we were able to open the file...
    if (dict_file != NULL)
    {
        char word[DICT_REC_LEN];
        string wordhash;

        // start reading in and processing one line at a time...
        // I chose fgets() for the while condition because
        // it does 2 things at once: it can be used to reliably check
        // for EOF while also advancing the file position
        while (fgets(word, DICT_REC_LEN, dict_file) != NULL)
        {
            // replace the trailing newline with a null terminator
            // so the \n won't be encoded as part of the hash
            int wlength = strlen(word);
            if (word[wlength - 1] == '\n')
            {
                word[wlength - 1] = '\0';
            }
    
            // encrypt the current dictionary word with the
            // same salt as the passed hash for comparison
            wordhash = crypt(word, salt);

            // if the hashes match, we have cracked the password!
            if (strcmp(wordhash, hash) == 0)
            {
                strcpy(dict_passwd, word);
                break;
            }
	    }

        // close the file
        fclose(dict_file);
    }

    return;
}


/**
 * returns the salt from a DES-based hash
 *
 * @arg     char[]  salt    variable array to capture salt value
 * @arg     string  hash    hash of password to be cracked
 * @return  void
 */
void get_salt(char salt[], string hash)
{
    salt[SALT_BYTES] = '\0';
    strncpy(salt, hash, SALT_BYTES);
}


/**
 * initiates a "brute force" attack, generating all possible combinations
 * of words from a predefined character pool and max word length
 *
 * @arg     char[]  brute_passwd    variable array to capture cracked password
 * @arg     string  hash            hash of password to be cracked
 * @return  void
 */
void brute_attack(char brute_passwd[], string hash)
{
    // create character pool for password generation...
    // I chose to build this character pool dynamically instead of hardcoding
    // the entire set of possible chars by using integer boundaries for ASCII
    // printable characters. This way if the pool definition changes, I don't
    // have to retype the entire array.
    char char_pool[MAX_CHARPOOL_SIZE];
    for (int i = 0; i < MAX_CHARPOOL_SIZE; i++)
    {
        // simply "add" the ASCII offset value to get the character desired
        char_pool[i] = i + CHARPOOL_MIN;
    }

    // define the container to hold the generated "words"
    char word[MAX_PWD_LEN + 1];

    // iterate through each generated word length
    for (int length = 1; length <= MAX_PWD_LEN; length++)
    {
        // set the last array element to a null terminator for string processing
        word[length] = '\0';
        
        // start each brute_force call (for the current word length) with
        // a string position of 0 to start with the first character
        brute_force(hash, brute_passwd, word, 0, length, char_pool);
        
        // short-circuit the loop if a hash match was found
        if (strlen(brute_passwd) > 0)
        {
            break;
        }
    }

    return;
}


/**
 * performs the brute force attack by generating each word combination using
 * recursion and then generating/comparing the hash for each unique combination
 *
 * I chose recursion for this algorithm mainly to allow it to easily scale
 * regardless of the value of MAX_PWD_LEN.  By using loop indicies to set
 * recursive calls, I can programatically set the number of times it is called,
 * versus hardcoding loop constructs that would have to be refactored for every
 * change to MAX_PWD_LEN.
 *
 * @arg     string  hash            hash of password to be cracked
 * @arg     char[]  brute_passwd    variable array to capture cracked password
 * @arg     char[]  word            variable array to capture generated word
 * @arg     int     pos             current character position in the word
 * @arg     int     max_len         current max length of word (set by loop in
 *                                      brute_attack())
 * @arg     char[]  char_pool       set of possible characters to use for word
 * @return  void
 */
void brute_force(
    string hash, char brute_passwd[], char word[], int pos, int max_len, 
    char char_pool[])
{
    string wordhash;

    // get salt from hash
    char salt[3];
    get_salt(salt, hash);

    // iterate through every character in the pool
    for (int i = 0; i < MAX_CHARPOOL_SIZE; i++)
    {
        // set the current word position to the next ASCII char
        word[pos] = char_pool[i];

        // if we've created a new unique word of the
        // current specified length, encrypt it and test
        if (pos == max_len - 1)
        {
            // encrypt the current generated word with the
            // same salt as the passed hash for comparison
            wordhash = crypt(word, salt);

            // if the hashes match, we have cracked the password!
            if (strcmp(wordhash, hash) == 0)
            {
                // copy the string so that we can
                // test for success in brute_attack()
                strcpy(brute_passwd, word);
                break;
            }
        }
        else
        {
            // ...otherwise, recursively call brute_force again with the next
            // word position number to iterate through all characters in the
            // new position
            brute_force(hash, brute_passwd, word, pos + 1, max_len, char_pool);
        }
    }
}

