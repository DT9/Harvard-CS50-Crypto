/**
 * initials.c
 * pset2, hacker edition
 * CSCI-E50
 *
 * this program prompts a user for their name and then outputs their initials
 * in uppercase with no spaces or periods
 *
 * Bryan Jackson <bryanjackson@g.harvard.edu>
 * created 20140922
 */

#include <stdio.h>
#include <cs50.h>
#include <ctype.h>
#include <string.h>

int main(void)
{
    // prompt user for their name
    string name = GetString();
    
    // cycle through all characters, capitalizing and
    // displaying any letter found after a space
    for (int i = 0, length = strlen(name); i < length; i++)
    {
        if ((i == 0 && isalpha(name[0])) || 
            (isalpha(name[i]) && isspace(name[i - 1])))
        {
            printf("%c", toupper(name[i]));
        }
    }
    
    printf("\n");
    
    // this was CS50 pset2.
    return 0;
}

