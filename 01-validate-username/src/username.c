#include "../includes/username.h"

#include <stddef.h>
#include <string.h>
#include <stdio.h>

int cwe_20_username_validate_length(const username name)
{
    if (name == nullptr)
    {
        return 0;
    }

    size_t length = strnlen(name, CWE_20_USERNAME_LENGTH_MAX);
    return (length >= CWE_20_USERNAME_LENGTH_MIN && length <= CWE_20_USERNAME_LENGTH_MAX);
}

/**
 * @brief   Does the username contain a null byte?
 *
 * @param   {username *} name - The username to validate.
 *
 * @return  {int} - Returns 1 if the username contains a null byte, 0 otherwise.
 */
int cwe_20_username_validate_null_byte(const char* name)
{
    if (name == NULL)
    {
        return 0;
    }

    // State machine
    // -----------------------------------------------------------------
    // We will iterate through each character in the username and maintain a state
    // to track whether we have encountered a null byte or not. If we find a null
    // byte before the end of the username, we will return 1 (indicating that
    // the username contains a null byte). If we reach the end of the username without
    // encountering a null byte, we will return 0 (indicating that the username
    // does not contain a null byte).
    //
    // States:
    //  0 - Initial state
    //  1 - Found alphabetic character or digit
    //  2 - Found null byte
    //  3 - Found non-null byte after null byte (invalid state)
    //  4 - Found end of string (valid state)
    //
    int state = 0;
    int pos = 0;

    while (state != 3 && state != 4)
    {
        if (pos >= CWE_20_USERNAME_LENGTH_MAX)
        {
            state = 4;
            break;
        }

        char current = name[pos];

        switch (state)
        {
        case 0:
        case 1:
            state = (current == '\0') ? 2 : 1;
            break;

        case 2:
            if (current != '\0')
            {
                state = 3; // embedded null detected
            }
            break;
        }

        pos++;
    }

    printf("State: %d, Position: %d\n", state, pos);
    return (state == 3) ? 1 : 0;
}

int cwe_20_username_validate(const username name)
{
    if (name == nullptr)
    {
        return 0;
    }

    if (!cwe_20_username_validate_length(name))
    {
        return 0;
    }

    return -1; // todo: implement this function.
}
