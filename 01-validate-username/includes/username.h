#ifndef CWE_20_USERNAME_H
#define CWE_20_USERNAME_H

#define CWE_20_USERNAME_LENGTH_MIN 3
#define CWE_20_USERNAME_LENGTH_MAX 32

typedef char username[CWE_20_USERNAME_LENGTH_MAX];

/**
 * @brief   Does the username contain a null byte?
 *
 * @param   {username} name - The username to validate.
 *
 * @return  {int} - Returns 1 if the username contains a null byte, 0 otherwise.
 */
int cwe_20_username_validate_null_byte(const username name);

/**
 * @brief   Perform full validation of a given username.
 *
 * @param   {username} name - The username to validate.
 *
 * @return  {int} - Returns 1 if the username is valid, 0 otherwise.
 */
int cwe_20_username_validate(const username name);

#endif //CWE_20_USERNAME_H
