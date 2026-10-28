#include <stdio.h>
#include <assert.h>

#include "includes/username.h"

static void run_test(const char *label, const char buffer[CWE_20_USERNAME_LENGTH_MAX], int expected)
{
    int result = cwe_20_username_validate_null_byte(buffer);
    printf("[%s] expected=%d, got=%d -> %s\n\n",
           label, expected, result, (result == expected) ? "PASS" : "FAIL");
    assert(result == expected);
}

int main()
{
    // 1. Embedded null in the middle of the name
    constexpr char t01[CWE_20_USERNAME_LENGTH_MAX] = "user\0name";
    run_test("01 embedded null mid-string", t01, 1);

    // 2. Plain valid username, no embedded null (trailing padding only)
    constexpr char t02[CWE_20_USERNAME_LENGTH_MAX] = "validUser";
    run_test("02 valid username", t02, 0);

    // 3. Null byte as the very first character, data after it
    constexpr char t03[CWE_20_USERNAME_LENGTH_MAX] = "\0hidden";
    run_test("03 leading null then data", t03, 1);

    // 4. Entirely empty buffer (all zeros)
    constexpr char t04[CWE_20_USERNAME_LENGTH_MAX] = "";
    run_test("04 all-zero buffer", t04, 0);

    // 5. NULL pointer input
    run_test("05 NULL pointer", NULL, 0);

    // 6. Embedded null at second-to-last position, non-null last byte
    constexpr char t06[CWE_20_USERNAME_LENGTH_MAX] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0X"; // 30 'a', '\0', 'X' = 32 bytes
    run_test("06 null at index 30, data at 31", t06, 1);

    // 7. Full-length username, no null anywhere (exactly 32 chars, no terminator)
    constexpr char t07[CWE_20_USERNAME_LENGTH_MAX] =
        "abcdefghijklmnopqrstuvwxyz012345"; // exactly 32 chars
    run_test("07 full 32-char buffer, no null", t07, 0);

    // 8. Multiple embedded nulls
    constexpr char t08[CWE_20_USERNAME_LENGTH_MAX] = "a\0b\0c";
    run_test("08 multiple embedded nulls", t08, 1);

    // 9. Single character followed by padding
    constexpr char t09[CWE_20_USERNAME_LENGTH_MAX] = "x";
    run_test("09 single char + padding", t09, 0);

    // 10. Null byte at index 0, rest of buffer also zero
    constexpr char t10[CWE_20_USERNAME_LENGTH_MAX] = "\0";
    run_test("10 leading null, no data after", t10, 0);

    // 11. 31 chars + implicit terminator at last byte (null only at the end)
    constexpr char t11[CWE_20_USERNAME_LENGTH_MAX] =
        "abcdefghijklmnopqrstuvwxyz01234"; // 31 chars, index 31 = '\0'
    run_test("11 null only at final byte", t11, 0);

    // 12. Special/non-alphanumeric characters after an embedded null
    constexpr char t12[CWE_20_USERNAME_LENGTH_MAX] = "admin\0!@#";
    run_test("12 null followed by symbols", t12, 1);

    printf("All tests passed.\n");
    return 0;
}