# Dictionary mapping CWE identifiers to descriptions and code examples
cwe_examples = {
    "CWE-20": {
        "description": "Improper Input Validation",
        "code": (
            "/* Example 1: Improper input validation for board dimensions */\n"
            "#define MAX_DIM 100\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n\n"
            "struct board_square_t {\n"
            "   int height;\n"
            "   int width;\n"
            "};\n\n"
            "int main(){\n"
            "    /* board dimensions. */\n"
            "    int m, n, error;\n"
            "    struct board_square_t *board;\n"
            "    printf(\"Please specify the board height: \\n\");\n"
            "    error = scanf(\"%d\", &m);\n"
            "    if (EOF == error) {\n"
            "        printf(\"No integer passed: Die evil hacker!\\n\");\n"
            "    }\n"
            "    printf(\"Please specify the board width: \\n\");\n"
            "    error = scanf(\"%d\", &n);\n"
            "    if (EOF == error) {\n"
            "         printf(\"No integer passed: Die evil hacker!\\n\");\n"
            "    }\n"
            "    if (m > MAX_DIM || n > MAX_DIM) {\n"
            "        printf(\"Value too large: Die evil hacker!\\n\");\n"
            "    }\n"
            "    board = (struct board_square_t*) malloc(m * n * sizeof(struct board_square_t));\n"
            "    return 0;\n"
            "}\n\n"
            "/* Note: While this code checks that the board dimensions do not exceed a maximum, it fails to validate that the inputs are non-negative. \n"
            "An attacker could supply large negative values to cause an integer overflow or excessive memory allocation. */\n\n"
            "/* Example 2: Improper input validation using sscanf */\n"
            "#include <stdio.h>\n\n"
            "/* This function attempts to extract a pair of numbers from a user-supplied string. */\n"
            "void parse_data(char *untrusted_input) {\n"
            "    int m, n, error;\n"
            "    error = sscanf(untrusted_input, \"%d:%d\", &m, &n);\n"
            "    if (EOF == error) {\n"
            "        printf(\"Did not specify integer value. Die evil hacker!\\n\");\n"
            "    }\n"
            "    printf(\"m is %d and n is %d\\n\", m, n);\n"
            "}\n\n"
            "int main(){\n"
            "    parse_data(\"123:\");\n"
            "    return 0;\n"
            "}\n\n"
            "/* Note: In this example, if an attacker provides input like \"123:\", only the first integer is initialized. \n"
            "Subsequent use of the second variable (n) may lead to undefined behavior (CWE-457: Use of uninitialized variable). */\n"
        )
    },
    "CWE-119": {
        "description": "Improper restriction of operations within the bounds of a memory buffer",
        "code": (
            "/* An example of an ERROR for some 64-bit architectures, if \"unsigned int\" is 32 bits and \"size_t\" is 64 bits: */\n"
            "#include <unistd.h>\n"
            "#include <stdlib.h>\n\n"
            "void *mymalloc(unsigned int size) { return malloc(size); }\n\n"
            "int main() {\n"
            "    char *buf;\n"
            "    size_t len;\n"
            "    read(0, &len, sizeof(len));\n"
            "    /* we forgot to check the maximum length */\n"
            "    /* 64-bit size_t gets truncated to 32-bit unsigned int */\n"
            "    buf = mymalloc(len);\n"
            "    read(0, buf, len);\n"
            "    return 0;\n"
            "}\n\n"
            "#define MAX_SIZE 16\n"
            "#include <stdio.h>\n"
            "#include <unistd.h>\n"
            "#include <string.h>\n"
            "#include <stdlib.h>\n\n"
            "/* This example applies an encoding procedure to an input string and stores it into a buffer. */\n"
            "char *copy_input(char *user_supplied_string) {\n"
            "    int i, dst_index;\n"
            "    char *dst_buf = (char*) malloc(4 * sizeof(char) * MAX_SIZE);\n"
            "    if (MAX_SIZE <= strlen(user_supplied_string)) {\n"
            "        printf(\"user string too long, die evil hacker!\\n\");\n"
            "        exit(0);\n"
            "    }\n"
            "    dst_index = 0;\n"
            "    for (i = 0; i < strlen(user_supplied_string); i++) {\n"
            "        if ('&' == user_supplied_string[i]) {\n"
            "            dst_buf[dst_index++] = '&';\n"
            "            dst_buf[dst_index++] = 'a';\n"
            "            dst_buf[dst_index++] = 'm';\n"
            "            dst_buf[dst_index++] = 'p';\n"
            "            dst_buf[dst_index++] = ';';\n"
            "        } else if ('<' == user_supplied_string[i]) {\n"
            "            /* encode to &lt; (encoding omitted for brevity) */\n"
            "        } else {\n"
            "            dst_buf[dst_index++] = user_supplied_string[i];\n"
            "        }\n"
            "    }\n"
            "    return dst_buf;\n"
            "}\n\n"
            "int main() {\n"
            "    char *uss = malloc(MAX_SIZE);\n"
            "    read(0, uss, MAX_SIZE);\n"
            "    char *dst_buff = copy_input(uss);\n"
            "    printf(\"%s\", dst_buff);\n"
            "    return 0;\n"
            "}\n\n"
            "#include <stdio.h>\n\n"
            "/* The following example asks a user for an offset into an array to select an item. */\n"
            "int GetUntrustedOffset() {\n"
            "    int x = -1;\n"
            "    return x;\n"
            "}\n\n"
            "int main(int argc, char **argv) {\n"
            "    char *items[] = {\"boat\", \"car\", \"truck\", \"train\"};\n"
            "    int index = GetUntrustedOffset();\n"
            "    printf(\"You selected %s\\n\", items[index-1]);\n"
            "    return 0;\n"
            "}\n\n"
            "#define MAX_SIZE 16\n"
            "#include <stdio.h>\n"
            "#include <unistd.h>\n"
            "#include <string.h>\n"
            "#include <stdlib.h>\n\n"
            "/* This example applies an encoding procedure to an input string and stores it into a buffer. */\n"
            "int main(int argc, char *argv[]) {\n"
            "    int i, j = 0;\n"
            "    char a[MAX_SIZE];\n\n"
            "    /* checks if the user provided an input */\n"
            "    if (argc < 2) return 0;\n\n"
            "    /* checks if the input provided by the user fits in the array a */\n"
            "    if (MAX_SIZE <= strlen(argv[1])) {\n"
            "        printf(\"user string too long\");\n"
            "        return 0;\n"
            "    }\n\n"
            "    /* performs the encoding */\n"
            "    for (i = 0; i < strlen(argv[1]); i++) {\n"
            "        if ('&' == argv[1][i]) {\n"
            "            a[j++] = '&';\n"
            "            a[j++] = 'a';\n"
            "            a[j++] = 'm';\n"
            "            a[j++] = 'p';\n"
            "            a[j++] = ';';\n"
            "        } else {\n"
            "            a[j++] = argv[1][i];\n"
            "        }\n"
            "    }\n"
            "    printf(\"The encoded string is %s \\n\", a);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-120": {
        "description": "Buffer copy without checking size of input",
        "code": (
            "// C code example\n"
            "#include <stdio.h>\n"
            "#include <string.h>\n\n"
            "int main() {\n"
            "    char last_name[20];\n"
            "    printf(\"Enter your last name: \");\n"
            "    scanf(\"%s\", last_name);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-125": {
        "description": "Out-of-bounds Read",
        "code": (
            "// C code example\n"
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    int a[10];\n"
            "    a[10] = 0;\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-134": {
        "description": "Use of externally-controlled format string",
        "code": (
            "/* C code example */\n"
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    char user_input[100];\n"
            "    scanf(\"%99s\", user_input);\n"
            "    // Vulnerable: uncontrolled format string\n"
            "    printf(user_input);\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int x;\n"
            "    int y = 10;\n"
            "    int a[10];\n"
            "    x = a[y];\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int x;\n"
            "    int y = 10;\n"
            "    int a[10];\n"
            "    if (y) {\n"
            "        x = a[y+2];\n"
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int y = 10;\n"
            "    int a[10];\n"
            "    while (y >= 0) {\n"
            "        a[y] = y;\n"
            "        y = y - 1;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-170": {
        "description": "Improper Null Termination",
        "code": (
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "#include <unistd.h>\n"
            "#define MAXLEN 1024\n\n"
            "int main(){\n"
            "    char inputbuf[MAXLEN];\n"
            "    char pathbuf[MAXLEN];\n"
            "    /* for some file descriptor fd */\n"
            "    read(0, inputbuf, MAXLEN); /* does not null terminate */\n"
            "    strcpy(pathbuf, inputbuf); /* requires null terminated input */\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-190": {
        "description": "Integer Overflow or Wraparound",
        "code": (
            "// C code example\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n\n"
            "int main() {\n"
            "    char *buf;\n"
            "    int len;\n"
            "    read(0, &len, sizeof(len));\n"
            "    buf = malloc(len);\n"
            "    read(0, buf, len); /* len casted to unsigned and overflows */\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-193": {
        "description": "Off-by-one Error",
        "code": (
            "// C code example\n"
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    // Off-by-one error: loop iterates one time too many\n"
            "    for (int i = 0; i <= 10; i++) {\n"
            "        printf(\"%d\\n\", i);\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-195": {
        "description": "Signed to unsigned conversion error",
        "code": (
            "#include <stdio.h>\n"
            "#include <string.h>\n\n"
            "int main(){\n"
            "    char firstname[20] = \"\";\n"
            "    char lastname[20] = \"Doe\";\n"
            "    char fullname[40] = \"\";\n"
            "    strncat(fullname, firstname, 20);\n"
            "    strncat(fullname, lastname, 20);\n"
            "    printf(\"Fullname: %s\\n\", fullname);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-197": {
        "description": "Numeric truncation error",
        "code": (
            "unsigned int amount(int y){ return y; }\n"
            "int main(){\n"
            "    int amoun;\n"
            "    int value = -300;\n"
            "    amoun = amount(value);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-222": {
        "description": "Truncation of Security-relevant information - TBD",
        "code": (
            "// Code example TBD\n"
            "// This vulnerability requires a more detailed context to illustrate properly.\n"
        )
    },
    "CWE-369": {
        "description": "Divide By Zero",
        "code": (
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    int x;\n"
            "    x = 1 / 0;\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int x;\n"
            "    int a[10];\n"
            "    a[0] = 0;\n"
            "    x = 1 / a[0];\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int x;\n"
            "    int y = 0;\n"
            "    if (!y) {\n"
            "        x = 4 / y;\n"
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            "int main() {\n"
            "    int x;\n"
            "    int y = 0;\n"
            "    x = 2 / y;\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-401": {
        "description": "Missing release of memory after effective lifetime",
        "code": (
            "#include <unistd.h>\n"
            "#include <stdlib.h>\n"
            "#define BLOCK_SIZE 16\n\n"
            "char* getBlock(int fd) {\n"
            "    char* buf = (char*) malloc(BLOCK_SIZE);\n"
            "    if (!buf) {\n"
            "        return NULL;\n"
            "    }\n"
            "    if (read(fd, buf, BLOCK_SIZE) != BLOCK_SIZE) {\n"
            "        return NULL;\n"
            "    }\n"
            "    return buf;\n"
            "}\n\n"
            "int main(){\n"
            "    char *buff = getBlock(0);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-401_fd": {
        "description": "Exposure of file descriptor to unintended control sphere - TBD",
        "code": (
            "// Code example TBD\n"
            "// This vulnerability would involve improper handling of file descriptors.\n"
        )
    },
    "CWE-415": {
        "description": "Double free",
        "code": (
            "#include <stdlib.h>\n"
            "#define SIZE 16\n\n"
            "int main(){\n"
            "    char* ptr = (char*)malloc(SIZE);\n"
            "    if (1) {\n"
            "        free(ptr);\n"
            "    }\n"
            "    free(ptr);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-416": {
        "description": "Use After Free",
        "code": (
            "#include <stdio.h>\n"
            "#include <unistd.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n\n"
            "#define BUFSIZER1 512\n"
            "#define BUFSIZER2 ((BUFSIZER1 / 2) - 8)\n\n"
            "int main(int argc, char **argv) {\n"
            "    char *buf1R1;\n"
            "    char *buf2R1;\n"
            "    char *buf2R2;\n"
            "    char *buf3R2;\n"
            "    buf1R1 = (char *) malloc(BUFSIZER1);\n"
            "    buf2R1 = (char *) malloc(BUFSIZER1);\n"
            "    free(buf2R1);\n"
            "    buf2R2 = (char *) malloc(BUFSIZER2);\n"
            "    buf3R2 = (char *) malloc(BUFSIZER2);\n"
            "    strncpy(buf2R1, argv[1], BUFSIZER1 - 1);\n"
            "    free(buf1R1);\n"
            "    free(buf2R2);\n"
            "    free(buf3R2);\n"
            "    return 0;\n"
            "}\n\n"
            "#include <stdlib.h>\n"
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "#define SIZE 64\n\n"
            "int main() {\n"
            "    int abrt = 0;\n"
            "    int err = 1;\n"
            "    char* ptr = (char*) malloc(SIZE * sizeof(char));\n"
            "    strcpy(ptr, \"This string is in the heap\");\n"
            "    if (err) {\n"
            "        abrt = 1;\n"
            "        free(ptr);\n"
            "        char* ptr2 = (char*) malloc(2 * sizeof(char));\n"
            "    }\n"
            "    if (abrt) {\n"
            "        printf(\"operation aborted before commit. Pointer value is ptr: %s\", ptr);\n"
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "void dangerous_func (int* ptr, int a, int b) {\n"
            "    int val = 0;\n"
            "    if (!ptr) return;\n"
            "    if (a) {\n"
            "        *ptr += 2;\n"
            "    } else {\n"
            "        val = *ptr; /* uFP: Use of null pointer detected: ptr */\n"
            "        free(ptr);\n"
            "    }\n"
            "    if (b) {\n"
            "        val += 5;\n"
            "    } else {\n"
            "        val += *ptr; /* TP: use after free detected: ptr */\n"
            "    }\n"
            "    if (a) free(ptr);\n"
            "    printf(\"val = %i\\n\", val);\n"
            "}\n\n"
            "int main() {\n"
            "    /* Unsafe function call */\n"
            "    dangerous_func(malloc(sizeof(int)), 0, 0);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-457": {
        "description": "Use of uninitialized variable",
        "code": (
            "// C code example\n"
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    int x, y;\n"
            "    x = y + 1; // y is uninitialized\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-476": {
        "description": "Null pointer dereference",
        "code": (
            "#define NULL 0\n"
            "#include <stdio.h>\n\n"
            "int main() {\n"
            "    int *p = NULL; \n"
            "    if (*p) {\n"
            "        printf(\"Variable p is NULL\\n\");\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-665": {
        "description": "Improper initialization",
        "code": (
            "#include <stdio.h>\n"
            "#include <string.h>\n\n"
            "int main() {\n"
            "    char str[20] = \"\";\n"
            "    strcat(str, \"hello world\");\n"
            "    printf(\"%s\", str);\n"
            "    return 0;\n"
            "}\n"
        )
    },
    "CWE-787": {
        "description": "Out-of-bounds Write - TBD",
        "code": (
            "// Code example TBD\n"
            "// Further details are needed to provide a proper example.\n"
        )
    }
}

def get_cwe_code(cwe_id):
    """
    Retrieve the code example for a given CWE identifier.
    If there are duplicate identifiers (e.g., CWE-401), you can disambiguate using a suffix.
    """
    return cwe_examples.get(cwe_id)

if __name__ == "__main__":
    # Example: Retrieve and print the example for a specific CWE
    selected_cwe = "CWE-20"
    example = get_cwe_code(selected_cwe)
    if example:
        print(f"{selected_cwe}: {example['description']}\n")
        print("Code Example:\n")
        print(example["code"])
    else:
        print(f"No example found for {selected_cwe}")
