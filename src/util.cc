#include <stdio.h>
#include "util.h"

extern "C" {
#include <openssl/md5.h>
}

void md5_bytes_to_hex(const unsigned char *md5, char *result) {
    char *ptr = result;
    for(int i = 0; i < 16; i++) {
        ptr += sprintf(ptr, "%02x", md5[i]);
    }
}

char* md5(const char *input) {
    unsigned char md5result[16];
    MD5((const unsigned char*)input, strlen(input), md5result);
    char *result = (char*)malloc(33);
    md5_bytes_to_hex(md5result, result);
    return result;
}

