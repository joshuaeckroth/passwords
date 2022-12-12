#include <string>
#include <cstring>
#include <stdio.h>
#include <iostream>
#include "util.h"

extern "C" {
#include <openssl/md5.h>
}

using std::cout, std::endl;

void md5_bytes_to_hex(const unsigned char *md5, char *result) {
    char *ptr = result;
    for(int i = 0; i < 16; i++) {
        ptr += sprintf(ptr, "%02x", md5[i]);
    }
}

std::string md5(const char *input) {
/*
    unsigned char md5result[16];
    MD5((const unsigned char*)input, strlen(input), md5result);
    char *result = (char*)malloc(33);
    md5_bytes_to_hex(md5result, result);
    std::string res_str(result);
    free(result);
    return res_str;
*/
    return "";
}

