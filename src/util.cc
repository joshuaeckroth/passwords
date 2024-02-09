#include <string>
#include <cstring>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include "util.h"

extern "C" {
#include <rax.h>
}

//extern "C" {
//#include <openssl/md5.h>
//#include <openssl/sha.h>
//}

using std::cout, std::endl;

void md5_bytes_to_hex(const unsigned char *md5, char *result) {
    char *ptr = result;
    for(int i = 0; i < 16; i++) {
        ptr += sprintf(ptr, "%02x", md5[i]);
    }
}

size_t random_integer(size_t a, size_t b) {
    static std::random_device dev;
    static std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(a, b);
    return (size_t) dist(rng);
}

bool in_radix(rax *tree, std::string s) {
    return raxFind(tree, (unsigned char*) s.c_str(), s.size() + 1) != raxNotFound;
}

//size_t random_poisson(size_t a, size_t b) {
//    static std::random_device dev;
//    static std::mt
//}

//std::string sha1(const char *input) {
//    unsigned char buffer[20] = {0};
//    SHA1((const unsigned char*) input, strlen(input), buffer);
//    std::stringstream ss;
//    ss << std::hex << std::setfill('0');
//    for (const auto &byte : buffer) {
//        ss << std::setw(2) << (int) byte;
//    }
//    return ss.str();
//}

//std::string md5(const char *input) {
/*
    unsigned char md5result[16];
    MD5((const unsigned char*)input, strlen(input), md5result);
    char *result = (char*)malloc(33);
    md5_bytes_to_hex(md5result, result);
    std::string res_str(result);
    free(result);
    return res_str;
*/
//    return "";
//}

