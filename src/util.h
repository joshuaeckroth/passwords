#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <iostream>
#include <climits>

extern "C" {
#include <rax.h>
}

#define ANSI_RED "\033[1;31m"
#define ANSI_BLUE "\033[1;36m"
#define ANSI_GREEN "\033[1;32m"
#define ANSI_RESET "\033[0m"
#define ANSI_RED_ERR "\033[1;31mERROR\033[0m"
#define ANSI_BLUE_INFO "\033[1;36mINFO\033[0m"
#define ANSI_GREEN_SUCCESS "\033[1;32mSUCCESS\033[0m"

#define PROFILING 1

void md5_bytes_to_hex(const unsigned char*, char*);
std::string md5(const char*);
//std::string sha1(const char*);

template<typename T>
void print_bits(T *data) {
    size_t num_bits = sizeof(T) * 8;
    for (size_t idx = 0; idx < num_bits; idx++) {
        std::cout << (bool) ((1 << idx) & *data);
    };
    std::cout << std::endl;
}

template<typename Q>
void print_queue(Q q) {
    for (; !q.empty(); q.pop()) {
        std::cout << q.top() << "\n";
    }
    std::cout << std::endl;
}

template<typename T>
void print_seq(T seq, int limit = INT_MAX) {
    int i = 0;
    for (auto ele : seq) {
        std::cout << ele << "\n";
        if (limit < i++) {
            break;
        }
    }
    std::cout << std::endl;
}

size_t random_integer(size_t, size_t);

bool in_radix(rax*, std::string);

#endif /* UTIL_H */
