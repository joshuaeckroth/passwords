#include <string>
#include <cstring>
#include <vector>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include "password_loader.h"

using std::cout, std::cerr, std::endl, std::string, std::vector, std::strerror, std::strlen;

vector<string> PasswordLoader::load_passwords(const char *path) {
    FILE *fp_passwords;
    if ((fp_passwords = fopen(path, "r")) == nullptr) {
        cerr << "Couldn't open passwords file: " << strerror(errno) << endl;
        throw std::runtime_error(strerror(errno));
    }
    char *pw = nullptr;
    size_t line_restrict = 0;
    vector<string> pw_vec;
    while (getline(&pw, &line_restrict, fp_passwords) != -1) {
        pw[strlen(pw)-1] = 0; // cut off delim
        pw_vec.emplace_back(pw);
        pw = nullptr;
    }
    free(pw);
    fclose(fp_passwords);
    return pw_vec;
}
