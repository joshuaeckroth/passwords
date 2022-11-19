#include <string>
#include <vector>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include "password_loader.h"

using std::cout, std::cerr, std::endl, std::string, std::vector;

vector<string> PasswordLoader::load_passwords(const char *path) {
    FILE *fp_passwords;
    if ((fp_passwords = fopen(path, "r")) == NULL) {
        cerr << "Couldn't open passwords file: " << strerror(errno) << endl;
        throw std::runtime_error(strerror(errno));
    }
    vector<string> pw_vec;
    return pw_vec;
}
