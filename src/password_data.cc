#include "password_data.h"

using std::string;

PasswordData::PasswordData(string password, bool is_target)
    : password(password), is_target(is_target) {
        complexity = estimate_password_complexity();
    }

double PasswordData::estimate_password_complexity() const {
    return password.size();
}

