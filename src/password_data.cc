#include "password_data.h"

using std::string;

PasswordData::PasswordData(string password, bool is_target, int max_rule_size)
    : password(password), is_target(is_target), max_rule_size(max_rule_size) {
        complexity = estimate_password_complexity();
    }

double PasswordData::estimate_password_complexity() const {
    return password.size();
}

