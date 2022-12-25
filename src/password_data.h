#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>

struct PasswordData {
    std::string password;
    double complexity;
    bool is_target;
    int max_rule_size;
    std::set<std::string> rule_histories;
    PasswordData(std::string, bool, int);

    double estimate_password_complexity() const;
};

#endif /* PASSWORD_DATA */
