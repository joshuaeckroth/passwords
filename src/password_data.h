#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>

struct PasswordData {
    std::string password;
    double complexity;
    bool is_target;
    std::set<std::string> rule_histories;
    PasswordData(std::string, bool);
    double estimate_password_complexity() const;
};

#endif /* PASSWORD_DATA */
