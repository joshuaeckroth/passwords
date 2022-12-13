#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>

struct PasswordData {
    bool is_target;
    std::set<std::string> rule_histories;
    PasswordData(bool);
};

#endif /* PASSWORD_DATA */
