#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>

struct PasswordData {
    float score;
    bool is_target;
    std::set<std::string> rule_histories;
    PasswordData(bool, float);
};

#endif /* PASSWORD_DATA */
