#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>

struct PasswordData {
    int hit_count;
    float score;
    bool is_target;
    unsigned int orig_idx;
    std::set<std::string> rule_histories;
    PasswordData(bool, float, unsigned int);
};

#endif /* PASSWORD_DATA */
