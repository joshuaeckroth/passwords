#ifndef PASSWORD_DATA
#define PASSWORD_DATA

#include <set>
#include <string>
#include <vector>

enum StrengthMetric {
    PROBABILITY,
    INDEX,
    PARTIAL_GUESSING
};

struct PasswordData {
    std::string password;
    double complexity;
    bool is_target;
    int max_rule_size;
    std::set<std::string> rule_histories;
    PasswordData(std::string, bool, int);
    double estimate_password_strength(const std::vector<double> &probabilities, size_t, StrengthMetric) const;
};

#endif /* PASSWORD_DATA */
