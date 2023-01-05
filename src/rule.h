#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>
#include <utility>

class Rule {
    private:
        const std::string raw;
        std::string clean_rule;
        float weight = 1.0;
    public:
        explicit Rule(std::string);
        explicit Rule(const char*);
        const std::string& get_rule_raw() const;
        const std::string& get_rule_clean() const;
        std::string apply_rule(const std::string&) const;
        float get_weight() const;
        void decay_weight();
        void reset_weight();
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
};

void initialize_rule_replacements();
std::string simplify_rule(const std::string& rule);
std::pair<size_t, size_t> count_distinct_rule_kinds(const std::string& rule);
bool check_rule_position_validity(const std::string& rule, const std::string& password);

#endif /* RULE_H */
