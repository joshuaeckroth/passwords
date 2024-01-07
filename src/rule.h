#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>
#include <utility>

class Rule {
    private:
        std::string raw;
        std::string clean_rule;
        float weight = 1.0;
    public:
        explicit Rule(std::string);
        explicit Rule(const char*);
        Rule(const Rule&);
        Rule(const Rule&&);
        std::vector<std::string> get_primitives();
        static Rule join_primitives(std::vector<std::string>);
        inline static const std::string tokenize_regex = R"((\:|l|u|c|C|t|T[\dA-Z]|r|d|p[\dA-Z]{2}|f|{|}|$(?<chars>[\w\p{P}\p{S}])|\^\g<chars>|\$\g<chars>|\[|\]|D[\dA-Z]|x[\dA-Z]{2}|O[\dA-Z]{2}|i[\dA-Z]\g<chars>|o[\dA-Z]\g<chars>|'[\dA-Z]|s\g<chars>{2}|@\g<chars>|z[\dA-Z]|Z[\dA-Z]|q)+?)";
        const std::string& get_rule_raw() const;
        const std::string& get_rule_clean() const;
        std::string apply_rule(const std::string&) const;
        float get_weight() const;
        void decay_weight();
        void reset_weight();
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
        Rule& operator=(const Rule &r);
};

void initialize_rule_replacements();
std::string simplify_rule(std::string rule);
std::pair<size_t, size_t> count_distinct_rule_kinds(const std::string& rule);
bool check_rule_position_validity(const std::string& rule, const std::string& password);

#endif /* RULE_H */
