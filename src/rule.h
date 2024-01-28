#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>
#include <utility>
#include <regex>
#include <vector>

class Rule {
    private:
        std::string raw;
        std::string clean_rule;
        float weight = 1.0;
        float score = 0.0;
        std::vector<std::string> tokens;
        inline static const std::string tokenize_regex_str = R"((\:|l|u|c|C|t|T[\dA-Z]|r|d|p[\dA-Z]{2}|f|\{|\}|\$[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|\^[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|\$[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|\[|\]|D[\dA-Z]|x[\dA-Z]{2}|O[\dA-Z]{2}|i[\dA-Z][\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|o[\dA-Z][\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|'[\dA-Z]|s[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]{2}|@[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|z[\dA-Z]|Z[\dA-Z]|q|k|K|\*[\dA-Z]{2}|L[\dA-Z]|R[\dA-Z]|\+[\dA-Z]|\-[\dA-Z]|\.[\dA-Z]|\,[\dA-Z]|y[\dA-Z]|Y[\dA-Z]|E|e[\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/]|3[\dA-Z][\w!@#$%^&*()_+=\-.,~`{}[\]|\\:;"'<>?/])+?)";
        inline static const std::regex tokenize_regex{Rule::tokenize_regex_str};
        std::vector<std::string> tokenize();
    public:
        explicit Rule(std::string);
        explicit Rule(const char*);
        Rule(const Rule&);
        Rule(const Rule&&);
        std::vector<std::string> get_primitives() const;
        static Rule join_primitives(std::vector<std::string>);
        const std::vector<std::string>& get_tokens() const;
        const std::string& get_rule_raw() const;
        const std::string& get_rule_clean() const;
        std::string apply_rule(const std::string&) const;
        // weight used in gentree, not genetic
        float get_weight() const;
        void decay_weight();
        void reset_weight();
        // score used in genetic, not gentree
        float get_score() const;
        void set_score(float);
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
        Rule& operator=(const Rule &r);
        bool operator==(const Rule &r) const;
};

void initialize_rule_replacements();
std::string simplify_rule(std::string rule);
std::pair<size_t, size_t> count_distinct_rule_kinds(const std::string& rule);
bool check_rule_position_validity(const std::string& rule, const std::string& password);

#endif /* RULE_H */
