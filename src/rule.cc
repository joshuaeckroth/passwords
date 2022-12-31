#include <string>
#include <iostream>
#include <utility>
#include <vector>
#include <regex>
#include "rule.h"

extern "C" {
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

using std::string, std::endl, std::cout, std::regex, std::regex_replace, std::vector, std::pair, std::get;

Rule::Rule(string s) : raw(std::move(s)) {
    clean_rule = regex_replace(regex_replace(raw, regex("\""), "QUOTE"), regex("\t"), "\\t");
}

Rule::Rule(const char* s) : raw(string(s)) {
    clean_rule = regex_replace(regex_replace(raw, regex("\""), "QUOTE"), regex("\t"), "\\t");
}

const string& Rule::get_rule_raw() const {
    return this->raw;
}

const string& Rule::get_rule_clean() const {
    return this->clean_rule;
}

float Rule::get_weight() const {
    return this->weight;
}

string Rule::apply_rule(const string& password) const {
    char *pw_cstr = (char*) calloc(password.size()+1, sizeof(char)); // +1 to make space for \0
    strcpy(pw_cstr, password.c_str());
    char new_password[RP_PASSWORD_SIZE];
//    cout << "raw rule is: " << this->raw << endl;
//    cout << "RP_PASSWORD_SIZE is: " << RP_PASSWORD_SIZE << endl;
//    cout << "password size is: " << password.size() << endl;
    _old_apply_rule(this->raw.c_str(), this->raw.size(), pw_cstr, password.size(), new_password);
    string result(new_password);
    free(pw_cstr);
    return result;
}

void Rule::decay_weight() {
    this->weight *= 0.99999;
}

void Rule::reset_weight() {
    this->weight = 1.0;
}

bool Rule::operator<(const Rule &r) const {
    return this->weight < r.get_weight();
}

std::ostream& operator<<(std::ostream &os, const Rule &r) {
    os << "hashcat function: " << r.get_rule_raw() << ", weight: " << r.get_weight();
    return os;
}

vector<pair<regex, string>> rule_replacements;
void initialize_rule_replacements() {
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ulcCt] ([\[\]\{\}r] )?([ulcC]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ul] ([\$\^]\S |s\S\S )+([ul]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([ulcCt]) ([\[\]\{\}r]))", "$1$3 $2 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([ulcCt]) ([\$\^][^A-Za-z] )+([ulcCt]))", "$1$2 $4 $3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ulcC] ([\$\^][^A-Za-z] )+([ulcC]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([\$\^][^A-Za-z] )+([ulcC]))", "$1$3 $2 "));
    rule_replacements.push_back(pair<regex, string>("(^| )l t", "$1u"));
    rule_replacements.push_back(pair<regex, string>("(^| )u t", "$1l"));
    rule_replacements.push_back(pair<regex, string>("(^| )c t", "$1C"));
    rule_replacements.push_back(pair<regex, string>("(^| )C t", "$1c"));
    rule_replacements.push_back(pair<regex, string>("(^| )([rkKt]) \\2", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^\S \[)", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$\S \])", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^\S r \])", "$1r"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$\S r \[)", "$1r"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \] \^(\S) r)", "$1[ \\$$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \] r)", "$1["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \[ r)", "$1]"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\{ +\\}", "$1"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\} +\\{", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^\S +(\$\S +|[\]ulcCt] +)+\[)", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$\S +(\^\S +|[\[ulcCt] +)+\])", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$\S \} \[)", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^\S \{ \])", "$1"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\} \\[", "$1]"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\{ \\]", "$1["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\} s(\S\S) \[)", "$1$2 ]"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\{ s(\S\S) \])", "$1$2 ["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\] \^(\S) \{)", "$1] $$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\[ \$(\S) \})", "$1[ ^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$(\S) \})", "$1^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(\S) \{)", "$1$$2"));
    // canonical ordering of symmetric operations
    // insert-front comes before insert-back
    rule_replacements.push_back(pair<regex, string>(R"((^| )(\$\S) (\^\S))", "$1$3 $2"));
    // chop-right comes before various other options
    rule_replacements.push_back(pair<regex, string>(R"((^| )\] (\[|s\S\S|\^\S|C|c|t|u|l))", "$1] $2"));
    // chop-left comes before various other options
    rule_replacements.push_back(pair<regex, string>(R"((^| )(s\S\S|\$\S|C|c|t|u|l) \[)", "$1[ $2"));
    // switching a char you just inserted
    rule_replacements.push_back(pair<regex, string>(R"((^| )(\$\^)(\S) s\3(\S))", "$1$2$4 s$3$4"));

    // cleanup spaces
    rule_replacements.push_back(pair<regex, string>(" +", " "));
    rule_replacements.push_back(pair<regex, string>(" $", ""));
    rule_replacements.push_back(pair<regex, string>("^ ", ""));
}

string simplify_rule(const string& rule) {
    string result;
    for(auto rep : rule_replacements) {
        result = regex_replace(rule, get<0>(rep), get<1>(rep));
        if(result != rule) {
            return simplify_rule(result);
        }
    }
    return result;
}

