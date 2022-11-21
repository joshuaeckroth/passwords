#include <string>
#include <iostream>
#include <utility>
#include <regex>
#include "rule.h"

extern "C" {
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

using std::string, std::endl, std::cout, std::regex, std::regex_replace;

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
