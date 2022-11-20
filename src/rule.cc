#include <string>
#include <iostream>
#include "rule.h"

extern "C" {
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

using std::string, std::endl, std::cout;

Rule::Rule(string s) : raw(s) {}

Rule::Rule(const char* s) : raw(string(s)) {}

string Rule::get_rule_raw() const {
    return this->raw;
}

unsigned int Rule::get_weight() const {
    return this->weight;
}

string Rule::apply_rule(string password) const {
    char *pw_cstr = (char*) calloc(password.size(), sizeof(char));
    strcpy(pw_cstr, password.c_str());
    char new_password[RP_PASSWORD_SIZE];
    _old_apply_rule(this->raw.c_str(), this->raw.size(), pw_cstr, password.size(), new_password); 
    string result(new_password);
    free(pw_cstr);
    return result;
}

void Rule::adjust_weight(int adjustment) {
    this->weight += adjustment;
}

bool Rule::operator<(const Rule &r) const {
    return this->weight < r.get_weight();
}

std::ostream& operator<<(std::ostream &os, const Rule &r) {
    os << "hashcat function: " << r.get_rule_raw() << ", weight: " << r.get_weight();
    return os;
}
