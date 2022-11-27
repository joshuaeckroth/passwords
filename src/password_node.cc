#include <string>
#include <cstring>
#include <iostream>
#include <regex>
#include "password_node.h"
#include "util.h"

using std::string, std::regex, std::regex_replace;

PasswordNode::PasswordNode(const string& s, bool is_target) : password(s), is_target(is_target) {
    password_md5 = md5(s.c_str());
    clean_password = regex_replace(regex_replace(s, regex("\""), "QUOTE"), regex("\t"), "\\t");
}

bool PasswordNode::operator<(const PasswordNode &node) const {
    return this->password < node.password;
}

bool PasswordNode::operator==(const PasswordNode &node) const {
    return this->password == node.password;
}

std::ostream& operator<<(std::ostream &os, const PasswordNode &node) {
    os << "PASSWORD: " << node.password << " TARGET?: " << ((node.is_target) ? "true" : "false");
    return os;
}
