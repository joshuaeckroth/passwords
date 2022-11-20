#include <string>
#include <iostream>
#include "password_node.h"

using std::string;

PasswordNode::PasswordNode(string s, bool is_target) : password(s), is_target(is_target) {}

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
