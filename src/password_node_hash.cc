#include <string>
#include <functional>
#include "password_node.h"
#include "password_node_hash.h"

size_t PasswordNodeHash::operator()(const PasswordNode &node) const {
    return std::hash<std::string>()(node.password);
}

bool PasswordNodeEqual::operator()(const PasswordNode &n1, const PasswordNode &n2) const {
    return n1.password == n2.password;
}
