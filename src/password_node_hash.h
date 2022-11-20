#ifndef PASSWORD_NODE_HASH_H
#define PASSWORD_NODE_HASH_H

#include "password_node.h"

class PasswordNodeHash {
    public:
        size_t operator()(const PasswordNode &node) const;
};

class PasswordNodeEqual {
    public:
        bool operator()(const PasswordNode &n1, const PasswordNode &n2) const;
};

#endif /* PASSWORD_NODE_HASH_H */
