#ifndef PASSWORD_NODE_H
#define PASSWORD_NODE_H

#include <string>
#include <iostream>

class PasswordNode {
    public:
        const std::string password;
        const bool is_target;
        PasswordNode(std::string, bool);
        bool operator<(const PasswordNode &node) const;
        bool operator==(const PasswordNode &node) const;
        friend std::ostream& operator<<(std::ostream &os, const PasswordNode &node);
};

#endif /* PASSWORD_NODE_H */
