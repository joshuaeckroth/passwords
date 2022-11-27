#ifndef PASSWORD_NODE_H
#define PASSWORD_NODE_H

#include <string>
#include <iostream>

class PasswordNode {
    public:
        const std::string password;
        std::string clean_password;
        const char* password_md5;
        const bool is_target;
        PasswordNode(const std::string&, bool);
        bool operator<(const PasswordNode &node) const;
        bool operator==(const PasswordNode &node) const;
        friend std::ostream& operator<<(std::ostream &os, const PasswordNode &node);
};

#endif /* PASSWORD_NODE_H */
