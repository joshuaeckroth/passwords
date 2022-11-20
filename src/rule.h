#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>

class Rule {
    private:
        const std::string raw;
        int weight = 0;
    public:
        Rule(std::string);
        Rule(const char*);
        std::string get_rule_raw(void) const;
        int get_weight(void) const;
        std::string apply_rule(std::string) const;
        void adjust_weight(int);
        // TODO: Implement score decay here?
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
};

#endif /* RULE_H */
