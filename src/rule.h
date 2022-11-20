#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>

class Rule {
    private:
        const std::string raw;
        unsigned int weight = 1; // don't decay past 1
    public:
        Rule(std::string);
        Rule(const char*);
        std::string get_rule_raw(void) const;
        unsigned int get_weight(void) const;
        std::string apply_rule(std::string) const;
        void adjust_weight(int);
        void reset_weight(void);
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
};

#endif /* RULE_H */
