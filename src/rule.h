#ifndef RULE_H
#define RULE_H

#include <string>
#include <iostream>

class Rule {
    private:
        const std::string raw;
        float weight = 1.0;
    public:
        Rule(std::string);
        Rule(const char*);
        std::string get_rule_raw(void) const;
        std::string apply_rule(std::string) const;
        float get_weight(void) const;
        void decay_weight();
        void reset_weight(void);
        bool operator<(const Rule &r) const;
        friend std::ostream& operator<<(std::ostream &os, const Rule &r);
};

#endif /* RULE_H */
