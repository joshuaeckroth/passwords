#ifndef RULE_DATA
#define RULE_DATA

struct RuleData {
    unsigned int hit_count;
    float score;
    bool is_composite;
    RuleData(unsigned int, float, bool);
};

#endif /* RULE_DATA */
