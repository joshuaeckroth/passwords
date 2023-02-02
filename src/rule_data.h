#ifndef RULE_DATA
#define RULE_DATA

struct RuleData {
    unsigned int hit_count;
    float score;
    bool is_composite;
    // when using partial guessing metric to rank
    // password strength, rank effectiveness of
    // rules by summing the individual password
    // strengths of passwords hit by the rule
    double hit_strength_sum = 0.0;
    RuleData(unsigned int, float, bool);
};

#endif /* RULE_DATA */
