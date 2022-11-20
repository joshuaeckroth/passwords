#include <vector>
#include <iostream>
#include <string>
#include <memory>
#include <random>
#include "graph_builder.h"
#include "graph.h"
#include "password_node.h"
#include "rule.h"

using std::string, std::vector, std::set, std::unique_ptr, std::cout, std::endl;

#define PW_HIT_WEIGHT_INCREASE 10
#define RULE_SCORE_DECAY_VALUE -1

GraphBuilder::GraphBuilder(unique_ptr<Graph> gp, vector<Rule> rules, vector<string> passwords) : gp(gp), rules(rules), target_pws(passwords) {
    this->rule_weight_sum = rules.size();
}

void GraphBuilder::build(void) {
    set<string> target_set;
    for (auto pw : this->target_pws) {
        gp->new_node(PasswordNode(pw, true));
        target_set.insert(pw);
    }
    for (auto pw : this->target_pws) {
        size_t rule_try_count = this->rules.size();
        // on first pass for each pw try all rules
        for (Rule r : rules) {
             string new_pw = r.apply_rule(pw);
             PasswordNode new_node(new_pw, false);
             if (gp->node_exists) {
                 cout << "Applying rule " << r.get_rule_raw() << " to " << pw << " hit " << new_pw << endl;
                 this->hits++;
                 r.adjust_weight(PW_HIT_WEIGHT_INCREASE);
                 this->rule_weight_sum += PW_HIT_WEIGHT_INCREASE;

             } else {
                 unsigned int current_weight = r.get_weight();
                 if (((int) current_weight + RULE_SCORE_DECAY_VALUE) >= 1) {
                     this->rule_weight_sum += RULE_SCORE_DECAY_VALUE;
                 }
             }
             this->steps++;
        }
    }
}

// various approaches: https://stackoverflow.com/questions/1761626/weighted-random-numbers
// this one is simple and good if weights are frequently changing 
Rule GraphBuilder::rnd_weighted_select(void) {
    std::random_device device;
    std::mt19937 generator(device());
    std::uniform_int_distribution<int> dist(0, this->rule_weight_sum-1);
    auto rand = dist(generator);
    for (auto rule : this->rules) {
        if (rnd < rule.weight) {
            return rule;
        }
        rand -= rule.weight;
    }
}


