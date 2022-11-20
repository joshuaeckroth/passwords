#include <unordered_set>
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

#define PW_HIT_WEIGHT_INCREASE 1
#define RULE_SCORE_DECAY_VALUE -1

GraphBuilder::GraphBuilder(Graph *gp, vector<Rule> rules, vector<string> passwords) : gp(gp), rules(rules), target_pws(passwords) {
    this->rule_weight_sum = rules.size();
}

/*
 * After all of m rules have been applied to n initial target passwords, choose
 * m / 2 rules using weighted random selection to apply to each transformation
 * that didn't hit a target password.  Repeat on generated children until out
 * of rules to apply.
 */
void GraphBuilder::build(size_t rule_try_cnt, PasswordNode node) {
    cout << "trying node.password: " << node.password.size() << endl;
    for (size_t i = 0; i < rule_try_cnt; i++) {
        Rule &r = rnd_weighted_select();
        string rule_raw = r.get_rule_raw();
        cout << "2 trying rule_raw: " << rule_raw << endl;
        string new_pw = r.apply_rule(node.password);
        this->steps++;
        if (this->target_pw_set.contains(new_pw)) {
            cout << "2 Applying rule " << rule_raw << " to " << node.password << " hit target " << new_pw << endl;
            this->hits++;
            r.adjust_weight(PW_HIT_WEIGHT_INCREASE);
            this->rule_weight_sum += PW_HIT_WEIGHT_INCREASE;
            this->gp->new_edge(node, rule_raw, PasswordNode(new_pw, true));
        } else {
            unsigned int current_weight = r.get_weight();
            if (((int) current_weight + RULE_SCORE_DECAY_VALUE) >= 1) {
                r.adjust_weight(RULE_SCORE_DECAY_VALUE);
                this->rule_weight_sum += RULE_SCORE_DECAY_VALUE;
            }
            auto new_miss_node = PasswordNode(new_pw, false);
            this->gp->new_edge_and_child(node, rule_raw, PasswordNode(new_pw, false));
            this->build(rule_try_cnt / 2, new_miss_node);
        }
    }
}

void GraphBuilder::build(void) {
    for (auto pw : this->target_pws) {
        this->gp->new_node(PasswordNode(pw, true));
        this->target_pw_set.insert(pw);
    }
    for (auto pw : this->target_pws) {
        size_t rule_try_count = this->rules.size();
        // on first pass for each pw try all rules
        cout << "Trying pw: " << pw << endl;
        for (Rule &r : this->rules) {
            string rule_raw = r.get_rule_raw();
            cout << "Trying rule: " << rule_raw << endl;
            string new_pw = r.apply_rule(pw);
            this->steps++;
            //PasswordNode new_pw_node(new_pw, false);
            if (this->target_pw_set.contains(new_pw)) {
                cout << "1 Applying rule " << rule_raw << " to " << pw << " hit target " << new_pw << endl;
                this->hits++;
                r.adjust_weight(PW_HIT_WEIGHT_INCREASE);
                this->rule_weight_sum += PW_HIT_WEIGHT_INCREASE;
                this->gp->new_edge(PasswordNode(pw, true), rule_raw, PasswordNode(new_pw, true));
                // don't go further down this path, since new_pw is a target node it will already get rules applied to it
                cout << "made it here" << endl;
            } else {
                unsigned int current_weight = r.get_weight();
                if (((int) current_weight + RULE_SCORE_DECAY_VALUE) >= 1) {
                    r.adjust_weight(RULE_SCORE_DECAY_VALUE);
                    this->rule_weight_sum += RULE_SCORE_DECAY_VALUE;
                }
                auto new_miss_node = PasswordNode(new_pw, false);
                this->gp->new_edge_and_child(PasswordNode(pw, true), rule_raw, new_miss_node);
                this->build(rule_try_count / 2, new_miss_node);
            }
        }
    }
}

void GraphBuilder::reset_rule_weights(void) {
    for (auto &r : this->rules) {
        r.reset_weight();
    }
}

// various approaches: https://stackoverflow.com/questions/1761626/weighted-random-numbers
// this one is simple and good if weights are frequently changing 
Rule& GraphBuilder::rnd_weighted_select(void) {
    std::random_device device;
    // TODO: investigate how this seeding works
    std::mt19937 generator(device());
    std::uniform_int_distribution<unsigned int> dist(0, this->rule_weight_sum-1);
    auto rnd = dist(generator);
    for (auto &rule : this->rules) {
        if (rnd < rule.get_weight()) {
            return rule;
        }
        rnd -= rule.get_weight();
    }
}


