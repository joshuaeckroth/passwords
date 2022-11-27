#include <utility>
#include <vector>
#include <iostream>
#include <string>
#include <memory>
#include "graph_builder.h"
#include "graph.h"
#include "password_node.h"
#include "rule.h"
#include "graph_db_writer.h"

using std::string, std::vector, std::set, std::unique_ptr, std::cout, std::endl;

GraphBuilder::GraphBuilder(Graph *gp, vector<Rule> rules, vector<string> passwords) : gp(gp), rules(std::move(rules)), target_pws(std::move(passwords)) {}

/*
 * After all of m rules have been applied to n initial target passwords, choose
 * m / 2 rules using weighted random selection to apply to each transformation
 * that didn't hit a target password.  Repeat on generated children until out
 * of rules to apply.
 */
void GraphBuilder::build(size_t rule_try_cnt, const PasswordNode& node) {
    //cout << "trying node.password: " << node.password.size() << endl;
    for (size_t i = 0; i < rule_try_cnt; i++) {
        Rule &r = rnd_weighted_select();
        reset_rule_weights_counter--;
        if(reset_rule_weights_counter <= 0) {
            reset_rule_weights_counter = RESET_RULE_WEIGHTS_COUNTER_INIT;
            reset_rule_weights();
        }
        string rule_raw = r.get_rule_raw();
        //cout << "2 trying rule_raw: " << rule_raw << endl;
        string new_pw = r.apply_rule(node.password);
        if(new_pw == node.password) {
            //cout << "Ignoring " << rule_raw << " on " << node.password << " = " << new_pw << endl;
            r.decay_weight();
            continue;
        }
        this->steps++;
        if (this->target_pw_set.contains(new_pw)) {
            cout << "2 Applying rule " << rule_raw << " to " << node.password << " hit target " << new_pw << endl; 
            this->hits++;
            this->gp->new_edge(node, r.get_rule_clean(), PasswordNode(new_pw, true));
        } else {
            r.decay_weight();
            auto new_miss_node = PasswordNode(new_pw, false);
            this->gp->new_edge_and_child(node, r.get_rule_clean(), PasswordNode(new_pw, false));
            this->build(rule_try_cnt / 3, new_miss_node);
        }
    }
}

void GraphBuilder::build(GraphDBWriter *writer) {
    for (const auto& pw : this->target_pws) {
        this->gp->new_node(PasswordNode(pw, true));
        this->target_pw_set.insert(pw);
    }
    int pw_count = 0;
    for (const auto& pw : this->target_pws) {
        size_t rule_try_count = this->rules.size();
        // on first pass for each pw try all rules
        //cout << "Trying pw: " << pw << endl;
        for (Rule &r : this->rules) {
            string rule_raw = r.get_rule_raw();
            //cout << "Trying rule: " << rule_raw << endl;
            string new_pw = r.apply_rule(pw);
            if(new_pw == pw) {
                //cout << "Ignoring " << rule_raw << " on " << pw << " = " << new_pw << endl;
                r.decay_weight();
                continue;
            }
            reset_rule_weights_counter--;
            if(reset_rule_weights_counter <= 0) {
                reset_rule_weights_counter = RESET_RULE_WEIGHTS_COUNTER_INIT;
                reset_rule_weights();
            }
            this->steps++;
            //PasswordNode new_pw_node(new_pw, false);
            if (this->target_pw_set.contains(new_pw)) {
                cout << "1 Applying rule " << rule_raw << " to " << pw << " hit target " << new_pw << endl;
                this->hits++;
                this->gp->new_edge(PasswordNode(pw, true), r.get_rule_clean(), PasswordNode(new_pw, true));
                // don't go further down this path, since new_pw is a target node it will already get rules applied to it
                //cout << "made it here" << endl;
            } else {
                r.decay_weight();
                auto new_miss_node = PasswordNode(new_pw, false);
                this->gp->new_edge_and_child(PasswordNode(pw, true), r.get_rule_clean(), new_miss_node);
                this->build(rule_try_count / 3, new_miss_node);
            }
        }
        pw_count++;
        if(pw_count % 5 == 0) {
            writer->submit(this->gp);
        }
    }
}

void GraphBuilder::reset_rule_weights() {
    cout << "Resetting rule weights" << endl;
    for (auto &r : this->rules) {
        r.reset_weight();
    }
    cout << "Node count: " << this->gp->node_count() << endl;
}

Rule& GraphBuilder::rnd_weighted_select() {
    while(true) {
        for(int i = 0; i < 10; i++) {
            vector<Rule *> good_rules;
            float rnd = ((float) random()) / ((float) RAND_MAX);
            for (auto &rule: this->rules) {
                if (rnd < rule.get_weight()) {
                    good_rules.push_back(&rule);
                }
            }
            if (!good_rules.empty()) {
                unsigned int pos = random() % good_rules.size();
                return *(good_rules.at(pos));
            }
        }
        reset_rule_weights();
    }
}


