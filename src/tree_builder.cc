#include <string>
#include <memory>
#include <cstring>
#include <vector>
#include <iostream>
#include <utility>
#include <set>
#include "tree_builder.h"
#include "password_data.h"
#include "rule_data.h"

extern "C" {
#include <rax.h>
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

#define RULE_SCORE_DECAY_FACTOR 0.99999f

using std::vector, std::string, std::cout, std::endl, std::pair, std::set;

TreeBuilder::TreeBuilder(const vector<string> &target_passwords, const vector<string> &rules)
    : rules(std::move(rules)) {
    this->pw_tree = raxNew();
    this->rule_tree = raxNew();
    this->target_cnt = target_passwords.size();
    for (auto &password : target_passwords) {
        PasswordData *pdp = new PasswordData(true, false);
        int check = raxInsert(this->pw_tree, (unsigned char*) password.c_str(), password.size(), (void*) pdp, NULL);
        this->available_passwords.insert({password, ""});
        this->pw_cnt++;
    }
    for (auto &rule : rules) {
        RuleData *rdp = new RuleData(0, 1.0f, false);
        int check = raxInsert(this->rule_tree, (unsigned char*) rule.c_str(), rule.size(), (void*) rdp, NULL);
        this->rule_cnt++;
    }
}

TreeBuilder::~TreeBuilder() {
    raxIterator it;
    raxStart(&it, this->rule_tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (RuleData*)it.data;
    }
    raxStop(&it);
    raxStart(&it, this->pw_tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*)it.data;
    }
    raxStop(&it);
    raxFree(pw_tree);
    raxFree(rule_tree);
}

char* TreeBuilder::apply_rule(const std::string &rule, const std::string &pw) const {
    const size_t pw_size = pw.size();
    char *pw_cstr = (char*) calloc(pw_size+1, sizeof(char));
    strcpy(pw_cstr, pw.c_str());
    char *new_pw = (char*) calloc(RP_PASSWORD_SIZE, sizeof(char));
    _old_apply_rule(rule.c_str(), rule.size(), pw_cstr, pw_size, new_pw);
    free(pw_cstr);
    return new_pw;
}

bool TreeBuilder::generates_self(const char *pw, string rule) const {
    char *regenerated = this->apply_rule(rule, pw);
    bool check = 0 == memcmp(regenerated, pw, strlen(pw));
    free(regenerated);
    return check;
}

void TreeBuilder::build(size_t max_cycles) {
    size_t pw_choose_n = this->target_cnt;
    // First cycle, apply all rules to all targets
    set<pair<string, string>> new_available; 
    for (auto &password_history : available_passwords) {
        auto password = password_history.first;
        for (auto &rule : rules) {
            char *new_pw = this->apply_rule(rule, password);
            if (memcmp(new_pw, password.c_str(), password.size()) == 0) {
                free(new_pw);
                continue;
            }
            PasswordData *pdp = new PasswordData(false, false);
            RuleData *rdp = (RuleData*) raxFind(this->rule_tree, (unsigned char*) rule.c_str(), rule.size());
            int check_exists = raxTryInsert(this->pw_tree, (unsigned char*) new_pw, strlen(new_pw), (void*) pdp, NULL);
            if (check_exists == 0) { // does exist
                delete pdp;
                rdp->hit_count++;
            } else {
                new_available.insert({new_pw, rule});
                this->pw_cnt++;
                rdp->score *= RULE_SCORE_DECAY_FACTOR;
            }
            free(new_pw);
        }
        PasswordData *pdp = (PasswordData*) raxFind(this->pw_tree, (unsigned char*) password.c_str(), password.size());
        pdp->did_apply_rules = true;
    }
    this->available_passwords = new_available;
    cout << "Made it past first cycle" << endl;
    // for (int idx = 0; idx < max_cycles; idx++) 
    size_t idx = 0;
    while (idx <= max_cycles) {
        //while (this->pw_cnt <= max_node_cnt && this->available_passwords.size() != 0) 
        cout << "pw_cnt: " << pw_cnt << endl;
        cout << "available_pw_size: " << this->available_passwords.size() << endl;
        for (auto &password_history : this->choose_passwords(pw_choose_n)) {
            auto password = password_history.first;
            auto history = password_history.second;
            for (auto &rule : rules) {
                if (idx == 0) {
                    cout << rule << endl;
                }
                char *new_pw = this->apply_rule(rule, password);
                // a rule than transforms a password into itself is uninteresting
                cout << "rule: " << rule << endl;
                if (memcmp(new_pw, password.c_str(), password.size()) == 0) {
                    free(new_pw);
                    continue;
                }
                else {
                    cout << "OLD: " << password << endl;
                    cout << "NEW: " << new_pw << endl;
                }
                PasswordData *old = nullptr;
                PasswordData *pdp = new PasswordData(false, false);
                // base rule, will always exist
                RuleData *rdp = (RuleData*) raxFind(this->rule_tree, (unsigned char*) rule.c_str(), rule.size());
                auto new_history = history + rule;
                RuleData *rdp_comp = new RuleData(0, 1.0f, true);
                RuleData *rdp_composite_existing = nullptr;
                // try to insert new composite rule
                cout << "COMPOSITE RULE IS: " << new_history.c_str() << endl;
                int check_rule_composite = raxTryInsert(this->rule_tree, (unsigned char*) new_history.c_str(), new_history.size(), (void*) rdp_comp, (void**) &rdp_composite_existing);
                int check_exists = raxTryInsert(this->pw_tree, (unsigned char*) new_pw, strlen(new_pw), (void*) pdp, (void**) &old);
                if (check_rule_composite == 0) { // composite rule already exists
                    //cout << "Comp rule already exists" << endl;
                    delete rdp_comp;
                    rdp_comp = rdp_composite_existing;
                } else {
                    //                    cout << "Comp rule DNE" << endl;
                    this->rule_cnt++;
                }
                if (check_exists == 0) { // generated pw already exists
                    //  cout << "Generated PW already exists" << endl;
                    delete pdp;
                    pdp = old;
                    if (pdp->is_target && !generates_self(new_pw, new_history)) {
                        //    cout << "Existing PW was target" << endl;
                        // Raise score of composite and base
                        rdp_comp->hit_count++; //
                        rdp->hit_count++;
                    } else {
                        //  cout << "Existing PW was not target" << endl;
                        rdp->score *= RULE_SCORE_DECAY_FACTOR;
                        rdp_comp->score *= RULE_SCORE_DECAY_FACTOR;
                    }
                } else {
                    this->available_passwords.insert({new_pw, new_history});
                    this->pw_cnt++;
                }
                free(new_pw);
            }
//            if (idx == 0) cout << endl;
            PasswordData *pdp = (PasswordData*) raxFind(this->pw_tree, (unsigned char*) password.c_str(), password.size());
            pdp->did_apply_rules = true;
        }
        cout << "Made it past idx: " << idx << endl;
        idx++;
    }
}

float TreeBuilder::weight_password(pair<string, string> password_history) {
    auto pw = password_history.first;
    auto history = password_history.second;
    RuleData *rdp = (RuleData*) raxFind(this->rule_tree, (unsigned char*) history.c_str(), history.size());
    return rdp->score;
}

void TreeBuilder::build(const char *pw, vector<string> composite_rule) {}

void TreeBuilder::prune_available(size_t n) {};

/*
 * Random weighted selection of n passwords
 */ 
vector<pair<string, string>> TreeBuilder::choose_passwords(size_t n) {
    cout << "Choosing passwords" << endl;
    size_t idx = 0;
    vector<pair<string, string>> res;
    //vector<pair<string, string>> to_erase;
    for (auto &set_entry : this->available_passwords) {
        if (idx >= n) {
            break;
        }
        res.push_back(set_entry);
        //to_erase.push_back(set_entry);
    //    this->available_passwords.erase(set_entry);
        idx++;
    }
    for (auto &erase : res) {
        this->available_passwords.erase(erase);
    }

    cout << "Done choosing passwords" << endl;
    return res;
}

rax* TreeBuilder::get_password_tree() {
    return this->pw_tree;
}

rax* TreeBuilder::get_rule_tree() {
    return this->rule_tree;
}
