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
    this->pw_tree_unprocessed = raxNew();
    this->pw_tree_processed = raxNew();
    this->rule_tree = raxNew();
    this->target_cnt = target_passwords.size();
    for (auto &password : target_passwords) {
        PasswordData *pdp = new PasswordData(true, false);
        int check = raxInsert(this->pw_tree_unprocessed, (unsigned char*) password.c_str(), password.size(), (void*) pdp, NULL);
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
    raxStart(&it, this->pw_tree_unprocessed);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*)it.data;
    }
    raxStop(&it);
    raxStart(&it, this->pw_tree_processed);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*)it.data;
    }
    raxStop(&it);
    raxFree(pw_tree_unprocessed);
    raxFree(pw_tree_processed);
    raxFree(rule_tree);
}

char* TreeBuilder::apply_rule(const std::string &rule, const std::string &pw) const {
    const size_t pw_size = pw.size();
    char *pw_cstr = (char*) calloc(pw_size+1, sizeof(char));
    strcpy(pw_cstr, pw.c_str());
    char *new_pw = (char*) calloc(RP_PASSWORD_SIZE, sizeof(char));
    _old_apply_rule(rule.c_str(), rule.size(), pw_cstr, pw_size, new_pw);
    free(pw_cstr);
//    cout << "NEW PW: " << new_pw << endl;
    return new_pw;
}

bool TreeBuilder::generates_self(const char *pw, string rule) const {
    char *regenerated = this->apply_rule(rule, pw);
    bool check = 0 == strcmp(regenerated, pw);
    free(regenerated);
    return check;
}

void TreeBuilder::build(size_t max_cycles) {
    size_t pw_choose_n = this->target_cnt;
    size_t idx = 0;
    while (idx <= max_cycles) {
        cout << "pw_cnt: " << pw_cnt << endl;
        for (auto &password_history : this->choose_passwords(pw_choose_n)) {
            auto password = password_history; //.first;
                                              //auto history = password_history.second;
            string history = "";
            PasswordData *pdp = nullptr;
            raxRemove(pw_tree_unprocessed, (unsigned char*)password.c_str(), password.size(), (void**)&pdp);
            raxInsert(this->pw_tree_processed, (unsigned char*) password.c_str(), password.size(), (void*) pdp, NULL);
            pdp = nullptr;
            for (auto &rule : rules) {
                if (idx == 0) {
                    cout << rule << endl;
                }
                char *new_pw = this->apply_rule(rule, password);
                if(!is_ascii(new_pw, strlen(new_pw))) {
                    free(new_pw);
                    continue;
                }
                // a rule than transforms a password into itself is uninteresting
                cout << "rule: " << rule << endl;
                if (strcmp(new_pw, password.c_str()) == 0) {
                    free(new_pw);
                    continue;
                }
                else {
                    cout << "OLD: " << password << endl;
                    cout << "NEW: " << new_pw << endl;
                }
                // base rule, will always exist
                RuleData *rdp = (RuleData*) raxFind(this->rule_tree, (unsigned char*) rule.c_str(), rule.size());
                auto new_history = history + rule;
                RuleData *rdp_comp = new RuleData(0, 1.0f, true);
                RuleData *rdp_composite_existing = nullptr;
                // try to insert new composite rule
                cout << "COMPOSITE RULE IS: " << new_history.c_str() << endl;
                int check_rule_composite = raxTryInsert(this->rule_tree, (unsigned char*) new_history.c_str(), new_history.size(), (void*) rdp_comp, (void**) &rdp_composite_existing);
                if (check_rule_composite == 0) { // composite rule already exists
                                                 //cout << "Comp rule already exists" << endl;
                    delete rdp_comp;
                    rdp_comp = rdp_composite_existing;
                } else {
                    //                    cout << "Comp rule DNE" << endl;
                    this->rule_cnt++;
                }
                void *old = nullptr;
                if((old = raxFind(this->pw_tree_processed, (unsigned char*)new_pw, strlen(new_pw))) != raxNotFound) {
                    cout << "Generated PW already exists as a processed one" << endl;
                    pdp = (PasswordData*)old;
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
                    free(new_pw);
                } else {
                    cout << "Generated PW does not exist as processed one" << endl;
                    pdp = new PasswordData(false, false);
                    int check_pw_unprocessed_exists = raxTryInsert(this->pw_tree_unprocessed, (unsigned char*) new_pw, strlen(new_pw), (void*) pdp, (void**) &old);
                    if (check_pw_unprocessed_exists == 0) { // generated pw already exists as unprocessed one
                        cout << "Generated PW already exists as unprocessed one" << endl;
                        delete pdp;
                        pdp = (PasswordData*)old;
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
                        free(new_pw);
                    } else {
                        this->pw_cnt++;
                    }
                }
            }
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

set<string> TreeBuilder::choose_passwords(size_t n) {
    cout << "Choosing passwords" << endl;
    set<string> res;
    raxIterator it;
    raxStart(&it, this->pw_tree_unprocessed);
    raxSeek(&it, "^", NULL, 0);
    for(size_t i = 0; i < 1; i++) {
        if(raxRandomWalk(&it, 0)) {
            cout << (const char*)it.key << endl;
            res.insert(string((const char*)it.key));
        } else {
            break;
        }
    }
    raxStop(&it);
    cout << "Done choosing passwords:" << endl;
    for(string s : res) {
        cout << "  > " << s << endl;
    }
    return res;
}

rax* TreeBuilder::get_password_tree_processed() {
    return this->pw_tree_processed;
}

rax* TreeBuilder::get_password_tree_unprocessed() {
    return this->pw_tree_unprocessed;
}

rax* TreeBuilder::get_rule_tree() {
    return this->rule_tree;
}

bool TreeBuilder::is_ascii(const char *s, size_t len) const {
    for(int i = 0; i < len; i++) {
        if(!(s[i] >= '!' && s[i] <= '~')) {
            return false;
        }
    }
    return true;
}

