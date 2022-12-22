#include <string>
#include <memory>
#include <cstring>
#include <fstream>
#include <vector>
#include <iostream>
#include <utility>
#include <set>
#include "tree_builder.h"
#include "password_data.h"
#include "rule_data.h"
#include "rule.h"

extern "C" {
#include <rax.h>
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

#define RULE_SCORE_DECAY_FACTOR 0.99999f

using std::vector, std::string, std::cout, std::endl, std::pair, std::set;

TreeBuilder::TreeBuilder(const vector<string> &target_passwords, set<string> &rules, int target_cnt)
    : rules(std::move(rules)), target_cnt(target_cnt) {
    this->pw_tree_unprocessed = raxNew();
    this->pw_tree_processed = raxNew();
    this->rule_tree = raxNew();
    cout << "Adding original passwords to rax..." << endl;
    for (auto &password : target_passwords) {
        PasswordData *pdp = new PasswordData(true);
        int check = raxInsert(this->pw_tree_unprocessed, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL);
    }
    cout << "Adding rules to rax..." << endl;
    for (auto &rule : rules) {
        RuleData *rdp = new RuleData(0, 1.0f, false);
        int check = raxInsert(this->rule_tree, (unsigned char*) rule.c_str(), rule.size()+1, (void*) rdp, NULL);
    }

    initialize_rule_replacements();
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
    //if(!check) cout << "Diff: " << pw << " != " << regenerated << " (rule: " << rule << ") " << endl;
    free(regenerated);
    return check;
}

void TreeBuilder::build(size_t max_cycles) {
    size_t pw_choose_n = this->target_cnt;
    size_t idx = 0;
    int target_hit_count = 0;
    int not_target_hit_count = 0;
    std::fstream statsout;
    statsout.open("results/stats.csv", std::ios::out);
    statsout << "iteration,processed,unprocessed,hitcount,nothitcount,hitpct\n";
    while (idx <= max_cycles) {
        set<string> next_passwords;
        cout << "idx: " << idx << " of " << max_cycles << " processed: " << this->pw_tree_processed->numnodes << " unprocessed: " << this->pw_tree_unprocessed->numnodes << endl;
        for (auto &password : this->choose_passwords(pw_choose_n)) {
            set<string> generated_passwords;
            PasswordData *orig_pdp = nullptr;
            raxRemove(pw_tree_unprocessed, (unsigned char*)password.c_str(), password.size()+1, (void**)&orig_pdp);
            raxInsert(this->pw_tree_processed, (unsigned char*) password.c_str(), password.size()+1, (void*) orig_pdp, NULL);
            set<string> prior_rule_histories = orig_pdp->rule_histories;
            PasswordData *pdp = nullptr;
            for (auto &rule : rules) {
                char *new_pw = this->apply_rule(rule, password);
                if(!is_ascii(new_pw, strlen(new_pw))) {
                    free(new_pw);
                    continue;
                }
                // a rule than transforms a password into itself is uninteresting
                if (strcmp(new_pw, password.c_str()) == 0) {
                    free(new_pw);
                    continue;
                }
                if(generated_passwords.contains(string(new_pw))) {
                    free(new_pw);
                    continue;
                }
                generated_passwords.insert(string(new_pw));

                set<string> new_rule_histories;
                for(string rh : prior_rule_histories) {
                    string rh2 = simplify_rule(rh + " " + rule, password);
                    if(!rh2.empty()) {
                        //cout << "Inserting " << rh2 << endl;
                        new_rule_histories.insert(rh2);
                    }
                }
                if(!prior_rule_histories.empty() && new_rule_histories.empty()) continue;
                new_rule_histories.insert(rule);
                void *old = nullptr;
                bool target = false;
                if((old = raxFind(this->pw_tree_processed, (unsigned char*)new_pw, strlen(new_pw)+1)) != raxNotFound) {
                    //cout << "Generated PW already exists as a processed one" << endl;
                    pdp = (PasswordData*)old;
                    pdp->rule_histories = new_rule_histories;
                    if (pdp->is_target && !generates_self(new_pw, rule)) {
                        target = true;
                    }
                } else {
                    //cout << "Generated PW does not exist as processed one" << endl;
                    pdp = new PasswordData(false);
                    pdp->rule_histories = new_rule_histories;
                    int check_pw_unprocessed_exists = raxTryInsert(this->pw_tree_unprocessed, (unsigned char*) new_pw, strlen(new_pw)+1, (void*) pdp, (void**) &old);
                    if (check_pw_unprocessed_exists == 0) { // generated pw already exists as unprocessed one
                        //cout << "Generated PW already exists as unprocessed one" << endl;
                        delete pdp;
                        pdp = (PasswordData*)old;
                        pdp->rule_histories = new_rule_histories;
                    } else {
                        //cout << "Added " << new_pw << endl;
                    }
                    if (pdp->is_target && !generates_self(new_pw, rule)) {
                        target = true;
                    }
                }
                // try to insert new composite rule
                for(string rh : new_rule_histories) {
                    RuleData *rdp_comp = new RuleData(0, 1.0f, true);
                    RuleData *rdp_composite_existing = nullptr;
                    //cout << "COMPOSITE RULE IS: " << rh << endl;
                    int check_rule_composite = raxTryInsert(this->rule_tree, (unsigned char*) rh.c_str(), rh.size()+1, (void*) rdp_comp, (void**) &rdp_composite_existing);
                    if (check_rule_composite == 0) { // composite rule already exists
                        delete rdp_comp;
                        rdp_comp = rdp_composite_existing;
                    }
                    if(target) {
                        rdp_comp->hit_count++;
                        if(rdp_comp->hit_count > 5 && !rules.contains(rh)) {
                            cout << "Adding primitive rule " << rh << endl;
                            rules.insert(rh);
                        }
                        target_hit_count++;
                    } else {
                        //rdp_comp->score *= RULE_SCORE_DECAY_FACTOR;
                        not_target_hit_count++;
                    }
                }
                free(new_pw);
            }
        }
        double pct = 100*((double)target_hit_count)/(target_hit_count + not_target_hit_count);
        cout << "target hit count: " << target_hit_count
             << ", not target hit count: " << not_target_hit_count
             << " = " << pct << "%" << endl;
        statsout << idx << "," << this->pw_tree_processed->numnodes << ","
                 << this->pw_tree_unprocessed->numnodes << ","
                 << target_hit_count << "," << not_target_hit_count << ","
                 << pct << "\n";
        target_hit_count = not_target_hit_count = 0;
        idx++;
    }
    statsout.close();
}

float TreeBuilder::weight_password(pair<string, string> password_history) {
    auto pw = password_history.first;
    auto history = password_history.second;
    RuleData *rdp = (RuleData*) raxFind(this->rule_tree, (unsigned char*) history.c_str(), history.size()+1);
    return rdp->score;
}

set<string> TreeBuilder::choose_passwords(size_t n) {
    //cout << "Choosing passwords" << endl;
    set<string> res;
    raxIterator it;
    raxStart(&it, this->pw_tree_unprocessed);
    raxSeek(&it, "^", NULL, 0);
    //raxShow(this->pw_tree_unprocessed);
    int i = 0;
    for(int maxlen = 10; maxlen <= 20 && i < n; maxlen++) {
        while(i < n) {
            if(raxRandomWalk(&it, 0)) {
                if(strlen((const char*)it.key) <= maxlen && rand() % 10 < 5) {
                    res.insert(string((const char*)it.key));
                    i++;
                }
            } else {
                i = n;
                break;
            }
        }
    }
    raxStop(&it);
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

