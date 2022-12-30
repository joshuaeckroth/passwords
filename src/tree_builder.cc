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

#define SCORE_DECAY_FACTOR 0.99f

using std::vector, std::string, std::cout, std::endl, std::pair, std::set;

TreeBuilder::TreeBuilder(const vector<string> *target_passwords, const vector<string> *dict_words, set<string> &rules, int target_cnt)
    : rules(std::move(rules)), target_cnt(target_cnt) {
    this->targets = target_passwords;
    const size_t pw_cnt = target_passwords->size();
    this->pw_tree_unprocessed = raxNew();
    this->pw_tree_processed = raxNew();
    this->rule_tree = raxNew();
    cout << "Adding original passwords to rax..." << endl;
    // half are targets (unprocessed, goals), half are starting points and not targets
    // maybe...
    // other idea: start with standard dictionary (english words) and try to hit targets (rockyou) ?
    int i = 0;
    for (auto &password : *target_passwords) {
        auto *pdp = new PasswordData(true, pw_cnt - i, i);
        raxInsert(this->pw_tree_unprocessed, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL);
        this->pwqueue.emplace(password, pdp);
        i++;
    }
    if (dict_words != nullptr) {
//        for (auto &word : *dict_words) {
//            if(word.size() > 5) {
//                PasswordData *pdp = new PasswordData(word, false);
//                PasswordData *old_pdp = nullptr;
//                raxInsert(this->pw_tree_unprocessed, (unsigned char*) word.c_str(), word.size()+1, (void*) pdp, (void**)&old_pdp);
//                if(old_pdp != nullptr) {
//                    delete pdp;
//                } else {
//                    this->pwqueue.push(pdp);
//                }
//            }
//        }
    }
    cout << "Adding rules to rax..." << endl;
    for (auto &rule : rules) {
        RuleData *rdp = new RuleData(0, 1.0f, false);
        raxInsert(this->rule_tree, (unsigned char*) rule.c_str(), rule.size()+1, (void*) rdp, NULL);
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

bool TreeBuilder::check_intermediate(unsigned int orig_target_idx, string rule, const char *pw) const {
    const size_t rule_size = rule.size();
    string password = this->targets->at(orig_target_idx);
    vector<size_t> space_indices;
    space_indices.reserve(rule_size / 2);
    for (size_t idx = 0; idx < rule_size; idx++) {
        if (' ' == rule[idx]) {
            space_indices.push_back(idx);
        }
    }
    vector<char*> intermediate_pws;
    intermediate_pws.reserve(rule_size / 2);
    for (size_t &si : space_indices) {
        auto subs = rule.substr(0, si);
        char *new_pw = this->apply_rule(subs, password);
        intermediate_pws.push_back(new_pw);
    }
    bool flag = true;
    for (auto & intermediate_pw : intermediate_pws) {
        if (strcmp(intermediate_pw, pw) == 0) {
            flag = false;
//            cout << pw << " " << password << " rule: " << rule << " " << i << " intermediate " << intermediate_pws[i] << " result " << flag << endl;
        }
    }
    for (auto & intermediate_pw : intermediate_pws) {
        free(intermediate_pw);
    }
    return flag;
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
        cout << "idx: " << idx << " of " << max_cycles << " processed: " << this->pw_tree_processed->numele << " unprocessed: " << this->pw_tree_unprocessed->numele << endl;
        set<QueueEntry> chosen = this->choose_passwords(pw_choose_n);
        if (chosen.empty()) break;
        size_t rule_history_count = 0;
        for (auto &queue_entry : chosen) {
            string password = queue_entry.first;
            float parent_score = queue_entry.second->score;
            unsigned int orig_idx_temp = queue_entry.second->orig_idx;
            PasswordData *orig_pdp = nullptr;
            raxRemove(this->pw_tree_unprocessed, (unsigned char*) password.c_str(), password.size()+1, (void**) &orig_pdp);
            raxInsert(this->pw_tree_processed, (unsigned char*) password.c_str(), password.size()+1, (void*) orig_pdp, NULL);
            set<string> prior_rule_histories;
            prior_rule_histories = orig_pdp->rule_histories;
            PasswordData *pdp = nullptr;
            for (auto &rule : rules) {
                char *new_pw = this->apply_rule(rule, password);
                if (!is_ascii(new_pw, strlen(new_pw))
                        || strcmp(new_pw, password.c_str()) == 0 // new_pw == pw is uninteresting 
                        || strlen(new_pw) > 15) {
                    free(new_pw);
                    continue;
                }
                set<string> new_rule_histories;
                for (const string &rh : prior_rule_histories) {
                    string rh2 = simplify_rule(rh + " " + rule, password);
                    if (!rh2.empty() && rh2.size() < 10 && check_intermediate(orig_idx_temp, rh2, new_pw)) {
                        //cout << "Inserting " << rh2 << " for " << new_pw << " from " << password << endl;
                        new_rule_histories.insert(rh2);
                    }
                }
                new_rule_histories.insert(rule);
                rule_history_count += new_rule_histories.size();
                void *old = nullptr;
                bool target = false;
                // Generated pw already exists as a processed pw
                if ((old = raxFind(this->pw_tree_processed, (unsigned char*) new_pw, strlen(new_pw)+1)) != raxNotFound) {
                    //cout << "Generated PW already exists as a processed one" << endl;
                    pdp = (PasswordData*) old;
                } else {
                    //cout << "Generated PW does not exist as processed one" << endl;
                    pdp = new PasswordData(false, parent_score * SCORE_DECAY_FACTOR, orig_idx_temp);
                    int check_pw_unprocessed_exists = raxTryInsert(this->pw_tree_unprocessed, (unsigned char*) new_pw, strlen(new_pw)+1, (void*) pdp, (void**) &old);
                    if (check_pw_unprocessed_exists == 0) { // generated pw already exists as unprocessed one
                        //cout << "Generated PW already exists as unprocessed one" << endl;
                        delete pdp;
                        pdp = (PasswordData*) old;
                    } else {
                        this->pwqueue.emplace(new_pw, pdp);
                    }
                }
                pdp->rule_histories = new_rule_histories;
                if (pdp->is_target) { // && !generates_self(new_pw, rule)) 
                    target = true;
                }
                // try to insert new composite rule
                if (target) {
                    for (const string& rh : new_rule_histories) {
                        auto *rdp_comp = new RuleData(0, 1.0f, true);
                        RuleData *rdp_composite_existing = nullptr;
                        //cout << "COMPOSITE RULE IS: " << rh << endl;
                        int check_rule_composite = raxTryInsert(this->rule_tree, (unsigned char*) rh.c_str(), rh.size()+1, (void*) rdp_comp, (void**) &rdp_composite_existing);
                        if (check_rule_composite == 0) { // composite rule already exists
                            delete rdp_comp;
                            rdp_comp = rdp_composite_existing;
                        }
                        rdp_comp->hit_count++;
                        if (rh.size() <= 8) {
                            //cout << "Adding primitive rule " << rh << endl;
                            this->rules.insert(rh);
                        }
                    }
                    target_hit_count++;
                    // if hit target, clear out rule histories since we have a new primitive
                    // TODO: leave in for consideration
                    pdp->rule_histories.clear();
                } else {
                    not_target_hit_count++;
                }
                free(new_pw);
            }
        }
        double pct = 100*((double)target_hit_count)/(target_hit_count + not_target_hit_count);
        cout << "target hit count: " << target_hit_count
             << ", not target hit count: " << not_target_hit_count
             << " = " << pct << "%" << " rule count " << rules.size() << " rule history count: " << rule_history_count << endl;
        statsout << idx << "," << this->pw_tree_processed->numele << ","
                 << this->pw_tree_unprocessed->numele << ","
                 << target_hit_count << "," << not_target_hit_count << ","
                 << pct << "\n";
        target_hit_count = not_target_hit_count = 0;
        idx++;
    }
    statsout.close();
}

set<QueueEntry> TreeBuilder::choose_passwords(size_t n) {
    set<QueueEntry> res;
    for(int i = 0; i < n && !this->pwqueue.empty(); i++) {
        QueueEntry qe = this->pwqueue.top();
        this->pwqueue.pop();
        //cout << pdp->password << " " << pdp->is_target << " = " << pdp->hitcount << "/" << pdp->complexity << endl;
        res.insert(qe);
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

bool TreeBuilder::is_ascii(const char *s, size_t len) {
    for(int i = 0; i < len; i++) {
        if(!(s[i] >= '!' && s[i] <= '~')) {
            return false;
        }
    }
    return true;
}

