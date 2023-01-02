#include <string>
#include <memory>
#include <cstring>
#include <fstream>
#include <vector>
#include <iostream>
#include <utility>
#include <algorithm>
#include <set>
#include <chrono>
#include "tree_builder.h"
#include "password_data.h"
#include "rule_data.h"
#include "rule.h"
#include "analyze_tree.h"

extern "C" {
#include <rax.h>
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

#define SCORE_DECAY_FACTOR 0.99f

using std::vector, std::string, std::cout, std::endl, std::pair, std::set, std::replace;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;

TreeBuilder::TreeBuilder(const vector<string> *target_passwords, const vector<string> *dict_words, set<string> &rules, int target_cnt)
    : rules(std::move(rules)), choose_pw_cnt(target_cnt) {
    this->targets = target_passwords;
    this->dict_words = dict_words;
    const size_t pw_cnt = target_passwords->size();
    this->pw_tree_unprocessed = raxNew();
    this->pw_tree_processed = raxNew();
    this->rule_tree = raxNew();
    cout << "Adding original passwords to rax..." << endl;
    size_t dict_words_size = 0;
    if(dict_words != nullptr) {
        dict_words_size = dict_words->size();
    }
    for(size_t idx = 0; idx < target_passwords->size(); idx++) {
        string password = target_passwords->at(idx);
        auto *pdp = new PasswordData(true, (dict_words_size + pw_cnt) - idx, idx);
        raxInsert(this->pw_tree_unprocessed, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL);
        this->pwqueue.emplace(password, pdp);
    }
    if (dict_words != nullptr) {
        cout << "Adding dictionary words to rax..." << endl;
        for(size_t idx = 0; idx < dict_words->size(); idx++) {
            string word = dict_words->at(idx);
            auto *pdp = new PasswordData(false, dict_words_size - idx, idx);
            PasswordData *old_pdp = nullptr;
            if(0 == raxTryInsert(this->pw_tree_unprocessed, (unsigned char*) word.c_str(), word.size()+1, (void*) pdp, (void**)&old_pdp)) {
                delete pdp; // this word is already a known password target from target_passwords vector
            } else {
                this->pwqueue.emplace(word, pdp);
            }
        }
    }
    cout << "Adding rules to rax..." << endl;
    for (auto &rule : this->rules) {
        auto *rdp = new RuleData(0, 1.0f, false);
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

char* TreeBuilder::apply_rule(std::string rule, const std::string &pw) {
    size_t pos;
    while ((pos = rule.find("_SPACE_")) != std::string::npos) {
        rule.replace(pos, pos+7, " ");
    }
    const size_t pw_size = pw.size();
    char *pw_cstr = (char*) calloc(pw_size+1, sizeof(char));
    strcpy(pw_cstr, pw.c_str());
    char *new_pw = (char*) calloc(RP_PASSWORD_SIZE, sizeof(char));
    _old_apply_rule(rule.c_str(), rule.size(), pw_cstr, pw_size, new_pw);
    free(pw_cstr);
    return new_pw;
}

bool TreeBuilder::check_intermediate(unsigned int orig_target_idx, string rule, const char *pw) const {
    const size_t rule_size = rule.size();
    string password;
    if(orig_target_idx < this->targets->size()) {
        password = this->targets->at(orig_target_idx);
    } else {
        password = this->dict_words->at(orig_target_idx - this->targets->size());
    }
    vector<size_t> space_indices;
    space_indices.reserve(rule_size / 2);
    for (size_t idx = 0; idx < rule_size; idx++) {
        if (' ' == rule[idx]) {
            space_indices.push_back(idx);
        }
    }
    space_indices.push_back(rule_size);
    vector<char*> intermediate_pws;
    intermediate_pws.reserve(rule_size / 2);
    for (size_t &si : space_indices) {
        auto subs = rule.substr(0, si);
        char *new_pw = this->apply_rule(subs, password);
        intermediate_pws.push_back(new_pw);
    }
    bool flag = true;
    for(size_t i = 0; flag && i < intermediate_pws.size(); ++i) {
        if (strcmp(intermediate_pws[i], pw) == 0) {
            flag = false;
        }
        for(size_t i2 = 0; flag && i2 < intermediate_pws.size(); ++i2) {
            if (i != i2 && strcmp(intermediate_pws[i], intermediate_pws[i2]) == 0) {
                flag = false;
            }
        }
    }
    for (auto & intermediate_pw : intermediate_pws) {
        free(intermediate_pw);
    }
    return flag;
}

void TreeBuilder::build(size_t max_cycles) {
    size_t pw_choose_n = this->choose_pw_cnt;
    size_t idx = 0;
    int target_hit_count = 0;
    int not_target_hit_count = 0;
    int rule_abandoned_intermediate_repeat = 0;
    std::fstream statsout;
    statsout.open("results/stats.csv", std::ios::out);
    statsout << "iteration,seconds,processed,unprocessed,hitcount,nothitcount,hitpct,rules_primitives_size,"
             << "rules_composites_size,rule_history_size,rule_abandoned_intermediate\n";
    while (idx <= max_cycles) {
        auto t1 = high_resolution_clock::now();
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
            set<string> removable_rules;
            for (auto &rule : rules) {
                bool check_pos = check_rule_position_validity(rule, password);
                if(!check_pos) {
                    continue;
                }
                char *new_pw = this->apply_rule(rule, password);
                if (strlen(new_pw) == 0 || !is_ascii(new_pw, strlen(new_pw)) || strcmp(new_pw, password.c_str()) == 0) { // new_pw == pw is uninteresting
                    free(new_pw);
                    continue;
                }
                set<string> new_rule_histories;
                for (const string &rh : prior_rule_histories) {
                    string rh2 = simplify_rule(rh + " " + rule);
                    bool no_intermediate = check_intermediate(orig_idx_temp, rh2, new_pw);
                    pair<size_t, size_t> cnt_kinds = count_distinct_rule_kinds(rh2);
                    check_pos = check_rule_position_validity(rh2, password);
                    if (!rh2.empty() && cnt_kinds.first <= 5 && cnt_kinds.second <= 10 && no_intermediate && check_pos) {
                        new_rule_histories.insert(rh2);
                    } else if(!no_intermediate) {
                        rule_abandoned_intermediate_repeat++;
                    }
                }
                new_rule_histories.insert(rule);
                void *old = nullptr;
                bool target = false;
                // Generated pw already exists as a processed pw
                if ((old = raxFind(this->pw_tree_processed, (unsigned char*) new_pw, strlen(new_pw)+1)) != raxNotFound) {
                    pdp = (PasswordData*) old;
                } else {
                    //cout << "Generated PW does not exist as processed one" << endl;
                    pdp = new PasswordData(false, parent_score * SCORE_DECAY_FACTOR, orig_idx_temp);
                    int check_pw_unprocessed_exists = raxTryInsert(this->pw_tree_unprocessed, (unsigned char*) new_pw, strlen(new_pw)+1, (void*) pdp, (void**) &old);
                    if (check_pw_unprocessed_exists == 0) { // generated pw already exists as unprocessed one
                        delete pdp;
                        pdp = (PasswordData*) old;
                    } else {
                        this->pwqueue.emplace(new_pw, pdp);
                    }
                }
                if (pdp->is_target) {
                    target = true;
                }
                // try to insert new composite rule
                if (target) {
                    bool new_rule_primitive = false;
                    for (const string& rh : new_rule_histories) {
                        auto *rdp_comp = new RuleData(0, 1.0f, true);
                        RuleData *rdp_composite_existing = nullptr;
                        int check_rule_composite = raxTryInsert(this->rule_tree, (unsigned char*) rh.c_str(), rh.size()+1, (void*) rdp_comp, (void**) &rdp_composite_existing);
                        if (check_rule_composite == 0) { // composite rule already exists
                            delete rdp_comp;
                            rdp_comp = rdp_composite_existing;
                        }
                        rdp_comp->hit_count++;
                        if (rdp_comp->hit_count > 1 && rdp_comp->hit_count > idx/2) {
                            if(this->rules.find(rh) == this->rules.end()) {
                                this->rules.insert(rh);
                                new_rule_primitive = true;
                            }
                        }
                    }
                    target_hit_count++;
                    if(new_rule_primitive) {
                        // if hit target, clear out rule histories since we have a new primitive
                        new_rule_histories.clear();
                    }
                } else {
                    not_target_hit_count++;
                }
                free(new_pw);
//                vector<string> new_rule_histories_removable;
//                for(const string& rh : new_rule_histories) {
//                    void *old = nullptr;
//                    if ((old = raxFind(this->rule_tree, (unsigned char *) rh.c_str(), rh.size() + 1)) != raxNotFound) {
//                        auto rdp = (RuleData *) old;
//                        if (idx > 20 && rdp->hit_count < idx / 20) {
//                            removable_rules.insert(rh);
//                            new_rule_histories_removable.push_back(rh);
//                        }
//                    }
//                }
//                for(const string& rh : new_rule_histories_removable) {
//                    new_rule_histories.erase(rh);
//                }
                pdp->rule_histories = new_rule_histories;
                rule_history_count += new_rule_histories.size();
            }
            for(const auto& rh : removable_rules) {
                this->rules.erase(rh);
                raxRemove(this->rule_tree, (unsigned char *) rh.c_str(), rh.size() + 1, (void **) NULL);
            }
        }
        auto t2 = high_resolution_clock::now();
        duration<double, std::milli> ms_double = t2 - t1;
        double pct = 100*((double)target_hit_count)/(target_hit_count + not_target_hit_count);
        cout << "seconds: " << ms_double.count()/1000 << " target hit count: " << target_hit_count
             << ", not target hit count: " << not_target_hit_count
             << " = " << pct << "%" << " primitive count " << rules.size() << " rule count "
             << raxSize(this->rule_tree) << " rule history count: " << rule_history_count << endl;
        statsout << idx << "," << ms_double.count()/1000 << "," << raxSize(this->pw_tree_processed) << ","
                 << raxSize(this->pw_tree_unprocessed) << ","
                 << target_hit_count << "," << not_target_hit_count << ","
                 << pct << "," << rules.size() << "," << raxSize(this->rule_tree) << "," << rule_history_count
                 << ", " << rule_abandoned_intermediate_repeat << "\n";
        target_hit_count = not_target_hit_count = 0;
        idx++;

        if(idx % 100 == 0) {
            AnalyzeTree at(this->rule_tree);
            at.analyze();
        }
    }
    statsout.close();
}

set<QueueEntry> TreeBuilder::choose_passwords(size_t n) {
    set<QueueEntry> res;
    for(int i = 0; i < n && !this->pwqueue.empty(); i++) {
        QueueEntry qe = this->pwqueue.top();
        this->pwqueue.pop();
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
        if(!(s[i] >= '!' && s[i] <= '~') && s[i] != ' ') {
            return false;
        }
    }
    return true;
}

