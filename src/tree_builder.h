#ifndef TREE_BUILDER
#define TREE_BUILDER

#include <string>
#include <set>
#include <vector>
#include <queue>
#include <utility>

#include "password_data.h"

extern "C" {
#include <rax.h>
}

typedef std::pair<std::string, const PasswordData*> QueueEntry;

class TreeBuilder {
    private:
        struct password_score_comparer {
            // if this bool function returns true, it means a is less than b, so b is preferred over a
            bool operator() (QueueEntry &a, QueueEntry &b) {
                return a.second->score > b.second->score;
            }
        } pwcomparer;
        char* apply_rule(const std::string &rule, const std::string &pw) const;
        std::set<std::string> rules;
        size_t target_cnt;
        size_t pw_cnt = 0;
        size_t rule_cnt = 0;
        rax *pw_tree_processed = nullptr;
        rax *pw_tree_unprocessed = nullptr;
        rax *rule_tree = nullptr;
        std::priority_queue<QueueEntry, std::vector<QueueEntry>, password_score_comparer> pwqueue;
        float weight_password(std::pair<std::string, std::string>);
        std::set<QueueEntry> choose_passwords(size_t);
        bool generates_self(const char*, std::string) const;
        bool is_ascii(const char*, size_t) const;
    public:
        TreeBuilder(const std::vector<std::string> &target_passwords, const std::vector<std::string> *dict_words, std::set<std::string> &rules, int target_cnt);
        ~TreeBuilder();
        void build(size_t);
        rax* get_password_tree_processed();
        rax* get_password_tree_unprocessed();
        rax* get_rule_tree();
};

#endif /* TREE_BUILDER */
