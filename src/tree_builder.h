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
                return a.second->score < b.second->score;
            }
        };
        [[nodiscard]] static char* apply_rule(std::string rule, const std::string &pw) ;
        const std::vector<std::string> *targets;
        const std::vector<std::string> *dict_words;
        std::set<std::string> rules;
        size_t choose_pw_cnt;
        float score_decay_factor;
        rax *pw_tree_processed = nullptr;
        rax *pw_tree_unprocessed = nullptr;
        rax *rule_tree = nullptr;
        std::priority_queue<QueueEntry, std::vector<QueueEntry>, password_score_comparer> pwqueue;
        std::set<QueueEntry> choose_passwords(size_t);
        static bool is_ascii(const char*, size_t) ;
    public:

        bool check_intermediate(unsigned int, std::string, const char*) const;
        TreeBuilder(const std::vector<std::string> *target_passwords, const std::vector<std::string> *dict_words, std::set<std::string> &rules, int target_cnt, float score_deay_factor);
        ~TreeBuilder();
        void build(size_t);
        rax* get_password_tree_processed();
        rax* get_password_tree_unprocessed();
        rax* get_rule_tree();
};

#endif /* TREE_BUILDER */
