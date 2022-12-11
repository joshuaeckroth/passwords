#ifndef TREE_BUILDER
#define TREE_BUILDER

#include <string>
#include <vector>
#include <set>
#include <utility>

extern "C" {
#include <rax.h>
}

class TreeBuilder {
    private:
        char* apply_rule(const std::string &rule, const std::string &pw) const;
        std::set<std::pair<std::string, std::string>> available_passwords; // pair of pw & rule history, set for removal for now
        const std::vector<std::string> rules;
        size_t target_cnt;
        size_t pw_cnt = 0;
        size_t rule_cnt = 0;
        rax *pw_tree = nullptr;
        rax *rule_tree = nullptr;
        float weight_password(std::pair<std::string, std::string>);
        std::vector<std::pair<std::string, std::string>> choose_passwords(size_t);
        void prune_available(size_t);
        void build(const char*, std::vector<std::string>);
        bool generates_self(const char*, std::string) const;
    public:
        TreeBuilder(const std::vector<std::string> &target_passwords, const std::vector<std::string> &rules);
        void build(size_t);
        rax* get_password_tree();
        rax* get_rule_tree();
};

#endif /* TREE_BUILDER */
