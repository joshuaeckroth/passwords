#ifndef TREE_BUILDER
#define TREE_BUILDER

#include <string>
#include <set>
#include <vector>
#include <utility>

extern "C" {
#include <rax.h>
}

class TreeBuilder {
    private:
        char* apply_rule(const std::string &rule, const std::string &pw) const;
        const std::vector<std::string> rules;
        size_t target_cnt;
        size_t pw_cnt = 0;
        size_t rule_cnt = 0;
        rax *pw_tree_processed = nullptr;
        rax *pw_tree_unprocessed = nullptr;
        rax *rule_tree = nullptr;
        float weight_password(std::pair<std::string, std::string>);
        std::set<std::string> choose_passwords(size_t);
        bool generates_self(const char*, std::string) const;
        bool is_ascii(const char*, size_t) const;
    public:
        TreeBuilder(const std::vector<std::string> &target_passwords, const std::vector<std::string> &rules);
        ~TreeBuilder();
        void build(size_t);
        rax* get_password_tree_processed();
        rax* get_password_tree_unprocessed();
        rax* get_rule_tree();
};

#endif /* TREE_BUILDER */
