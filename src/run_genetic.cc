#include <vector>
#include <string>
#include "genetic.h"
#include "rule_loader.h"
#include "password_loader.h"
#include "password_data.h"

extern "C" {
#include <rax.h>
}

using namespace std;

rax *build_target_password_tree(const vector<string>& target_passwords) {
    rax *pw_tree_targets = raxNew();
    const size_t pw_cnt = target_passwords.size();
    for(size_t idx = 0; idx < target_passwords.size(); idx++) {
        string password = target_passwords.at(idx);
        auto *pdp = new PasswordData(true, (pw_cnt - idx) / ((float) pw_cnt + 1.0), idx);
        if (0 == raxTryInsert(pw_tree_targets, (unsigned char*)password.c_str(), password.size()+1, (void *) pdp,
                              NULL)) {
            // this password has already been inserted
            continue;
        }
    }
    return pw_tree_targets;
}

int main() {
    //load rules and primitives
    vector<string> rules_vec = RuleLoader::load_rules<string>("rules/primitives.rule");
    vector<string> primitives = RuleLoader::load_rules<string>("rules/primitives.rule");
    vector<Rule> rules;
    for (const auto &r: rules_vec) {
        rules.emplace_back(r);
    }
    //load passwords
    vector<string> target_passwords = PasswordLoader::load_passwords("data/rockyou.txt");
    rax *pw_tree_targets = build_target_password_tree(target_passwords);
    Genetic genetic(rules, primitives, target_passwords, pw_tree_targets);
    genetic.run(100);
}
