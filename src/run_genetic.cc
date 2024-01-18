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
    for (size_t idx = 0; idx < target_passwords.size(); idx++) {
        string password = target_passwords.at(idx);
        auto *pdp = new PasswordData(true, (pw_cnt - idx) / ((float) pw_cnt + 1.0), idx);
        if (0 == raxTryInsert(pw_tree_targets, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL)) {
            // this password has already been inserted
            continue;
        }
    }
    return pw_tree_targets;
}

int main(int argc, const char **argv) {
    if (argc != 6) {
        cerr << "Usage: "
            << argv[0]
            << "\n  <initial population>\n  <primitives for mutations>\n  <password targets>\n  <cycles>"
            << "\n  <evolution strategy: 'individual|collective'>"
            << endl;
        return -1;
    }
    const char *initial_population_path = argv[1];
    const char *primitives_path = argv[2];
    const char *password_targets_path = argv[3];
    int cycles = atoi(argv[4]);
    const char *strategy = argv[5];
    cout << "*** Loading initial population from " << initial_population_path << endl;
    vector<string> rules_vec = RuleLoader::load_rules<string>(initial_population_path);
    vector<Rule> rules;
    for (const auto &r : rules_vec) {
        rules.emplace_back(r);
    }
    cout << "*** Loading primitives from " << primitives_path << endl;
    vector<string> primitives = RuleLoader::load_rules<string>(primitives_path);
    cout << "*** Loading password targets from " << password_targets_path << endl;
    vector<string> target_passwords = PasswordLoader::load_passwords(password_targets_path);
    rax *pw_tree_targets = build_target_password_tree(target_passwords);
    cout << "*** Starting genetic algorithm with " << cycles << " cycles" << endl;
    Genetic genetic(rules, primitives, target_passwords, pw_tree_targets, cycles);
    genetic.run(cycles, ("collective" == string(strategy)) ? COLLECTIVE : INDIVIDUAL);
    raxIterator it;
    raxStart(&it, pw_tree_targets);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*) it.data;
    }
    raxStop(&it);
    raxFree(pw_tree_targets);

}
