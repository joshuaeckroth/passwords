#include <vector>
#include <string>
#include "genetic.h"
#include "rule_loader.h"
#include "password_loader.h"
#include "password_data.h"
#include "partial_guessing.h"

extern "C" {
#include <rax.h>
}

using namespace std;

int main(int argc, const char **argv) {
    if (argc != 6) {
        cerr << "Usage: "
            << argv[0]
            << "\n  <initial population>\n  <primitives for mutations>\n  <password targets>\n  <cycles>"
            << "\n  <evolution strategy: 'individual|collective'>"
            << "\n <password distributions>"
            << endl;
        return -1;
    }
    const char *initial_population_path = argv[1];
    const char *primitives_path = argv[2];
    const char *password_targets_path = argv[3];
    int cycles = atoi(argv[4]);
    const char *strategy = argv[5];
    // for computing password strengths
    const char *pw_distribution_path = argv[6];
    StrengthMap password_strengths;
    PGV partial_guess_data;
    partial_guess_data = get_pguess_metrics(pw_distribution_path);
    password_strengths = make_strength_map(partial_guess_data);
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
    Genetic genetic(rules, primitives, target_passwords, pw_tree_targets, cycles, password_strengths);
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
