#include <vector>
#include <string>
#include <glog/logging.h>
#include "genetic.h"
#include "rule_loader.h"
#include "password_loader.h"
#include "password_data.h"
#include "partial_guessing.h"

extern "C" {
#include <rax.h>
}

/*to run code:
make genetic USE_PARALLEL=1
./bin/genetic rules/best64.rule rules/primitives.rule data/rockyou-1k.txt data/rockyou-100.txt 100 collective data/pguess_metrics_cache.tsv
 */
using namespace std;

int main(int argc, const char **argv) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;
    if (argc != 8) {
        cerr << "Usage: "
            << argv[0]
            << "\n  <initial population> e.g. rules/best64.rule"
            << "\n  <primitives for mutations> e.g. rules/primitives.rule"
            << "\n  <password targets> e.g. data/rockyou-1k.txt"
            << "\n  <initial passwords> e.g. data/rockyou-100.txt"
            << "\n  <cycles> e.g. 10"
            << "\n  <evolution strategy: 'individual|collective'> e.g. collective"
            << "\n  <password distributions> e.g. data/pguess_metrics_cache.tsv"
            << endl;
        return -1;
    }
    const char *initial_population_path = argv[1];
    const char *primitives_path = argv[2];
    const char *password_targets_path = argv[3];
    const char *initial_passwords_path = argv[4];
    int cycles = atoi(argv[5]);
    const char *strategy = argv[6];
    // for computing password strengths
    const char *pw_distribution_path = argv[7];
    StrengthMap password_strengths;
    PGV partial_guess_data;
    LOG(INFO) << "Loading partial guess metrics...";
    partial_guess_data = get_pguess_metrics(pw_distribution_path);
    (void) compute_strength_unseen(partial_guess_data);
    password_strengths = make_strength_map(partial_guess_data);
    LOG(INFO) << "Loading initial population from " << initial_population_path;
    vector<string> rules_vec = RuleLoader::load_rules<string>(initial_population_path);
    vector<Rule> rules;
    for (const auto &r : rules_vec) {
        rules.emplace_back(r);
    }
    LOG(INFO) << "Loading primitives from " << primitives_path;
    vector<string> primitives = RuleLoader::load_rules<string>(primitives_path);
    LOG(INFO) << "Loading password targets from " << password_targets_path;
    vector<string> target_passwords = PasswordLoader::load_passwords(password_targets_path);
    rax *pw_tree_targets = build_target_password_tree(target_passwords);
    LOG(INFO) << "Loading initial passwords from " << initial_passwords_path;
    vector<string> initial_passwords = PasswordLoader::load_passwords(initial_passwords_path);
    rax *pw_tree_initial = build_initial_password_tree(initial_passwords);
    LOG(INFO) << "Starting genetic algorithm with " << cycles << " cycles";
    Genetic genetic(rules,
            primitives,
            target_passwords,
            pw_tree_targets,
            initial_passwords,
            pw_tree_initial,
            password_strengths);
    genetic.run(cycles, ("collective" == string(strategy)) ? COLLECTIVE : INDIVIDUAL);
    genetic.delete_trees();
    LOG(INFO) << "Program terminated naturally";
}
