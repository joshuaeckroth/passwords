#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <memory>
#include <utility>
#include <unordered_map>
#include <unistd.h>
#include "util.h"
#include "password_loader.h"
#include "rule.h"
#include "rule_loader.h"
#include "password_data.h"
#include "tree_builder.h"
#include "analyze_tree.h"
#include "partial_guessing.h"

extern "C" {
#include <rax.h>
}

using std::set, std::vector, std::string, std::cout, std::endl;

int main(int argc, const char **argv) {
//    cout << sha1("password") << endl;
//    cout << sha1("12345") << endl;
    cout << "gentree starting..." << endl;
    string password_list, rule_list, dictionary, pw_distribution_fp;
    int count_per_cycle, num_cycles;
    float score_decay_factor;
    int opt;
    while (((opt = getopt(argc, (char * const *) argv, "w:d:")) != -1)) {
        switch (opt) {
            case 'w':
                dictionary = optarg;
                break;
            case 'd':
                pw_distribution_fp = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d password distribution file] <password list> <rule list> <pwd count per cycle> <num cycles> <score decay factor> [-w dictionary wordlist]\n", argv[0]);
                return -1;
        }
    }
    if (optind < argc) {
        int i = optind;
        password_list = argv[i++];
        cout << "password_list: " << password_list << endl;
        rule_list = argv[i++];
        cout << "rule_list: " << rule_list << endl;
        count_per_cycle = atoi(argv[i++]);
        cout << "count_per_cycle: " << count_per_cycle << endl;
        num_cycles = atoi(argv[i++]);
        cout << "num_cycles: " << num_cycles << endl;
        score_decay_factor = atof(argv[i++]);
        cout << "score_decay_factor: " << score_decay_factor << endl;
    } else {
        fprintf(stderr, "Usage: %s [-d password distribution file] <password list> <rule list> <pwd count per cycle> <num cycles> <score decay factor> [-w dictionary wordlist] [-d password distribution file]\n", argv[0]);
        return -1;
    }
    vector<string> rules_vec = RuleLoader::load_rules<string>(rule_list.c_str());
    set<string> rules;
    for (auto r : rules_vec) {
        rules.insert(r);
    }
    cout << "Loaded rules successfully..." << endl;
    vector<string> pws = PasswordLoader::load_passwords(password_list.c_str());
    vector<string> *passwords = &pws;
    cout << "Loaded passwords successfully..." << endl;
    vector<string> *dict_words = nullptr;
    vector<string> dw;
    if (dictionary != "") {
        cout << "Reading dictionary..." << endl;
        dw = PasswordLoader::load_passwords(dictionary.c_str());
        dict_words = &dw;
    }
    std::unordered_map<string, PartialGuessData> distribution;
    if (pw_distribution_fp != "") {
        cout << "Reading password distributions..." << endl;
        distribution = read_distribution(pw_distribution_fp);
        PGV prob_vec = to_probability_vec(distribution);
        generate_partial_guessing_strengths(prob_vec);
        print_pgd(prob_vec);
    }
    TreeBuilder tb(passwords, dict_words, rules, count_per_cycle, score_decay_factor);
    tb.build(num_cycles);
    rax *pw_tree_processed = tb.get_password_tree_processed();
    /*
    cout << "Processed passwords:" << endl;
    raxShow(pw_tree_processed);
    cout << "Unprocessed passwords:" << endl;
    rax *pw_tree_unprocessed = tb.get_password_tree_unprocessed();
    raxShow(pw_tree_unprocessed);
     */
    rax *rule_tree = tb.get_rule_tree();
    //raxShow(rule_tree);
    analyze_rules(rule_tree);
    analyze_passwords(pw_tree_processed);
    return 0;
}

