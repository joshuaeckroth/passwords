#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <memory>
#include "util.h"
#include "password_loader.h"
#include "rule.h"
#include "rule_loader.h"
#include "password_data.h"
#include "tree_builder.h"
#include "analyze_tree.h"

extern "C" {
#include <rax.h>
}

using std::set, std::vector, std::string, std::cout, std::endl;

int main(int argc, const char **argv) {
    cout << "gentree starting..." << endl;
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "Usage: %s <password list> <rule list> <pwd count per cycle> <num cycles> <score decay factor> <optional: dictionary>\n", argv[0]);
        return -1;
    }
    vector<string> rules_vec = RuleLoader::load_rules<string>(argv[2]);
    set<string> rules;
    for (auto r : rules_vec) {
        rules.insert(r);
    }
    cout << "Loaded rules successfully..." << endl;
    vector<string> pws = PasswordLoader::load_passwords(argv[1]);
    vector<string> *passwords = &pws;
    cout << "Loaded passwords successfully..." << endl;
    vector<string> *dict_words = nullptr;
    vector<string> dw;
    if (argc == 7) {
        dw = PasswordLoader::load_passwords(argv[6]);
        dict_words = &dw;
    }
    TreeBuilder tb(passwords, dict_words, rules, atoi(argv[3]), atof(argv[5]), atoi(argv[4]));
    //cout << tb.check_intermediate(0, "$1 $2 $3 { }", "password123") << endl;
    tb.build();
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

