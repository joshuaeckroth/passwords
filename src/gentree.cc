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
    if(argc != 6) {
        fprintf(stderr, "Usage: %s <source word list> <password list> <rule list> <pwd count per cycle> <num cycles>\n", argv[0]);
        return -1;
    }
    vector<string> rules_vec = RuleLoader::load_rules<string>(argv[3]);
    set<string> rules;
    for(auto r : rules_vec) {
        rules.insert(r);
    }
    cout << "Loaded rules successfully..." << endl;

    vector<string> source_words = PasswordLoader::load_passwords(argv[1]);
    cout << "Loaded source words successfully..." << endl;

    vector<string> passwords = PasswordLoader::load_passwords(argv[2]);
    cout << "Loaded passwords successfully..." << endl;

    TreeBuilder tb(source_words, passwords, rules, atoi(argv[4]));
    tb.build(atoi(argv[5]));
    /*
    cout << "Processed passwords:" << endl;
    rax *pw_tree_processed = tb.get_password_tree_processed();
    raxShow(pw_tree_processed);
    cout << "Unprocessed passwords:" << endl;
    rax *pw_tree_unprocessed = tb.get_password_tree_unprocessed();
    raxShow(pw_tree_unprocessed);
    */
    rax *rule_tree = tb.get_rule_tree();
    //raxShow(rule_tree);
    AnalyzeTree at(rule_tree);
    at.analyze();
    return 0;
}
