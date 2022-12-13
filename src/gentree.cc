#include <iostream>
#include <vector>
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

using std::vector, std::string, std::cout, std::endl;

int main(int argc, const char **argv) {
    cout << "gentree starting..." << endl;
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <password list> <rule list>\n", argv[0]);
        return -1;
    }
    vector<string> rules = RuleLoader::load_rules<string>(argv[2]);
    cout << "Loaded rules successfully..." << endl;
    vector<string> passwords = PasswordLoader::load_passwords(argv[1]);
    cout << "Loaded passwords successfully..." << endl;
    TreeBuilder tb(passwords, rules, 1000);
    tb.build(100);
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
