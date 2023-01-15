#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <stdio.h>
#include "analyze_tree.h"
#include "rule_data.h"
#include "password_data.h"

extern "C" {
#include <rax.h>
}

using std::cout, std::endl, std::string;

void analyze_rules(rax* rule_tree) {
    std::fstream results;
    std::fstream rulesout;
    results.open("results/rules_analysis.tsv", std::ios::out);
    rulesout.open("results/generated.rule", std::ios::out);
    // always put a no-op in generated set
    rulesout << ":\n";
    raxIterator it;
    raxStart(&it, rule_tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        RuleData *rdp = (RuleData*) it.data;
        char *k = (char*) malloc((int) it.key_len);
        memcpy(k, it.key, it.key_len);
        if (rdp->hit_count > 0) {
//            cout << "Rule: " << k << endl;
//            cout << "Hit count: " << rdp->hit_count << endl;
            size_t pos;
            string rule(k);
            while ((pos = rule.find("_SPACE_")) != std::string::npos) {
                rule.replace(pos, pos+7, " ");
            }
            results << k << "\t" << rdp->hit_count << "\n";
            rulesout << rule << "\n";
        }
        free(k);
    }
    raxStop(&it);
    results.close();
    rulesout.close();
}

void analyze_passwords(rax* pw_tree) {
    std::fstream results;
    results.open("results/passwords_analysis.tsv", std::ios::out);
    // always put a no-op in generated set
    raxIterator it;
    raxStart(&it, pw_tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        PasswordData *pdp = (PasswordData*) it.data;
        if(pdp->hit_count > 0) {
            results << it.key << "\t" << pdp->hit_count << "\n";
        }
    }
    raxStop(&it);
    results.close();
}

