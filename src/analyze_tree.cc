#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <stdio.h>
#include "analyze_tree.h"
#include "rule_data.h"

extern "C" {
#include <rax.h>
}

using std::cout, std::endl, std::string;

AnalyzeTree::AnalyzeTree(rax *rt) : rule_tree(rt) {}

//  snprintf(char * __restrict __str, size_t __size, const char * __restrict __format, ...) __printflike(3, 4);

void AnalyzeTree::analyze() {
    std::fstream results;
    std::fstream rulesout;
    results.open("results/analyze_results.tsv", std::ios::out);
    rulesout.open("results/generated.rule", std::ios::out);
    raxIterator it;
    raxStart(&it, this->rule_tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        RuleData *rdp = (RuleData*) it.data;
        char *k = (char*) malloc((int) it.key_len);
        memcpy(k, it.key, it.key_len);
        if (rdp->hit_count > 0) {
            cout << "Rule: " << k << endl;
            cout << "Hit count: " << rdp->hit_count << endl;
            results << k << "\t" << rdp->hit_count << "\n";
            rulesout << k << "\n";
        }
        free(k);
    }
    raxStop(&it);
    results.close();
    rulesout.close();
}
