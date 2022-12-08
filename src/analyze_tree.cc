#include <iostream>
#include "analyze_tree.h"
#include "rule_data.h"

extern "C" {
#include <rax.h>
}

using std::cout, std::endl;

AnalyzeTree::AnalyzeTree(rax *rt) : rule_tree(rt) {}

void AnalyzeTree::analyze() {
    cout << "called this" << endl;
    raxIterator it;
    raxStart(&it, this->rule_tree);
    raxSeek(&it, "^", (unsigned char*) "foo", 3);
    while (raxNext(&it)) {
        cout << "iterated" << endl;
        RuleData *rdp = (RuleData*) it.data;
        //const char 
        cout << (char*) it.key << endl;
        cout << rdp->hit_count << endl;
    }
}
