#ifndef ANALYZE_TREE
#define ANALYZE_TREE

extern "C" {
#include <rax.h>
}

// Analyzes a rule tree
class AnalyzeTree {
    private:
        rax *rule_tree;
    public:
        AnalyzeTree(rax*);
        void analyze();
};

#endif /* ANALYZE_TREE */
