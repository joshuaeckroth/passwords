#ifndef ANALYZE_TREE
#define ANALYZE_TREE

extern "C" {
#include <rax.h>
}

void analyze_rules(rax*);
void analyze_passwords(rax*);

#endif /* ANALYZE_TREE */
