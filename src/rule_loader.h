#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <vector>
#include "rule.h"

namespace RuleLoader {
    std::vector<Rule> load_rules(const char*);
}

#endif /* RULE_LOADER_H */
