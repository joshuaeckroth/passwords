//
// Created by josh on 12/21/23.
//

#include <vector>
#include <string>
#include "genetic.h"
#include "rule_loader.h"
using namespace std;

int main() {
    vector<string> rules_vec = RuleLoader::load_rules<string>("rules/best64.rule");
    vector<Rule> rules;
    for (const auto &r: rules_vec) {
        rules.emplace_back(r);
    }
    Genetic genetic(rules);
    genetic.run(10);
}
