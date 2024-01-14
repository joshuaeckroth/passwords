#include <vector>
#include <string>
#include "genetic.h"
#include "rule_loader.h"
using namespace std;

int main() {
    vector<string> rules_vec = RuleLoader::load_rules<string>("rules/best64.rule");
    vector<string> primitives = RuleLoader::load_rules<string>("rules/primitives.rule");
    vector<Rule> rules;
    for (const auto &r: rules_vec) {
        rules.emplace_back(r);
    }
    Genetic genetic(rules, primitives);
    genetic.run(10);
}
