#include <vector>
#include <string>
#include "genetic.h"
#include "rule_loader.h"
#include "password_loader.h"
using namespace std;

int main() {
    //load rules
    vector<string> rules_vec = RuleLoader::load_rules<string>("rules/best64.rule");
    vector<Rule> rules;
    for (const auto &r: rules_vec) {
        rules.emplace_back(r);
    }
    //load passwords
    vector<string> pws = PasswordLoader::load_passwords("data/passwords_8.txt");
    vector<string> *passwords = &pws;

    //call genetic constructor
    Genetic genetic(rules, *passwords);
    genetic.run(10);
}
