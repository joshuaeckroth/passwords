//
// Created by josh on 12/21/23.
//

#include "genetic.h"
#include <algorithm>
#include <iostream>
using namespace std;

Genetic::Genetic(vector<Rule> &rules) : population(rules) {}

Genetic::~Genetic() {
}

void Genetic::run(int num_generations) {
    for (int i = 0; i < num_generations; i++) {
        cout << "generation " << i << endl;
        pair<Rule, Rule> parents = select_parents();
        cout << "parents: " << parents.first.get_rule_clean() << " and " << parents.second.get_rule_clean() << endl;
        pair<Rule, Rule> children = crossover(parents);
        cout << "children: " << children.first.get_rule_clean() << " and " << children.second.get_rule_clean() << endl;
        mutate(children.first);
        mutate(children.second);
        cout << "mutated children: " << children.first.get_rule_clean() << " and " << children.second.get_rule_clean() << endl;
        children.first.reset_weight();
        children.second.reset_weight();
        population.push_back(children.first);
        population.push_back(children.second);
        // sort by fitness
        sort(population.begin(), population.end(), [&](const Rule &a, const Rule &b) {
            return evaluate_fitness(a) < evaluate_fitness(b);
        });
        population.pop_back(); // remove two lowest-fitness rules
        population.pop_back();
    }
}

pair<Rule, Rule> Genetic::select_parents() {
    // pick top two parents
    return make_pair(population[0], population[1]);
}

// TODO: update Rule class to keep a parsed version (discrete primitives)
pair<Rule, Rule> Genetic::crossover(const pair<Rule, Rule>& parents) {
    // TODO: fix this, currently just imagining it's a string, not a sequence of primitives
    string rule_a = parents.first.get_rule_clean();
    string rule_b = parents.second.get_rule_clean();
    int crossover_point = rand() % rule_a.size(); // TODO: ensure crossover point is not beyond size of both rules
    string child_a = rule_a.substr(0, crossover_point) + rule_b.substr(crossover_point);
    string child_b = rule_b.substr(0, crossover_point) + rule_a.substr(crossover_point);
    return make_pair(Rule(child_a), Rule(child_b));
}

// TODO: don't treat as a string; use actual primitives for mutation
Rule Genetic::mutate(const Rule &rule) {
    string rule_str = rule.get_rule_clean();
    int mutation_point = rand() % rule_str.size();
    rule_str[mutation_point] = 'a' + (rand() % 26);
    return Rule(rule_str);
}

double Genetic::evaluate_fitness(const Rule &rule) {
    // run against a set of passwords and see how many it cracks
    return 0.0;
}