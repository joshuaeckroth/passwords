#include <algorithm>
#include <iostream>
#include "genetic.h"
#include "tree_builder.h"
#include "rule.h"
#include "password_data.h"

extern "C" {
#include <rax.h>
}

using namespace std;

Genetic::Genetic(vector<Rule> &rules, vector<string> &primitives, vector<string> &target_passwords, rax *pw_tree_targets, int max_pop)
    : primitives(primitives), target_passwords(target_passwords), pw_tree_targets(pw_tree_targets), max_pop(max_pop) {
    population = deque<Rule>(rules.begin(), rules.end());
    initialize_rule_replacements();
    srand(0);
}

Genetic::~Genetic() {}

void Genetic::add_to_population(Rule &rule, const Rule& parent_a, const Rule& parent_b, const int &top_score) {
    if(rule == parent_a || rule == parent_b) {
        return;
    }
    float fitness = evaluate_fitness(rule, parent_a, parent_b, top_score);
    rule.set_score(fitness);
    if (population.empty()) {
        population.push_back(rule);
        return;
    }
    for(auto it = population.begin(); it != population.end(); it++) {
        if(fitness > it->get_score()) {
            if(it->get_rule_clean() == rule.get_rule_clean()) {
                return;
            }
            population.insert(it, rule);
            return;
        }
    }
    population.push_back(rule);
}

void Genetic::run(int num_generations) {
    int top_score = 0;
    for (int i = 0; i < num_generations; i++) {
        cout << "generation " << i << endl;
        pair<Rule, Rule> parents = select_parents();
        cout << "parents: " << parents.first.get_rule_clean() << " and " << parents.second.get_rule_clean() << endl;
        vector<Rule> children = crossover(parents);
        for(Rule child: children) {
            if(child.get_tokens().size() > 10) {
                cout << "Skipping child with too many tokens: " << child.get_rule_clean() << endl;
                continue;
            }
            cout << "child: " << child.get_rule_clean() << endl;
            auto type_idx = (size_t) rand() % 5;
            auto type = (MutationType) type_idx;
            child = mutate(child, type);
            cout << "mutated child: " << child.get_rule_clean() << endl;
            string child_simplified_str = simplify_rule(child.get_rule_clean());
            cout << "Child: " << child.get_rule_clean() << " simplified to: " << child_simplified_str << endl;
            if(!child_simplified_str.empty()) {
                Rule child_simplified = Rule(child_simplified_str);
                add_to_population(child_simplified, parents.first, parents.second, top_score);
            }
        }
        if(population.size() > max_pop) {
            cout << "Removing lowest-fitness rules" << endl;
            int remove_count = population.size() - max_pop;
            for (int j = 0; j < remove_count; j++) {
                cout << "Dropped rule: " << population.back().get_rule_clean() << " with score "
                     << population.back().get_score() << endl;
                population.pop_back();
            }
        }
        top_score = population.front().get_score();
        cout << "Best 10 rules:" << endl;
        for(int j = 0; j < 10; j++) {
            cout << population[j].get_rule_clean() << " with score " << population[j].get_score() << endl;
        }
        cout << "Population size: " << population.size() << endl;
    }
}

pair<Rule, Rule> Genetic::select_parents() {
    for(auto it = population.begin(); it != population.end(); it++) {
        Rule& first = *it;
        Rule& second = *(it+1);
        pair<Rule, Rule> parents = make_pair(first, second);
        if(breed_pairs.find(parents) == breed_pairs.end()) {
            breed_pairs.insert(parents);
            return parents;
        }
    }
    cout << "No parents found, returning first two rules" << endl;
    return make_pair(population.front(), population.front());
}

vector<Rule> Genetic::crossover(const pair<Rule, Rule>& parents) {
    vector<string> rule_a_tokens = parents.first.get_tokens();
    vector<string> rule_b_tokens = parents.second.get_tokens();
    if(rule_a_tokens.size() <= 2 || rule_b_tokens.size() <= 2) {
        Rule concat_rule = Rule::join_primitives({parents.first.get_rule_clean(), parents.second.get_rule_clean()});
        return {concat_rule};
    }
    uniform_int_distribution<int> uniform_dist(1, min(rule_a_tokens.size(), rule_b_tokens.size())-2);
    int crossover_point = 1 + rand() % (min(rule_a_tokens.size(), rule_b_tokens.size()) - 1);
    cout << "crossover point: " << crossover_point << endl;
    vector<string> child_left_right_tokens, child_right_left_tokens, child_concat_tokens, child_concat_reverse_tokens,
            child_left_tokens, child_right_tokens;
    for (int i = 0; i < crossover_point; i++) {
        child_left_right_tokens.push_back(rule_a_tokens[i]);
        child_right_left_tokens.push_back(rule_b_tokens[i]);
        child_left_tokens.push_back(rule_a_tokens[i]);
        child_right_tokens.push_back(rule_b_tokens[i]);
    }
    for (int i = crossover_point; i < rule_a_tokens.size(); i++) {
        child_right_left_tokens.push_back(rule_a_tokens[i]);
    }
    for (int i = crossover_point; i < rule_b_tokens.size(); i++) {
        child_left_right_tokens.push_back(rule_b_tokens[i]);
    }
    child_concat_tokens.insert(child_concat_tokens.end(), child_left_right_tokens.begin(), child_left_right_tokens.end());
    child_concat_tokens.insert(child_concat_tokens.end(), child_right_left_tokens.begin(), child_right_left_tokens.end());
    child_concat_reverse_tokens.insert(child_concat_reverse_tokens.end(), child_right_left_tokens.begin(), child_right_left_tokens.end());
    child_concat_reverse_tokens.insert(child_concat_reverse_tokens.end(), child_left_right_tokens.begin(), child_left_right_tokens.end());
    Rule child_rule_a = Rule::join_primitives(child_left_right_tokens);
    Rule child_rule_b = Rule::join_primitives(child_right_left_tokens);
    Rule child_rule_c = Rule::join_primitives(child_concat_tokens);
    Rule child_rule_d = Rule::join_primitives(child_concat_reverse_tokens);
    Rule child_rule_e = Rule::join_primitives(child_left_tokens);
    Rule child_rule_f = Rule::join_primitives(child_right_tokens);
    return {child_rule_a, child_rule_b, child_rule_c, child_rule_d, child_rule_e, child_rule_f};
}

Rule Genetic::mutate(const Rule &rule, MutationType type) {
    if(type == NO_MUTATION) {
        return rule;
    }
    auto primitives = rule.get_primitives();
    size_t prim_count = primitives.size();
    size_t idx = (size_t) rand() % prim_count + ((type == INSERT) ? 1 : 0);
    auto it = primitives.begin() + idx;
    string primitive = "";
    if (type == INSERT || type == SUBSTITUTE) {
        size_t prim_idx = (size_t) rand() % this->primitives.size();
        primitive = this->primitives[prim_idx];
    }
    switch (type) {
        case INSERT:
            primitives.insert(it, primitive);
            break;
        case DELETE:
            primitives.erase(it);
            break;
        case SUBSTITUTE:
            primitives[idx] = primitive;
            break;
        case DUPLICATE:
            primitives.insert(it, primitives[idx]);
            break;
    }
    return Rule::join_primitives(primitives);
}

// run against a set of passwords and see how many it cracks
float Genetic::evaluate_fitness(const Rule &rule, const Rule &parent_a, const Rule &parent_b, const int &top_score) {
    int N = max(10, top_score) * 2;
    float score = 0.0;
    // generate vector of N random positions
    vector<size_t> positions;
    for (size_t i = 0; i < N; i++) {
        positions.push_back(rand() % this->target_passwords.size());
    }
    // transform a password (passwords set in constructor)
    int no_op_count = 0;
    for (unsigned long position : positions) {
        string password = this->target_passwords[position];
	    //apply rule
    	string new_pw = rule.apply_rule(password);
        string new_pw_parent_a = parent_a.apply_rule(password);
        string new_pw_parent_b = parent_b.apply_rule(password);
        if(new_pw == password || new_pw_parent_a == new_pw || new_pw_parent_b == new_pw) {
            no_op_count++;
        }
		//check password set for hits with the transformed password
		//transformed password is in the tree
		if ((raxFind(this->pw_tree_targets, (unsigned char*)new_pw.c_str(), new_pw.size()+1)) != raxNotFound) {
            score+=1.0;
        }
    }
    if(no_op_count == N) {
        score = 0.0;
        cout << "No-op rule detected: " << rule.get_rule_clean() << endl;
    }
    return score;
}
