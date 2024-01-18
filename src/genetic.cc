#include <algorithm>
#include <set>
#include <iostream>
#include <functional>
#include <random>
#include <numeric>
#include <utility>
#include "genetic.h"
#include "tree_builder.h"
#include "rule.h"
#include "password_data.h"
#include "util.h"

extern "C" {
#include <rax.h>
}

using namespace std;

Genetic::Genetic(vector<Rule> &rules, vector<string> &primitives, vector<string> &target_passwords, rax *pw_tree_targets, size_t max_pop)
    : primitives(primitives), target_passwords(target_passwords), pw_tree_targets(pw_tree_targets), max_pop(max_pop) {
    population_vec = rules;
    population = deque<Rule>(rules.begin(), rules.end());
    initialize_rule_replacements();
}

Genetic::~Genetic() {}

void Genetic::add_to_population(Rule &rule, const Rule& parent_a, const Rule& parent_b, const int &top_score) {
    if (rule == parent_a || rule == parent_b) {
        return;
    }
    float fitness = evaluate_fitness(rule, parent_a, parent_b, top_score);
    rule.set_score(fitness);
    if (population.empty()) {
        population.push_back(rule);
        return;
    }
    for (auto it = population.begin(); it != population.end(); it++) {
        if (fitness > it->get_score()) {
            if (it->get_rule_clean() == rule.get_rule_clean()) {
                return;
            }
            population.insert(it, rule);
            return;
        }
    }
    population.push_back(rule);
}


// returns a count of the number of *unique* password targets hit
size_t Genetic::evaluate_population_fitness(vector<Rule> pop) {
    size_t score = 0;
    std::set<string> unique_hits;
    for (auto &rule : pop) {
        for (auto &pw : this->target_passwords) {
            string new_pw = rule.apply_rule(pw);
            if (new_pw == pw) continue; // noop
            if (in_radix(this->pw_tree_targets, new_pw)) {
                unique_hits.insert(new_pw);
            }
        }
    }
    return unique_hits.size();
}

void Genetic::run(size_t num_generations, EvolutionStrategy strategy) {
    if (strategy == COLLECTIVE) {
        while (this->population_vec.size() < POPULATION_SIZE) {
            this->population_vec.insert(this->population_vec.end(),
                    this->population_vec.begin(),
                    this->population_vec.end());
        }
        vector<Rule> tmp_vec;
        for (size_t idx = 0; idx < POPULATION_SIZE; idx++) {
            tmp_vec.push_back(this->population_vec[idx]);
        }
        this->population_vec = tmp_vec;
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(this->population_vec.begin(),
                this->population_vec.end(),
                std::default_random_engine(seed));
        for (size_t idx = 0; idx < num_generations; idx++) {
            /* 
             * Select individuals for mating...
             * For population level fitness we care about
             * how rules contribute to overall fitness -
             * choose individuals for mating based on
             * which subgroups get the biggest number of
             * _unique_ hits on targets.
             */
            typedef std::pair<std::vector<Rule>, size_t> eval_pair;
            vector<eval_pair> subgroup_evals;
            size_t partition_size = POPULATION_SIZE / POPULATION_PARTITIONS;
            for (size_t j = 0; j < POPULATION_PARTITIONS; j++) {
                vector<Rule> partition;
                partition.reserve(partition_size);
                std::copy(this->population_vec.begin() + (j * partition_size),
                        this->population_vec.begin() + ((j + 1) * partition_size),
                        std::back_inserter(partition));
                subgroup_evals.push_back({partition, 0});
            }
            // TODO: parallelize
            for (auto &group : subgroup_evals) {
                size_t fitness = this->evaluate_population_fitness(group.first);
                group.second = fitness;
            }
            std::sort(subgroup_evals.begin(), subgroup_evals.end(),
                    [](eval_pair a, eval_pair b) { return a.second > b.second; });
            for (auto &group : subgroup_evals) {
                cout << "Fitness: " << group.second << endl;
            }
            /*
             * Mate individuals "randomly" from two subgroups deemed
             * most effective. Randomly to prevent the same pairs
             * from mating multiple times when the same groups are
             * the most effective in multiple runs. IDEA: rotate the
             * second group by an offset of idx to prevent having to
             * shuffle/choose randomly.
             */
            // TODO: CROSSOVER
            /*
             * Mutate some small number of individuals
             */
            // TODO: MUTATION
            /*
             * Add new group of individuals to the population to
             * replace a weaker group of individuals
             */
            // TODO: Replace worst-performing group in population with new group
            return;
        }
    } else {
        size_t top_score = 0;
        for (size_t i = 0; i < num_generations; i++) {
            cout << "generation " << i << endl;
            pair<Rule, Rule> parents = select_parents();
            cout << "parents: " << parents.first.get_rule_clean() << " and " << parents.second.get_rule_clean() << endl;
            vector<Rule> children = crossover(parents);
            for (Rule child: children) {
                if (child.get_tokens().size() > 10) {
                    cout << "Skipping child with too many tokens: " << child.get_rule_clean() << endl;
                    continue;
                }
                cout << "child: " << child.get_rule_clean() << endl;
                // select mutation type
                size_t type_idx = random_integer(0, 4);
                auto type = (MutationType) type_idx;
                child = mutate(child, type);
                cout << "mutated child: " << child.get_rule_clean() << endl;
                string child_simplified_str = simplify_rule(child.get_rule_clean());
                cout << "Child: " << child.get_rule_clean() << " simplified to: " << child_simplified_str << endl;
                if (!child_simplified_str.empty()) {
                    Rule child_simplified = Rule(child_simplified_str);
                    add_to_population(child_simplified, parents.first, parents.second, top_score);
                }
            }
            if (population.size() > max_pop) {
                cout << "Removing lowest-fitness rules" << endl;
                size_t remove_count = population.size() - max_pop;
                for (size_t j = 0; j < remove_count; j++) {
                    cout << "Dropped rule: " << population.back().get_rule_clean() << " with score "
                        << population.back().get_score() << endl;
                    population.pop_back();
                }
            }
            top_score = population.front().get_score();
            cout << "Best 10 rules:" << endl;
            for (size_t j = 0; j < 10; j++) {
                cout << population[j].get_rule_clean() << " with score " << population[j].get_score() << endl;
            }
            cout << "Population size: " << population.size() << endl;
        }
    }
}

pair<Rule, Rule> Genetic::select_parents() {
    for (auto it = population.begin(); it != population.end(); it++) {
        Rule& first = *it;
        Rule& second = *(it+1);
        pair<Rule, Rule> parents = make_pair(first, second);
        if (!breed_pairs.contains(parents)) {
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
    if (rule_a_tokens.size() <= 2 || rule_b_tokens.size() <= 2) {
        Rule concat_rule = Rule::join_primitives({parents.first.get_rule_clean(), parents.second.get_rule_clean()});
        return {concat_rule};
    }
    size_t crossover_point = 1 + random_integer(0, min(rule_a_tokens.size(), rule_b_tokens.size()) - 2);
    //int crossover_point = 1 + rand() % (min(rule_a_tokens.size(), rule_b_tokens.size()) - 1);
    cout << "crossover point: " << crossover_point << endl;
    /* consider: ABC and XYZ as the parents, crossover point 1 */
    vector<string> child_left_right_tokens, /* AYZ */
        child_right_left_tokens, /* XBC */
        child_concat_tokens, /* AYZXBC */
        child_concat_reverse_tokens, /* XBCAYZ */
        child_left_tokens, /* A */
        child_right_tokens, /* X */
        child_left_rest_tokens, /* BC */
        child_right_rest_tokens, /* YZ */
        child_orig_concat_tokens, /* ABCXYZ */
        child_orig_concat_tokens_reverse; /* XBCAYZ */
    for (int i = 0; i < crossover_point; i++) {
        child_left_right_tokens.push_back(rule_a_tokens[i]);
        child_right_left_tokens.push_back(rule_b_tokens[i]);
        child_left_tokens.push_back(rule_a_tokens[i]);
        child_right_tokens.push_back(rule_b_tokens[i]);
    }
    for (int i = crossover_point; i < rule_a_tokens.size(); i++) {
        child_right_left_tokens.push_back(rule_a_tokens[i]);
        child_left_rest_tokens.push_back(rule_a_tokens[i]);
    }
    for (int i = crossover_point; i < rule_b_tokens.size(); i++) {
        child_left_right_tokens.push_back(rule_b_tokens[i]);
        child_right_rest_tokens.push_back(rule_b_tokens[i]);
    }
    child_concat_tokens.insert(child_concat_tokens.end(), child_left_right_tokens.begin(), child_left_right_tokens.end());
    child_concat_tokens.insert(child_concat_tokens.end(), child_right_left_tokens.begin(), child_right_left_tokens.end());
    child_concat_reverse_tokens.insert(child_concat_reverse_tokens.end(), child_right_left_tokens.begin(), child_right_left_tokens.end());
    child_concat_reverse_tokens.insert(child_concat_reverse_tokens.end(), child_left_right_tokens.begin(), child_left_right_tokens.end());
    child_orig_concat_tokens.insert(child_orig_concat_tokens.end(), rule_a_tokens.begin(), rule_a_tokens.end());
    child_orig_concat_tokens.insert(child_orig_concat_tokens.end(), rule_b_tokens.begin(), rule_b_tokens.end());
    child_orig_concat_tokens_reverse.insert(child_orig_concat_tokens_reverse.end(), rule_b_tokens.begin(), rule_b_tokens.end());
    child_orig_concat_tokens_reverse.insert(child_orig_concat_tokens_reverse.end(), rule_a_tokens.begin(), rule_a_tokens.end());
    Rule child_rule_a = Rule::join_primitives(child_left_right_tokens);
    Rule child_rule_b = Rule::join_primitives(child_right_left_tokens);
    Rule child_rule_c = Rule::join_primitives(child_concat_tokens);
    Rule child_rule_d = Rule::join_primitives(child_concat_reverse_tokens);
    Rule child_rule_e = Rule::join_primitives(child_left_tokens);
    Rule child_rule_f = Rule::join_primitives(child_right_tokens);
    Rule child_rule_g = Rule::join_primitives(child_left_rest_tokens);
    Rule child_rule_h = Rule::join_primitives(child_right_rest_tokens);
    Rule child_rule_i = Rule::join_primitives(child_orig_concat_tokens);
    Rule child_rule_j = Rule::join_primitives(child_orig_concat_tokens_reverse);
    return {child_rule_a, child_rule_b, child_rule_c, child_rule_d, child_rule_e,
            child_rule_f, child_rule_g, child_rule_h, child_rule_i, child_rule_j};
}

Rule Genetic::mutate(const Rule &rule, MutationType type) {
    if (type == NO_MUTATION) {
        return rule;
    }
    auto rule_primitives = rule.get_primitives();
    size_t prim_count = rule_primitives.size();
    size_t idx = random_integer(0, prim_count - ((type == INSERT) ? 0 : 1));
    auto it = rule_primitives.begin() + idx;
    string primitive = "";
    if (type == INSERT || type == SUBSTITUTE) {
        size_t prim_idx = random_integer(0, this->primitives.size() - 1);
        primitive = this->primitives[prim_idx];
    }
    switch (type) {
        case INSERT:
            rule_primitives.insert(it, primitive);
            break;
        case DELETE:
            rule_primitives.erase(it);
            break;
        case SUBSTITUTE:
            rule_primitives[idx] = primitive;
            break;
        case DUPLICATE:
            rule_primitives.insert(it, rule_primitives[idx]);
            break;
        case NO_MUTATION:
            return rule;
    }
    return Rule::join_primitives(rule_primitives);
}

// run against a set of passwords and see how many it cracks
float Genetic::evaluate_fitness(const Rule &rule, const Rule &parent_a, const Rule &parent_b, const int &top_score) {
    int N = max(10, top_score) * 2;
    float score = 0.0;
    // generate vector of N random positions
    vector<size_t> positions;
    for (size_t i = 0; i < N; i++) {
        positions.push_back(random_integer(0, this->target_passwords.size() - 1));
    }
    // transform a password (passwords set in constructor)
    int no_op_count = 0;
    for (unsigned long position : positions) {
        string password = this->target_passwords[position];
	    //apply rule
    	string new_pw = rule.apply_rule(password);
        string new_pw_parent_a = parent_a.apply_rule(password);
        string new_pw_parent_b = parent_b.apply_rule(password);
        if (new_pw == password || new_pw_parent_a == new_pw || new_pw_parent_b == new_pw) {
            no_op_count++;
        }
		//check password set for hits with the transformed password
		//transformed password is in the tree
		if ((raxFind(this->pw_tree_targets, (unsigned char*)new_pw.c_str(), new_pw.size()+1)) != raxNotFound) {
            score+=1.0;
        }
    }
    if (no_op_count == N) {
        score = 0.0;
        cout << "No-op rule detected: " << rule.get_rule_clean() << endl;
    }
    return score;
}

