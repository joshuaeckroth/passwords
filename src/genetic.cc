#include "genetic.h"
#include "tree_builder.h"
#include <algorithm>
#include <iostream>
#include <random>
using namespace std;

Genetic::Genetic(vector<Rule> &rules, vector<string> &primitives, vector<string> *target_passwords) : population(rules), primitives(primitives), target_passwords(target_passwords), rand_generator(rd()) {}

Genetic::~Genetic() {
}

void Genetic::run(int num_generations) {
    for (int i = 0; i < num_generations; i++) {
        cout << "generation " << i << endl;
        pair<Rule, Rule> parents = select_parents();
        cout << "parents: " << parents.first.get_rule_clean() << " and " << parents.second.get_rule_clean() << endl;
        vector<Rule> children = crossover(parents);
        for(Rule child: children) {
            cout << "child: " << child.get_rule_clean() << endl;
//            mutate(child);
            cout << "mutated child: " << child.get_rule_clean() << endl;
            child.reset_weight();
            population.push_back(child);
        }
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

vector<Rule> Genetic::crossover(const pair<Rule, Rule>& parents) {
    vector<string> rule_a_tokens = parents.first.get_tokens();
    vector<string> rule_b_tokens = parents.second.get_tokens();
    if(rule_a_tokens.size() <= 2 || rule_b_tokens.size() <= 2) {
        Rule concat_rule = Rule::join_primitives({parents.first.get_rule_clean(), parents.second.get_rule_clean()});
        return {concat_rule};
    }
    uniform_int_distribution<int> uniform_dist(1, min(rule_a_tokens.size(), rule_b_tokens.size())-2);
    int crossover_point = uniform_dist(rand_generator);
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
    auto primitives = rule.get_primitives();
    size_t prim_count = primitives.size();
    std::random_device dev;
    std::mt19937 rng(dev());
    typedef std::uniform_int_distribution<std::mt19937::result_type> dtype;
    dtype dist(0, prim_count - ((type == INSERT) ? 0 : 1));
    size_t idx = (size_t) dist(rng);
    auto it = primitives.begin() + idx;
    string primitive = "";
    if (type == INSERT || type == SUBSTITUTE) {
        dtype prim_dist(0, this->primitives.size() - 1);
        primitive = this->primitives[prim_dist(rng)];
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

// TODO: don't treat as a string; use actual primitives for mutation
Rule Genetic::mutate(const Rule &rule) {
    string rule_str = rule.get_rule_clean();
    int mutation_point = rand() % rule_str.size();
    rule_str[mutation_point] = 'a' + (rand() % 26);
    return Rule(rule_str);
}

// error: use of undeclared identifier 'target_passwords'
// run against a set of passwords and see how many it cracks
double Genetic::evaluate_fitness(const Rule &rule) {
    //tree builder for passwords
    TreeBuilder tb(target_passwords,
               dict_words,
               population, //rules
               count_per_cycle,
               score_decay_factor,
               num_cycles,
               pw_distribution_fp != "",
               password_strengths);

    rax *pw_tree_processed = tb.get_password_tree_processed();
    float score = 0.0;
    // transform a password (passwords set in constructor)

    for (const string& password : target_passwords) {
	    //apply rule
    	string new_pw = rule.apply_rule(password);
        cout << "New password:" << new_pw << endl;

		//check password set for hits with the transformed password
		//transformed password is in the tree
		if ((raxFind(this->pw_tree_processed, (unsigned char*) new_pw, strlen(new_pw)+1)) != raxNotFound) {
            score+=1.0;
        }
		/*for (const string& target : target_passwords) {
            	if (target == new_pw) {
	        	score+=1.0;
	    		}
        }*/
    }
    return score;
}
/*double Genetic::evaluate_fitness(const Rule &rule, const vector<string> *target_passwords) {
    // run against a set of passwords and see how many it cracks
	this->targets = target_passwords;
	//loop through passwords
	for(size_t idx = 0; idx < target_passwords->size(); idx++) {
        	string password = target_passwords->at(idx);
		//apply rule to password, then check against passwords
		char *new_pw = this->apply_rule(rule, password);
	}
    return hit_count;
}*/
