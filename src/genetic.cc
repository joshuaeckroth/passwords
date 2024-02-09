#include <algorithm>
#include <set>
#include <iostream>
#include <functional>
#include <random>
#include <utility>
#include <thread>
#include <chrono>
#include "genetic.h"
#include "tree_builder.h"
#include "rule.h"
#include "password_data.h"
#include "util.h"
#include "partial_guessing.h"

extern "C" {
#include <rax.h>
}

using namespace std;

Genetic::Genetic(
        vector<Rule> &rules,
        vector<string> &primitives,
        vector<string> &target_passwords,
        rax *pw_tree_targets,
        vector<string> &initial_passwords,
        rax *pw_tree_initial,
        size_t max_pop,
        StrengthMap sm)
    : primitives(primitives),
      target_passwords(target_passwords),
      pw_tree_targets(pw_tree_targets),
      initial_passwords(initial_passwords),
      pw_tree_initial(pw_tree_initial),
      max_pop(max_pop),
      password_strengths(sm) {
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


//make village fitness the RPP
float Genetic::evaluate_population_fitness(vector<Rule> pop) {
    // rpp is the number of rules/ 100*(cracked/hashed)
    // cracked is number of passwords cracked by an entire village (so don't include passwords already cracked by the village)
    //what is hashed value here? the number of initial passwords

    // get the number of unique password targets hit by a rule set
    size_t target_count = this->target_passwords.size();
    size_t initial_count = this->initial_passwords.size();
    // TODO: cache this
    static float pct_cracked_no_rule = [&]() -> float {
        size_t cracked_count = 0;
        for (string &pw : this->initial_passwords) {
            if (in_radix(this->pw_tree_targets, pw)) {
                cracked_count++;
            }
        }
        return (cracked_count / (float) target_count) * 100.0f;
    }();
    cout << "pct cracked no rule: " << pct_cracked_no_rule << endl;
    std::set<string> unique_hits;
    for (auto &rule : pop) {
        for (auto &pw : this->initial_passwords) {
            unique_hits.insert(pw); // add all initial passwords to unique hits (to subtract from later)
            string new_pw = rule.apply_rule(pw);
            if (new_pw == pw) continue; // noop
            //cout << "rule: " << rule.get_rule_clean() << " applied to " << pw << " yields " << new_pw << endl;
            if (in_radix(this->pw_tree_targets, new_pw)) {
                cout << "hit: " << new_pw << endl;
                auto old_score = rule.get_score();
                auto search = this->password_strengths.find(new_pw);
                auto new_score = old_score + (
                    (search != this->password_strengths.end()) ? search->second : get_strength_unseen()
                );
                cout << "old score: " << old_score << ", new score: " << new_score << endl;
                rule.set_score(new_score); 
                unique_hits.insert(new_pw);
                cout << "unique hits: " << unique_hits.size() << endl;
            }
        }
    }
    int num_cracked = unique_hits.size();
    cout << "num cracked: " << num_cracked << endl;
    // parts of the rpp calculation:
    cout << "pop size: " << pop.size() << endl;
    cout << "target count: " << target_count << endl;
    cout << "num cracked: " << num_cracked << endl;
    cout << "pct cracked: " << (100.0f * ((float) num_cracked / (float) target_count)) << endl;
    cout << "pct cracked no rule: " << pct_cracked_no_rule << endl;
    cout << "rpp divider: " << (100.0f * ((float) num_cracked / (float) target_count)) - pct_cracked_no_rule << endl;
    cout << "rpp: " << (float) pop.size() / ((100.0f * ((float) num_cracked / (float) target_count)) - pct_cracked_no_rule) << endl;
    float rpp = (float) pop.size() / ((100.0f * ((float) num_cracked / (float) target_count)) - pct_cracked_no_rule);
    return rpp;
    /*
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
    */
}

void Genetic::run(size_t num_generations, EvolutionStrategy strategy) {
    if (strategy == COLLECTIVE) {
        for (size_t idx = 0; idx < VILLAGE_COUNT; idx++) {
            Village v(this->population_vec);
            this->villages.push_back(v);
        }
        for (size_t idx = 0; idx < num_generations; idx++) {
            size_t num_villages = this->villages.size();
            cout << "*** Generation: " << idx + 1 << ", village count: " << num_villages << endl;
            /* 
             * Select individuals for mating...
             * For population level fitness we care about
             * RPP (rules per percentage cracked). For
             * individual fitness we care about the strength
             * of passwords cracked by a rule
             */
            // evaluate fitness of each village (RPP)
            std::vector<std::pair<Village, float>> subgroup_evals;
            for (auto &village : this->villages) {
                float fitness = this->evaluate_population_fitness(village);
                cout << "Village fitness: " << fitness << endl;
                subgroup_evals.push_back(make_pair(village, fitness));
            }
            // select parents from each village
            vector<vector<pair<Rule, Rule>>> all_parents;
#ifdef USE_PARALLEL
#ifndef THREAD_COUNT
            static size_t max_thread_count = std::thread::hardware_concurrency();
#else
            // if processor supports multiple logical cores per physical core
            // (ex: hyperthreading) this can be manually set to the number of
            // physical cores - TODO: this is a HACK, fix later
            static size_t max_thread_count = THREAD_COUNT;
#endif
            all_parents.reserve(num_villages);
            std::vector<std::thread> threads;
//            threads.reserve(num_villages);
            cout << "*** Creating worker threads for parent selection..." << endl;
            for (size_t vidx = 0; vidx < num_villages; vidx++) {
                cout << "*** Creating thread " << vidx + 1 << endl;
                std::thread t(
                    [&](size_t idx) {
                        auto parents = this->select_parents(TOURNAMENT, idx);
                        all_parents[idx] = parents;
                    },
                    vidx
                );
                threads.push_back(std::move(t));
            }
            for (auto &thread : threads) {
                thread.join();
            }
            cout << "*** All threads joined..." << endl;
#else
            for (size_t vidx = 0; vidx < num_villages; vidx++) {
                auto parents = this->select_parents(TOURNAMENT, vidx);
                for (auto &p : parents) {
                    cout << "Village " << vidx << " parents: " << p.first.get_rule_clean() << " and " << p.second.get_rule_clean() << endl;
                }
                all_parents.push_back(parents);
            }
#endif
            /*
             * Mate individuals "randomly" from two subgroups deemed
             * most effective. Randomly to prevent the same pairs
             * from mating multiple times when the same groups are
             * the most effective in multiple runs. IDEA: rotate the
             * second group by an offset of idx to prevent having to
             * shuffle/choose randomly.
             */
            // prune worst-performing villages
            // prune if max # of villages is exceeded, to keep same number of villages
            if (subgroup_evals.size() > VILLAGE_COUNT) {
                cout << "Pruning worst-performing villages..." << endl;
                size_t remove_count = subgroup_evals.size() - VILLAGE_COUNT;
                for (size_t j = 0; j < remove_count; j++) {
                    cout << "Dropped village: " << &subgroup_evals.back().first << " with score "
                         << subgroup_evals.back().second << endl;
                    subgroup_evals.pop_back();
                }
            }

            /*
             * Crossover: Merge/breed some small number of individuals
             */
            for(size_t i = 0; i < num_villages; i++) {
                auto &village = subgroup_evals[i].first;
                auto &parents = all_parents[i];
                cout << "Crossover for village " << i << "..." << endl;
                for(auto &p : parents) {
                    cout << "Village " << i << " parents: " << p.first.get_rule_clean() << " and " << p.second.get_rule_clean() << endl;
                    vector<Rule> children = crossover(p);
                    for (Rule child: children) {
                        if (child.get_tokens().size() > 10) {
                            cout << "Skipping child with too many tokens: " << child.get_rule_clean() << endl;
                            continue;
                        }
                        cout << "child: " << child.get_rule_clean() << endl;
                        // select mutation type
                        size_t type_idx = random_integer(0, MUTATION_TYPE_SENTINEL - 1);
                        auto type = (MutationType) type_idx;
                        child = mutate(child, type);
                        cout << "mutated child: " << child.get_rule_clean() << endl;
                        string child_simplified_str = simplify_rule(child.get_rule_clean());
                        cout << "Child: " << child.get_rule_clean() << " simplified to: " << child_simplified_str << endl;
                        if (!child_simplified_str.empty()) {
                            Rule child_simplified = Rule(child_simplified_str);
                            add_to_population(child_simplified, parents[0].first, parents[0].second, subgroup_evals[i].second);
                        }
                    }
                }
            }
        }
    } else {
//        size_t top_score = 0;
//        for (size_t i = 0; i < num_generations; i++) {
//            cout << "generation " << i << endl;
//            pair<Rule, Rule> parents = select_parents();
//            cout << "parents: " << parents.first.get_rule_clean() << " and " << parents.second.get_rule_clean() << endl;
//            vector<Rule> children = crossover(parents);
//            for (Rule child: children) {
//                if (child.get_tokens().size() > 10) {
//                    cout << "Skipping child with too many tokens: " << child.get_rule_clean() << endl;
//                    continue;
//                }
//                cout << "child: " << child.get_rule_clean() << endl;
//                // select mutation type
//                size_t type_idx = random_integer(0, MUTATION_TYPE_SENTINEL - 1);
//                auto type = (MutationType) type_idx;
//                child = mutate(child, type);
//                cout << "mutated child: " << child.get_rule_clean() << endl;
//                string child_simplified_str = simplify_rule(child.get_rule_clean());
//                cout << "Child: " << child.get_rule_clean() << " simplified to: " << child_simplified_str << endl;
//                if (!child_simplified_str.empty()) {
//                    Rule child_simplified = Rule(child_simplified_str);
//                    add_to_population(child_simplified, parents.first, parents.second, top_score);
//                }
//            }
//            if (population.size() > max_pop) {
//                cout << "Removing lowest-fitness rules" << endl;
//                size_t remove_count = population.size() - max_pop;
//                for (size_t j = 0; j < remove_count; j++) {
//                    cout << "Dropped rule: " << population.back().get_rule_clean() << " with score "
//                        << population.back().get_score() << endl;
//                    population.pop_back();
//                }
//            }
//            top_score = population.front().get_score();
//            cout << "Best 10 rules:" << endl;
//            for (size_t j = 0; j < 10; j++) {
//                cout << population[j].get_rule_clean() << " with score " << population[j].get_score() << endl;
//            }
//            cout << "Population size: " << population.size() << endl;
//        }
    }
}

vector<pair<Rule, Rule>> Genetic::select_parents(SelectionStrategy select_strat, size_t village_idx) const {
    if (select_strat == SelectionStrategy::TOURNAMENT) {
        Village pop = this->villages[village_idx];
        size_t pop_size = pop.size();
        size_t tournament_count = (size_t) (((float) pop_size) * POPULATION_GROWTH_RATE);
        size_t tournament_size = (size_t) (pop_size * TOURNAMENT_PCT);
        Village mating_pool;
        cout << "*** Running tournaments..." << endl;
        for (size_t idx = 0; idx < tournament_count * 2; idx++) {
            Village shuffled(pop);
            unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
            std::shuffle(shuffled.begin(), shuffled.end(), std::default_random_engine(seed));
            Rule top(":");
            float top_score = 0.0f;
            for (size_t j = 0; j < tournament_size; j++) {
                Rule r = shuffled[j];
                if (top_score == 0.0f || r.get_score() > top_score) {
                    top = r;
                }
            }
            mating_pool.push_back(top);
        }
        cout << "*** Ran tournaments..." << endl;
        vector<pair<Rule, Rule>> mating_pairs;
        for (size_t idx = 0; idx < tournament_count; idx++) {
            mating_pairs.push_back(make_pair(mating_pool[idx], mating_pool[tournament_count + idx]));
        }
        return mating_pairs;
    } else {
//        for (auto it = population.begin(); it != population.end(); it++) {
//            Rule& first = *it;
//            Rule& second = *(it+1);
//            pair<Rule, Rule> parents = make_pair(first, second);
//            if (!breed_pairs.contains(parents)) {
//                breed_pairs.insert(parents);
//                return parents;
//            }
//        }
//        cout << "No parents found, returning first two rules" << endl;
//        return make_pair(population.front(), population.front());
        return {};
    }
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
        default:
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
        positions.push_back(random_integer(0, this->initial_passwords.size() - 1));
    }
    // transform a password (passwords set in constructor)
    int no_op_count = 0;
    for (unsigned long position : positions) {
        string password = this->initial_passwords[position];
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

rax *build_target_password_tree(const vector<string>& target_passwords) {
    rax *pw_tree_targets = raxNew();
    const size_t pw_cnt = target_passwords.size();
    for (size_t idx = 0; idx < target_passwords.size(); idx++) {
        string password = target_passwords.at(idx);
        auto *pdp = new PasswordData(true, (pw_cnt - idx) / ((float) pw_cnt + 1.0), idx);
        if (0 == raxTryInsert(pw_tree_targets, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL)) {
            // this password has already been inserted
            continue;
        }
    }
    return pw_tree_targets;
}

rax *build_initial_password_tree(const vector<string>& initial_passwords) {
    rax *pw_tree_initial = raxNew();
    const size_t pw_cnt = initial_passwords.size();
    for (size_t idx = 0; idx < initial_passwords.size(); idx++) {
        string password = initial_passwords.at(idx);
        auto *pdp = new PasswordData(true, (pw_cnt - idx) / ((float) pw_cnt + 1.0), idx);
        if (0 == raxTryInsert(pw_tree_initial, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL)) {
            // this password has already been inserted
            continue;
        }
    }
    return pw_tree_initial;
}
void Genetic::delete_trees() {
    raxIterator it;
    raxStart(&it, pw_tree_targets);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*) it.data;
    }
    raxStop(&it);

    raxStart(&it, pw_tree_initial);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
        delete (PasswordData*) it.data;
    }
    raxStop(&it);

    raxFree(pw_tree_targets);
    raxFree(pw_tree_initial);
}

//TO DO: try to generalize the methods to apply to both trees at once
/*
rax *build_password_tree(const vector<string>& passwords) {
    rax *pw_tree_initial = raxNew();
    const size_t pw_cnt = passwords.size();
    for (size_t idx = 0; idx < passwords.size(); idx++) {
        string password = passwords.at(idx);
        auto *pdp = new PasswordData(true, (pw_cnt - idx) / ((float) pw_cnt + 1.0), idx);
        if (0 == raxTryInsert(pw_tree_initial, (unsigned char*) password.c_str(), password.size()+1, (void*) pdp, NULL)) {
            // this password has already been inserted
            continue;
        }
    }
    return pw_tree_initial;
}

delete_tree(rax* tree) {
    raxStart(&it, tree);
    raxSeek(&it, "^", NULL, 0);
    while (raxNext(&it)) {
    delete (PasswordData*) it.data;
    }
    raxStop(&it);
    raxFree(tree);
}
*/

