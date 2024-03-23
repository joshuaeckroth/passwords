#include <algorithm>
#include <set>
#include <iostream>
#include <fstream>
#include <functional>
#include <random>
#include <utility>
#include <thread>
#include <chrono>
#include <cmath>
#include <glog/logging.h>
#include "genetic.h"
#include "tree_builder.h"
#include "rule.h"
#include "password_data.h"
#include "util.h"
#include "partial_guessing.h"
#include "fitness.h"

extern "C" {
#include <rax.h>
}

using namespace std;

Genetic::Genetic(
        vector<Rule> &rules, // initial pop
        vector<string> &primitives,
        vector<string> &target_passwords,
        rax *pw_tree_targets,
        vector<string> &initial_passwords,
        rax *pw_tree_initial,
        StrengthMap sm)
    : primitives(primitives),
      target_passwords(target_passwords),
      pw_tree_targets(pw_tree_targets),
      initial_passwords(initial_passwords),
      pw_tree_initial(pw_tree_initial),
      password_strengths(sm) {
    population_vec = rules;
    population = deque<Rule>(rules.begin(), rules.end());
    initialize_rule_replacements();
}

Genetic::~Genetic() {}

void Genetic::add_to_population(Rule&& rule) {
    for (auto &v : this->villages) {
        if (v.size() < VILLAGE_SIZE_MAX) {
            v.push_back(std::move(rule));
            return;
        }
    }
    Village v;
    v.push_back(std::move(rule));
    this->villages.push_back(std::move(v));
}

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
const VillageFitness Genetic::evaluate_population_fitness(vector<Rule> pop) {
    // rpp is the #rules / 100 * (cracked / hashed)
    // cracked is number of passwords cracked by an entire village (so don't include passwords already cracked by the village)
    // get the number of unique password targets hit by a rule set
    size_t target_count = this->target_passwords.size();
    size_t initial_count = this->initial_passwords.size();
    static float pct_cracked_no_rule = [&]() -> float {
        size_t cracked_count = 0;
        for (string &pw : this->initial_passwords) {
            if (in_radix(this->pw_tree_targets, pw)) {
                cracked_count++;
            }
        }
        return (cracked_count / (float) target_count) * 100.0f;
    }();
    std::set<string> unique_hits;
    for (auto &rule : pop) {
        for (auto &pw : this->initial_passwords) {
            unique_hits.insert(pw); // add all initial passwords to unique hits (to subtract from later)
            string new_pw = rule.apply_rule(pw);
            if (new_pw == pw) continue; // noop
            // cout << "rule: " << rule.get_rule_clean() << " applied to " << pw << " yields " << new_pw << endl;
            if (in_radix(this->pw_tree_targets, new_pw)) {
                //cout << "hit: " << new_pw << endl;
                auto old_score = rule.get_score();
                auto search = this->password_strengths.find(new_pw);
                auto new_score = old_score + (
                    (search != this->password_strengths.end()) ? search->second : get_strength_unseen()
                );
                //cout << "old score: " << old_score << ", new score: " << new_score << endl;
                rule.set_score(new_score); 
                unique_hits.insert(new_pw);
                //cout << "unique hits: " << unique_hits.size() << endl;
            }
        }
    }
    int num_cracked = unique_hits.size();
    float rpp_divisor = ((100.0f * ((float) num_cracked / (float) target_count)) - pct_cracked_no_rule);
    float rpp = (float) pop.size() / rpp_divisor;
    double pct_cracked = (100.0f * ((float) num_cracked / (float) target_count));
    DLOG(INFO) << "--- num cracked: " << num_cracked;
    // parts of the rpp calculation:
    DLOG(INFO) << "--- pop size: " << pop.size();
    DLOG(INFO) << "--- target count: " << target_count;
    DLOG(INFO) << "--- pct cracked: " << pct_cracked;
    DLOG(INFO) << "--- pct cracked no rule: " << pct_cracked_no_rule;
    DLOG(INFO) << "--- rpp divider: " << rpp_divisor;
    DLOG(INFO) << "--- rpp: " << rpp;
    return VillageFitness(pct_cracked, rpp);
}

void Genetic::mate_individuals(vector<pair<Rule, Rule>> parents) {
    for (auto &p: parents) {
        auto p1_clean = p.first.get_rule_clean();
        auto p2_clean = p.second.get_rule_clean();

        vector<Rule> children = crossover(p);
        for (Rule child: children) {
            auto child_clean = child.get_rule_clean();
            if (child.get_tokens().size() > 10) {
                //cout << "Skipping child with too many tokens: " << child_clean << endl;
                continue;
            }
            if (child_clean == p1_clean || child_clean == p2_clean) {
                //cout << "Skipping child identical to one of parents: " << child_clean << endl;
                continue;
            }
            //cout << "child: " << child_clean << endl;
            // maybe mutate
            bool do_mutate = random_integer(1, 100) <= (size_t) (100 * MUTATION_CHANCE);
            if (do_mutate) {
                // select mutation type
                size_t type_idx = random_integer(0, MUTATION_TYPE_SENTINEL - 1);
                auto type = (MutationType) type_idx;
                child = mutate(child, type);
                //cout << "mutated child: " << child_clean << endl;
            }
            string child_simplified_str = simplify_rule(child_clean);
            ///cout << "Child: " << child_clean << " simplified to: " << child_simplified_str << endl;
            if (!child_simplified_str.empty()) {
                Rule child_simplified = Rule(child_simplified_str);
                this->add_to_population(std::move(child_simplified));
            }
        }
    }
}

void Genetic::run(size_t num_generations, EvolutionStrategy strategy) {
    ofstream stats_out("genetic_stats.tsv", ios::out | ios::trunc);
    if (!stats_out.is_open()) {
        LOG(ERROR) << "Failed to open genetic_stats.tsv for writing";
        return;
    }
    stats_out << "generation\tvillage\tfitness_cracked_pct\tfitness_rpp" << endl;
    if (strategy == COLLECTIVE) {
        /*
         * STEP 1: INITIALIZE POPULATION
         */
        for (size_t idx = 0; idx < VILLAGE_COUNT_INITIAL; idx++) {
            Village v(this->population_vec);
            this->villages.push_back(v);
        }
        for (size_t idx = 0; idx < num_generations; idx++) {
            size_t num_villages = this->villages.size();
            LOG(INFO) << "*** Generation: " << idx + 1 << ", village count: " << num_villages;
            // evaluate fitness of each village (RPP)
            typedef std::pair<Village, VillageFitness> vp;
            std::vector<vp> subgroup_evals;
            size_t j = 1;
            for (auto &village : this->villages) {
                LOG(INFO) << "*** Evaluating population fitness for village: " << j;
                VillageFitness fitness = this->evaluate_population_fitness(village);
                LOG(INFO) << "Village fitness: " << fitness.to_string();
                stats_out << idx + 1 << "\t" << j << "\t" << fitness.get_cracked_pct() << "\t" << fitness.get_rpp() << endl;
                stats_out.flush();
                subgroup_evals.push_back(make_pair(std::move(village), fitness));
                j += 1;
            }
            this->villages.clear();
            std::sort(subgroup_evals.begin(), subgroup_evals.end(), [](vp a, vp b) {
                    return a.second > b.second;
                    });
            for (auto &p : subgroup_evals) {
                this->villages.push_back(std::move(p.first));
            }
            subgroup_evals.clear();
            // prune worst-performing villages, stay below VILLAGE_COUNT
            if (num_villages > VILLAGE_COUNT_MAX) {
                LOG(INFO) << "*** Pruning worst-performing villages...";
                size_t remove_count = num_villages - VILLAGE_COUNT_MAX;
                for (size_t j = 0; j < remove_count; j++) {
                    this->villages.pop_back();
                }
                LOG(INFO) << "*** Dropped " << remove_count << " villages...";
            }
            num_villages = this->villages.size();
            /*
             * STEP 2: SELECT INDIVIDUALS FOR MATING
             * For population level fitness we care about
             * RPP (rules per percentage cracked). For
             * individual fitness we care about the strength
             * of passwords cracked by a rule
             */
            vector<vector<pair<Rule, Rule>>> all_parents; // parents from each village
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
            // cout << "*** Creating worker threads for parent selection..." << endl;
            for (size_t vidx = 0; vidx < num_villages; vidx++) {
                // cout << "*** Creating thread " << vidx + 1 << endl;
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
            // cout << "*** All threads joined..." << endl;
#else
            for (size_t vidx = 0; vidx < num_villages; vidx++) {
                auto parents = this->select_parents(TOURNAMENT, vidx, num_villages);
                for (auto &p : parents) {
                    DLOG(INFO) << "Village " << vidx << " parents: " << p.first.get_rule_clean()
                        << " and " << p.second.get_rule_clean();
                }
                all_parents.push_back(parents);
            }
#endif
            /*
             * STEP 3: MATE INDIVIDUALS (crossover)
             */
            //migration--instead of parents being from same village, make them be from different villages
            /*
             * * add likelihood of this happening as a parameter
             * * split all_parents into two and loop through each separately
             * * Get first rule of each of the two villages
             * * Create a temporary village, where each rule pair made from the two villages picked (second one picked randomly)
             * * add mate_individuals as a function
             * Currently picking a random village, pick intentional one instead?
             * *Best performing village? Closest performing village? Can the same village be picked to be the second for multiple villages?
             * TODO: Migrated village creation?
             * *do the rules migrating need to be taken out of village they came from?
             * *for picking the parent rules, currently getting the first from both villages--*should we randomize which is taken, the first or second, from both villages?
             * save the migrated parent village as a new village?
             * should I do the select_parents method to create the migrated village? adapt it to work on two villages?
             * are all villages same size?
             */
            //make temporary village where first rule in every pair is from one village, second rule in every pair is from second village
            //split all_parents into group for doing migration, and group doing crossover within the village
            //migration_split_result result = migration_split(all_parents);
            for (size_t i = 0; i < num_villages; i++) {
                //bool do_migration = random_integer(1, 100) <= (size_t) (100 * MIGRATION_CHANCE);
                bool do_migration = 0;
                if (do_migration) {
                    auto &first_parents = all_parents[i];
                    vector<pair<Rule, Rule>> parents; // new parent combinations, where parents from different villages
                    cout << "Creating migrated parent village ..." << endl;
                    size_t second_vill_ind = random_integer(0, num_villages-1);//random num between 0 and num_villages-1 that is not i
                    if (second_vill_ind == i) {
                        if (i < all_parents.size() - 1) {
                            second_vill_ind += 1;
                        } else {
                            second_vill_ind -= 1;
                        }
                    }
                    auto &second_parents = all_parents[second_vill_ind];
                    //go through both villages, create new rule pairs by index, add to migrated village
                    for (size_t k = 0; k < first_parents.size(); k++) {
                        auto p1_rule = first_parents[k].first;
                        auto p1_clean = p1_rule.get_rule_clean();
                        auto p2_rule = second_parents[k].first;
                        auto p2_clean = p2_rule.get_rule_clean();
                        pair<Rule, Rule> migrated_parents = make_pair(p1_rule, p2_rule);
                        cout << "Parent 1: " << p1_clean << " from Village " << i << " and "
                            << "Parent 2: " << p2_clean << " from Village " << second_vill_ind << endl;
                        parents.push_back(migrated_parents);
                    }
                    // after getting new combo-village parents
                    LOG(INFO) << "*** Crossover for villages " << i << " and " << second_vill_ind << "...";
                    mate_individuals(parents);
                } else {
                    auto &parents = all_parents[i];
                    LOG(INFO) << "*** Crossover for village " << i << "...";
                    mate_individuals(parents);
                }
            }
            google::FlushLogFiles(google::INFO);
        }
    }
}

vector<pair<Rule, Rule>> Genetic::select_parents(SelectionStrategy select_strat, size_t village_idx, size_t village_count) const {
    if (select_strat == SelectionStrategy::TOURNAMENT) {
        Village pop = this->villages[village_idx];
        size_t pop_size = pop.size();
        size_t tournament_count = (size_t) (((float) pop_size) * POPULATION_GROWTH_RATE);
        size_t tournament_size = (size_t) (pop_size * TOURNAMENT_PCT);
        Village mating_pool;
        LOG(INFO) << "*** Running tournaments...";
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
        LOG(INFO) << "*** Ran tournaments...";
        vector<pair<Rule, Rule>> mating_pairs;
        for (size_t idx = 0; idx < tournament_count; idx++) {
            // for whatever mutation chance, make second parent from a random village and random index
            bool do_migration = random_integer(1, 100) <= (size_t) (100 * MIGRATION_CHANCE);
            cout << "village count: " << village_count << endl;
            cout << "village index: " << village_idx << endl;
            if (do_migration) {
                size_t rand;
                do {
                    rand = random_integer(0, village_count - 1);
                } while (rand == village_idx);
                //size_t rand = random_integer(0, village_count-1); // exclude village index value
                cout << "migrating with random village: " << rand << endl; // this didn't always print
                Village migration_pool = this->villages[rand]; //this isn't always assigning a village?
                cout << "after migration pool created" << endl;
                size_t pool_size = migration_pool.size();
                mating_pairs.push_back(make_pair(mating_pool[idx], migration_pool[random_integer(0, pool_size-1)]));
                cout << "migrated parents pushed" << endl;
            } else {
                cout << "no migration" << endl;
                mating_pairs.push_back(make_pair(mating_pool[idx], mating_pool[tournament_count + idx]));
            }
        }
        return mating_pairs;
    } else {
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
    DLOG(INFO) << "crossover point: " << crossover_point;
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
            score += 1.0;
        }
    }
    if (no_op_count == N) {
        score = 0.0;
        DLOG(INFO) << "No-op rule detected: " << rule.get_rule_clean();
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
