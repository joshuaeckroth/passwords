#ifndef PASSWORDS_GENETIC_H
#define PASSWORDS_GENETIC_H

#include <vector>
#include <deque>
#include <utility>
#include <set>
#include "rule.h"
#include "partial_guessing.h"
#include "fitness.h"

extern "C" {
#include <rax.h>
}

#define POPULATION_SIZE 2500
#define VILLAGE_SIZE_MAX POPULATION_SIZE
#define VILLAGE_COUNT_INITIAL 5
#define VILLAGE_COUNT_MAX 10
#define POPULATION_GROWTH_RATE 0.1f
#define TOURNAMENT_PCT 0.5f
// chance for an individual to breed with a member
// of another village/population instead of its own
#define GENE_MIGRATION_CHANCE 0.01f
#define MUTATION_CHANCE 0.02f // NOTE: no smaller than 0.01
#define MIGRATION_CHANCE 0.20f

enum MutationType {
    INSERT,
    DELETE,
    SUBSTITUTE,
    DUPLICATE,
    MUTATION_TYPE_SENTINEL
};

enum EvolutionStrategy {
    INDIVIDUAL,
    COLLECTIVE,
    EVOLUTION_STRATEGY_SENTINEL
};

enum SelectionStrategy {
    TOURNAMENT,
    SELECTION_STRATEGY_SENTINEL
};

typedef std::vector<Rule> Village;
typedef std::vector<Village> Villages;

//class 

class Genetic {
    public:
        explicit Genetic(std::vector<Rule>&, std::vector<std::string>&, std::vector<std::string>&,
                rax*, std::vector<std::string>&, rax*, size_t, StrengthMap);
        ~Genetic();
        Rule mutate(const Rule&, MutationType);
        void run(size_t, EvolutionStrategy);
        void delete_trees();
    private:
        void add_to_population(Rule&, const Rule&, const Rule&, const int&);
        void add_to_population(Rule&&);
        void mate_individuals (std::vector<std::pair<Rule, Rule>>);
        std::vector<Rule> crossover(const std::pair<Rule, Rule>&);
        float evaluate_fitness(const Rule&, const Rule&, const Rule&, const int&);
        const VillageFitness evaluate_population_fitness(std::vector<Rule>);
        std::vector<std::pair<Rule, Rule>> select_parents(
            SelectionStrategy s = TOURNAMENT,
            size_t village_idx = 0
        ) const;
        std::set<std::pair<Rule, Rule>> breed_pairs;
        std::deque<Rule> population;
        Villages villages;
        std::vector<Rule> population_vec;
        std::vector<std::string> primitives;
        std::vector<std::string> target_passwords;
        std::vector<std::string> initial_passwords;
        StrengthMap password_strengths;
        rax *pw_tree_targets;
        rax *pw_tree_initial;
        size_t max_pop;
};

rax *build_target_password_tree(const std::vector<std::string> &target_passwords);
rax *build_initial_password_tree(const std::vector<std::string> &initial_passwords);

#endif //PASSWORDS_GENETIC_H
