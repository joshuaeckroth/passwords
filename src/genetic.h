#ifndef PASSWORDS_GENETIC_H
#define PASSWORDS_GENETIC_H

#include <vector>
#include <deque>
#include <utility>
#include <set>
#include "rule.h"
#include "partial_guessing.h"

extern "C" {
#include <rax.h>
}

#define POPULATION_SIZE 2500
#define POPULATION_PARTITIONS 5
#define POPULATION_GROWTH_RATE 0.1f
#define TOURNAMENT_PCT 0.5f
// chance for an individual to breed with a member
// of another village/population instead of its own
#define GENE_MIGRATION_CHANCE 0.01f
#define VILLAGE_COUNT POPULATION_PARTITIONS
#define MUTATION_CHANCE 0.02f

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
        explicit Genetic(std::vector<Rule>&,
                std::vector<std::string>&, std::vector<std::string>&, rax*,
                size_t, StrengthMap);
        ~Genetic();
        Rule mutate(const Rule&, MutationType);
        void run(size_t, EvolutionStrategy);
    private:
        void add_to_population(Rule&, const Rule&, const Rule&, const int&);
        std::vector<Rule> crossover(const std::pair<Rule, Rule>&);
        float evaluate_fitness(const Rule&, const Rule&, const Rule&, const int&);
        size_t evaluate_population_fitness(std::vector<Rule>);
        std::vector<std::pair<Rule, Rule>> select_parents(
            SelectionStrategy s = TOURNAMENT,
            size_t village_idx = 0
        );
        std::set<std::pair<Rule, Rule>> breed_pairs;
        std::deque<Rule> population;
        Villages villages;
        std::vector<Rule> population_vec;
        std::vector<std::string> primitives;
        std::vector<std::string> target_passwords;
        StrengthMap password_strengths;
        rax *pw_tree_targets;
        size_t max_pop;
};

rax *build_target_password_tree(const std::vector<std::string> &target_passwords);

#endif //PASSWORDS_GENETIC_H
