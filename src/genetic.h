#ifndef PASSWORDS_GENETIC_H
#define PASSWORDS_GENETIC_H

#include <vector>
#include <deque>
#include <utility>
#include <set>
#include "rule.h"

extern "C" {
#include <rax.h>
}

#define POPULATION_SIZE 2500
#define POPULATION_PARTITIONS 5
#define MUTATION_CHANCE 0.02f

enum MutationType {
    INSERT,
    DELETE,
    SUBSTITUTE,
    DUPLICATE,
    NO_MUTATION
};

enum EvolutionStrategy {
    INDIVIDUAL,
    COLLECTIVE
};

class Genetic {
    public:
        explicit Genetic(std::vector<Rule>&, std::vector<std::string>&, std::vector<std::string>&, rax*, size_t);
        ~Genetic();
        Rule mutate(const Rule&, MutationType);
        void run(size_t, EvolutionStrategy);
    private:
        void add_to_population(Rule&, const Rule&, const Rule&, const int&);
        std::vector<Rule> crossover(const std::pair<Rule, Rule>&);
        float evaluate_fitness(const Rule&, const Rule&, const Rule&, const int&);
        size_t evaluate_population_fitness(std::vector<Rule>);
        std::pair<Rule, Rule> select_parents();
        std::set<std::pair<Rule, Rule>> breed_pairs;
        std::deque<Rule> population;
        std::vector<Rule> population_vec;
        std::vector<std::string> primitives;
        std::vector<std::string> target_passwords;
        rax *pw_tree_targets;
        size_t max_pop;
};


#endif //PASSWORDS_GENETIC_H
