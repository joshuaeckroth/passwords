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

enum MutationType {
    INSERT,
    DELETE,
    SUBSTITUTE,
    DUPLICATE
};

class Genetic {
    public:
        explicit Genetic(std::vector<Rule>&, std::vector<std::string>&, std::vector<std::string>&, rax *);
        ~Genetic();
        void run(int);
    private:
        void add_to_population(Rule&);
        std::vector<Rule> crossover(const std::pair<Rule, Rule>&);
        Rule mutate(const Rule&, MutationType);
        float evaluate_fitness(const Rule&);
        std::pair<Rule, Rule> select_parents();
        std::set<std::pair<Rule, Rule>> breed_pairs;
        std::deque<Rule> population;
        std::vector<std::string> primitives;
        std::vector<std::string> target_passwords;
        rax *pw_tree_targets;
};


#endif //PASSWORDS_GENETIC_H
