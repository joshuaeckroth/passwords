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
    DUPLICATE,
    NO_MUTATION
};

class Genetic {
    public:
        explicit Genetic(std::vector<Rule>&, std::vector<std::string>&, std::vector<std::string>&, rax *, int);
        ~Genetic();
        void run(int);
    private:
        void add_to_population(Rule&, const Rule&, const Rule&, const int&);
        std::vector<Rule> crossover(const std::pair<Rule, Rule>&);
        Rule mutate(const Rule&, MutationType);
        float evaluate_fitness(const Rule&, const Rule&, const Rule&, const int&);
        std::pair<Rule, Rule> select_parents();
        std::set<std::pair<Rule, Rule>> breed_pairs;
        std::deque<Rule> population;
        std::vector<std::string> primitives;
        std::vector<std::string> target_passwords;
        rax *pw_tree_targets;
        int max_pop;
};


#endif //PASSWORDS_GENETIC_H
