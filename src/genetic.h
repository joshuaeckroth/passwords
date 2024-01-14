//
// Created by josh on 12/21/23.
//

#ifndef PASSWORDS_GENETIC_H
#define PASSWORDS_GENETIC_H

#include <vector>
#include <utility>
#include "rule.h"

enum MutationType {
    INSERT,
    DELETE,
    SUBSTITUTE,
    DUPLICATE
};

class Genetic {
    public:
        explicit Genetic(std::vector<Rule>&, std::vector<std::string>&);
        ~Genetic();
        void run(int);
    private:
        std::pair<Rule, Rule> crossover(const std::pair<Rule, Rule>&);
        Rule mutate(const Rule&, MutationType);
        double evaluate_fitness(const Rule&);
        std::pair<Rule, Rule> select_parents();
        std::vector<Rule> population;
        std::vector<std::string> primitives;
};


#endif //PASSWORDS_GENETIC_H
