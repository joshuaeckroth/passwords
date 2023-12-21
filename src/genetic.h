//
// Created by josh on 12/21/23.
//

#ifndef PASSWORDS_GENETIC_H
#define PASSWORDS_GENETIC_H

#include <vector>
#include <utility>
#include "rule.h"

class Genetic {
public:
    explicit Genetic(std::vector<Rule>&);
    ~Genetic();
    void run(int);

private:
    void initialize_population();
    std::pair<Rule, Rule> crossover(const std::pair<Rule, Rule>&);
    Rule mutate(const Rule&);
    double evaluate_fitness(const Rule&);
    std::pair<Rule, Rule> select_parents();
    std::vector<Rule> population;
};


#endif //PASSWORDS_GENETIC_H
