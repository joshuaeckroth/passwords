#ifndef GRAPH_BUILDER_H
#define GRAPH_BUILDER_H

#include <unordered_set>
#include <vector>
#include <string>
#include <memory>
#include "graph.h"
#include "password_node.h"
#include "rule.h"

class GraphBuilder {
    private:
        Graph *gp;
        std::vector<std::string> target_pws;
        std::unordered_set<std::string> target_pw_set;
        std::vector<Rule> rules;
        size_t rule_weight_sum;
        size_t steps = 0;
        size_t hits = 0;
        Rule& rnd_weighted_select(void);
        void build(size_t, PasswordNode);
        void reset_rule_weights(void);
    public:
        GraphBuilder(Graph*, std::vector<Rule> rules, std::vector<std::string>);
        void build(void);

};

#endif /* GRAPH_BUILDER_H */
