#ifndef GRAPH_H
#define GRAPH_H

#include <set>
#include <string>
#include <iostream>
#include <unordered_map>
#include <utility>
#include "password_node.h"
#include "password_node_hash.h"

class Graph {
    private:
        std::unordered_map<PasswordNode, std::set<std::pair<std::string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> adj_list;
    public:
        Graph(void);
        std::unordered_map<PasswordNode, std::set<std::pair<std::string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> get_adj_list(void) const;
        bool node_exists(PasswordNode) const;
        void new_node(PasswordNode);
        void new_edge(PasswordNode, std::string, PasswordNode);
        void new_edge_and_child(PasswordNode, std::string, PasswordNode);
        void merge_with(const Graph &g);
        friend std::ostream& operator<<(std::ostream &os, const Graph &graph);
};

#endif /* GRAPH_H */
