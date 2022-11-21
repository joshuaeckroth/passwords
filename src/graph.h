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
        Graph();
        std::unordered_map<PasswordNode, std::set<std::pair<std::string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> get_adj_list() const;
        void new_node(const PasswordNode&);
        void new_edge(const PasswordNode&, const std::string&, const PasswordNode&);
        void new_edge_and_child(const PasswordNode&, const std::string&, const PasswordNode&);
        unsigned int node_count() const;
        friend std::ostream& operator<<(std::ostream &os, const Graph &graph);
};

#endif /* GRAPH_H */
