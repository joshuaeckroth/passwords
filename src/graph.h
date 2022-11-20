#ifndef GRAPH_H
#define GRAPH_H

#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include "password_node.h"
#include "password_node_hash.h"

class Graph {
    private:
        std::unordered_map<PasswordNode, std::set<std::pair<std::string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> adj_list;
        //std::unordered_map<PasswordNode, int, PasswordNodeHash, PasswordNodeEqual> adj_list;
    public:
        Graph(void);
        std::unordered_map<PasswordNode, std::set<std::pair<std::string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> get_adj_list(void);
        // std::unordered_map<PasswordNode, int, PasswordNodeHash, PasswordNodeEqual> get_adj_list(void);
        bool node_exists(PasswordNode) const;
        void new_node(PasswordNode);
        void new_edge(PasswordNode, std::string, PasswordNode);
        void new_edge_and_child(PasswordNode, std::string, PasswordNode);
        void merge_with(const Graph &g);
};

#endif /* GRAPH_H */
