#include <set> 
#include <string>
#include <iostream>
#include <unordered_map>
#include <utility>
#include <stdexcept>
#include "password_node.h"
#include "password_node_hash.h"
#include "graph.h"

using std::string, std::pair, std::set, std::endl;

Graph::Graph() {}

std::unordered_map<PasswordNode, set<pair<string, PasswordNode>>, PasswordNodeHash, PasswordNodeEqual> Graph::get_adj_list(void) const {
    return this->adj_list;
}

bool Graph::node_exists(PasswordNode node) const {
    return this->adj_list.contains(node);
}

int Graph::node_count() const {
    return this->adj_list.size();
}

void Graph::new_node(PasswordNode node) {
    set<pair<string, PasswordNode>> empty_set;
    this->adj_list.insert({node, empty_set});
}

void Graph::new_edge(PasswordNode node_1, string rule_edge, PasswordNode node_2) {
    if (!this->adj_list.contains(node_1) || !this->adj_list.contains(node_2)) {
        throw std::logic_error("Node(s) to create edge between DNE!");
    }
    this->adj_list[node_1].insert(pair<string, PasswordNode>(rule_edge, node_2));
}

void Graph::new_edge_and_child(PasswordNode parent_node, string rule_edge, PasswordNode child_node) {
    bool parent_exists = this->adj_list.contains(parent_node);
    bool child_exists = this->adj_list.contains(child_node);
    pair<string, PasswordNode> edge_node_pair(rule_edge, child_node);
    if (parent_exists) {
        this->adj_list[parent_node].insert(edge_node_pair);
        if (!child_exists) {
            this->new_node(child_node);
        }
    } else {
        throw std::logic_error("Trying to add a child to a parent that DNE!");
    }
}

void Graph::merge_with(const Graph &g) {
    return;
}

std::ostream& operator<<(std::ostream &os, const Graph &graph) {
    os << "=== GRAPH START ===\n";
    for (auto kv : graph.get_adj_list()) {
        os << "NODE: " << kv.first << "\n";
        for (auto edge_node : kv.second) {
           os << "\t=== " << edge_node.first << " ===> " << edge_node.second.password << "\n";
        }
    }
    os << "=== GRAPH END ===" << endl;
    return os;
}

