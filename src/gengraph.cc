#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include <queue>
#include <string>
#include <functional>
#include "rule.h"
#include "rule_loader.h"
#include "password_loader.h"
#include "util.h"
#include "password_node.h"
#include "graph.h"

extern "C" {
#include <neo4j-client.h>
}

using std::vector, std::string, std::cout, std::endl, std::pair;

int main(int argc, const char** argv) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <password list> <rule list>\n", argv[0]);
        return -1;
    }
   
    auto rules = RuleLoader::load_rules(argv[2]);
    auto passwords = PasswordLoader::load_passwords(argv[1]);
    print_seq(passwords);

    Graph pw_graph;
    PasswordNode n1(passwords[0], true);
    PasswordNode n2(passwords[1], false);
    pw_graph.new_node(n1);
    pw_graph.new_edge_and_child(n1, rules[0].get_rule_raw(), n2);
    
    //cout << pw_graph.get_adj_list()[PasswordNode(passwords[0], true)].contains(pair<string, PasswordNode>(rules[0].get_rule_raw(), PasswordNode(passwords[1], false))) << endl;

//    std::priority_queue<Rule, vector<Rule>, std::less<Rule>> rule_q(rules.begin(), rules.end());
//    print_queue(rule_q);

}

