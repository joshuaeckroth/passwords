#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include <queue>
#include <string>
#include <functional>
#include <memory>
#include "rule.h"
#include "rule_loader.h"
#include "password_loader.h"
#include "util.h"
#include "password_node.h"
#include "graph.h"
#include "graph_builder.h"
#include "graph_db_writer.h"

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
    // print_seq(passwords);
    Graph *gp = new Graph;
    GraphBuilder gb(gp, rules, passwords);
    gb.build();
    //cout << *gp << endl;
    GraphDBWriter writer;
    bool did_connect = writer.connect();
    writer.submit(gp);
    cout << "Connected to Neo4j? " << ((did_connect) ? "true" : "false") << endl;
    return 0;
}

