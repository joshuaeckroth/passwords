#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <errno.h>
#include "graph_db_writer.h"
#include "rule.h"
#include "password_node.h"
#include "graph.h"

extern "C" {
#include <neo4j-client.h>
}

#define CLEAR_DB 1

using std::cout, std::endl, std::string;

GraphDBWriter::GraphDBWriter() = default;

bool GraphDBWriter::connect() {
    neo4j_client_init();
    this->conn = neo4j_connect("neo4j://neo4j:lambda%0@localhost:7687", NULL, NEO4J_INSECURE);
    if (conn == NULL) {
        neo4j_perror(stderr, errno, "Connection failed :(");
        return false;
    }
#if CLEAR_DB == 1
    neo4j_result_stream_t *results;
    results = neo4j_run(conn, "MATCH (n) DETACH DELETE n", neo4j_null);
    if (results == NULL) {
        neo4j_perror(stderr, errno, "Failed to run DELETE statement");
    }
    neo4j_close_results(results);
#endif
    return true;
}

void GraphDBWriter::submit(Graph *gp) {
    // create tsv node header for bulk import to Neo4j
    std::fstream f_node_header;
    f_node_header.open("results/neo4j_node_header_import.tsv", std::ios::out);
    if (!f_node_header) {
        cout << "Could not create neo4j_node_header_import.tsv" << endl;
    } else {
        cout << "Created neo4j_node_header_import.tsv" << endl;
    }
    f_node_header << "md5:ID\tpassword\titeration:int\tis_target:int";

    // create tsv node file for bulk import to Neo4j
    std::fstream f_node;
    f_node.open("results/neo4j_node_import.tsv", std::ios::out);
    if (!f_node) {
        cout << "Could not create neo4j_node_import.tsv" << endl;
    } else {
        cout << "Created neo4j_node_import.tsv" << endl;
    }
    for (const auto& kv : gp->get_adj_list()) {
        auto pw_node = kv.first;
        const char *md5_pw = pw_node.password_md5;
        string row = string(md5_pw) + "\t\"" + pw_node.clean_password + "\"\t" + std::to_string(pw_node.iteration) + "\t" + std::to_string((pw_node.is_target) ? 1 : 0) + "\n";
        f_node << row;
    }

    // create tsv relationship header for bulk import to Neo4j
    std::fstream f_relations_header;
    f_relations_header.open("results/neo4j_relations_header_import.tsv", std::ios::out);
    if (!f_relations_header) {
        cout << "Could not create neo4j_relations_header_import.tsv" << endl;
    } else {
        cout << "Created neo4j_node_relations_import.tsv" << endl;
    }
    f_relations_header << ":START_ID\trule\t:END_ID\t:TYPE";

    // create tsv relationship file for bulk import to Neo4j
    std::fstream f_relations;
    f_relations.open("results/neo4j_relations_import.tsv", std::ios::out);
    if (!f_relations) {
        cout << "Could not create neo4j_relations_import.tsv" << endl;
    } else {
        cout << "Created neo4j_relations_import.tsv" << endl;
    }
    for (const auto& kv : gp->get_adj_list()) {
        auto parent_node = kv.first;
        const char *parent_md5 = parent_node.password_md5;
        for (const auto& edge_node : kv.second) {
            string rule = edge_node.first;
            auto child_node = edge_node.second;
            const char *child_md5 = child_node.password_md5;
            string row = string(parent_md5) + "\t\"" + rule + "\"\t" + string(child_md5) + "\tGENERATED\n";
            f_relations << row;
        }
    }

//    f_node_header << "test,test\n";
//    f_node_header << "test1,test1\n";
    f_node_header.close();
    f_node.close();
    f_relations_header.close();
    f_relations.close();
    neo4j_close(this->conn);
    neo4j_client_cleanup();
}
