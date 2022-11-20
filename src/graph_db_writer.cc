#include <iostream>
#include <string>
#include <stdio.h>
#include <errno.h>
#include "graph_db_writer.h"
#include "rule.h"
#include "util.h"
#include "password_node.h"
#include "graph.h"

extern "C" {
#include <neo4j-client.h>
}

#define CLEAR_DB 1

GraphDBWriter::GraphDBWriter() {}

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
}
