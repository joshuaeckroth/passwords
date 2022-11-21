#ifndef GRAPH_DB_WRITER_H
#define GRAPH_DB_WRITER_H

#include <iostream>
#include <string>
#include "rule.h"
#include "util.h"
#include "password_node.h"
#include "graph.h"

extern "C" {
#include <neo4j-client.h>
}

class GraphDBWriter {
    private:
        neo4j_connection_t *conn = nullptr;
    public:
        GraphDBWriter();
        bool connect();
        void submit(Graph*);
};

#endif /* GRAPH_DB_WRITER_H */
