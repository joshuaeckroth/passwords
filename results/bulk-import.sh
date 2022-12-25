export JAVA_HOME=/usr/lib/jvm/java-11-openjdk/
"/home/josh/.config/Neo4j Desktop/Application/relate-data/dbmss/dbms-155d4682-4af7-499a-9f87-9ad78d7716ed/bin/neo4j-admin" import --nodes=neo4j_node_header_import.tsv,neo4j_node_import.tsv --relationships=neo4j_relations_header_import.tsv,neo4j_relations_import.tsv --delimiter="\t" --id-type=STRING --force
