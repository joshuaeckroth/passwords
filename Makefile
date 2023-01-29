CXXFLAGS += -std=c++20 -O3 -g
CFLAGS_NATIVE_PW := $(CFLAGS)
CFLAGS_NATIVE_PW += -DWITH_HWMON
CFLAGS_NATIVE_PW += -I/opt/homebrew/Cellar/boost/1.76.0/include -L/opt/homebrew/Cellar/boost/1.76.0/lib -lboost_regex

ifeq ($(UNAME),Darwin)
ifeq ($(shell test $(DARWIN_VERSION) -le 15; echo $$?), 0)
CFLAGS_NATIVE_PW += -DMISSING_CLOCK_GETTIME
endif
ifeq ($(IS_APPLE_SILICON),1)
CFLAGS_NATIVE_PW += -arch arm64
endif
else
CFLAGS_NATIVE_PW += -I/usr/include
endif

CFLAGS_NATIVE_PW += -I external/hashcat/include -I external/hashcat/deps/LZMA-SDK/C -I external/hashcat/deps/zlib -I external/hashcat/deps/zlib/contrib -I external/hashcat/deps/OpenCL-Headers -I external/hashcat/deps/xxHash -I external/hashcat/deps/unrar -I external/hashcat/OpenCL

RADIX_ROOT := external/rax
RADIX_FLAGS := -I $(RADIX_ROOT) 

# OPENSSL_FLAGS = $(shell PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@1.1/lib/pkgconfig/ pkg-config --cflags --libs)

NEO4J_FLAGS = $(shell PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@1.1/lib/pkgconfig:external/libneo4j-client-v4-install/lib/pkgconfig/ pkg-config --cflags --libs neo4j-client)
HC_ARCHIVE = external/hashcat/obj/combined.NATIVE.a

GENGRAPH_SRCS = src/rule.cc src/util.cc src/rule_loader.cc src/password_loader.cc src/password_node.cc src/graph.cc src/password_node_hash.cc src/graph_builder.cc src/graph_db_writer.cc src/gengraph.cc
GENGRAPH_OBJS = $(subst .cc,.o,$(GENGRAPH_SRCS))

GENTREE_SRCS = src/gentree.cc src/util.cc src/rule_loader.cc src/password_loader.cc src/rule.cc src/password_data.cc src/rule_data.cc src/tree_builder.cc src/analyze_tree.cc src/partial_guessing.cc
GENTREE_OBJS = $(subst .cc,.o,$(GENTREE_SRCS)) src/rax.o

all: gentree rule_regex_exp

$(HC_ARCHIVE):
	DEBUG=1 cd external/hashcat && make obj/combined.NATIVE.a

.PHONY: clean
clean:
	rm -f src/*.o
	cd external/hashcat && make clean

src/rule.o: src/rule.cc src/rule.h $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/rule.cc -o src/rule.o $(HC_ARCHIVE)

src/password_node.o: src/password_node.cc src/password_node.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/password_node.cc -o src/password_node.o

src/password_node_hash.o: src/password_node_hash.cc src/password_node_hash.h src/password_node.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/password_node_hash.cc -o src/password_node_hash.o

src/graph.o: src/graph.cc src/graph.h src/password_node.h src/password_node_hash.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/graph.cc -o src/graph.o

src/graph_builder.o: src/graph_builder.cc src/graph_builder.h src/graph.h src/password_node.h src/rule.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -c src/graph_builder.cc -o src/graph_builder.o

src/graph_db_writer.o: src/graph_db_writer.cc src/graph_db_writer.h src/rule.h src/util.h src/password_node.h src/graph.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -c src/graph_db_writer.cc -o src/graph_db_writer.o

src/rule_loader.o: src/rule_loader.cc src/rule_loader.h src/rule.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c src/rule_loader.cc -o src/rule_loader.o

src/password_loader.o: src/password_loader.cc src/password_loader.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c src/password_loader.cc -o src/password_loader.o

src/util.o: src/util.cc src/util.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -c src/util.cc -o src/util.o

src/gengraph.o: src/gengraph.cc src/rule.h src/rule_loader.h src/password_loader.h src/util.h src/password_node.h src/graph.h src/graph_builder.h src/graph_db_writer.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -c src/gengraph.cc -o src/gengraph.o

gengraph: $(GENGRAPH_OBJS) $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -o gengraph $(GENGRAPH_OBJS) $(HC_ARCHIVE)

src/rax.o: $(RADIX_ROOT)/rax.h
	$(CC) -c $(RADIX_ROOT)/rax.c -o src/rax.o

src/password_data.o: src/password_data.cc src/password_data.h
	$(CXX) $(CXXFLAGS) -c src/password_data.cc -o src/password_data.o

src/rule_data.o: src/rule_data.cc src/rule_data.h
	$(CXX) $(CXXFLAGS) -c src/rule_data.cc -o src/rule_data.o

src/tree_builder.o: src/tree_builder.cc src/tree_builder.h $(RADIX_ROOT)/rax.h src/password_data.h src/rule_data.h src/rule.h $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(RADIX_FLAGS) $(LFLAGS_NATIVE) -c src/tree_builder.cc -o src/tree_builder.o $(HC_ARCHIVE)

src/analyze_tree.o: src/analyze_tree.cc $(RADIX_ROOT)/rax.h src/analyze_tree.h src/rule_data.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(RADIX_FLAGS) $(LFLAGS_NATIVE) -c src/analyze_tree.cc -o src/analyze_tree.o

src/gentree.o: src/gentree.cc src/rule.h src/password_loader.h src/rule_loader.h src/util.h src/password_data.h src/tree_builder.h src/analyze_tree.h src/partial_guessing.h $(RADIX_ROOT)/rax.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) $(NEO4J_FLAGS) -c src/gentree.cc -o src/gentree.o 

gentree: $(GENTREE_OBJS) $(HC_ARCHIVE) 
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) $(NEO4J_FLAGS) -o gentree $(GENTREE_OBJS) $(HC_ARCHIVE)

rule_regex_exp: src/rule_regex_exp.cc src/rule.h src/rule_loader.h src/rule.o src/rule_loader.o $(HC_ARCHIVE) $(RADIX_ROOT)/rax.h src/rax.o
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) src/rule_regex_exp.cc -o rule_regex_exp src/rule.o src/rule_loader.o $(HC_ARCHIVE) src/rax.o
