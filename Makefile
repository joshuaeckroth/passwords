CXXFLAGS += -std=c++20 -O3 -g

ifdef USE_PARALLEL
CXXFLAGS += -DUSE_PARALLEL
endif

ifdef DO_PROFILE
CXXFLAG += -pg
endif

ifdef THREAD_COUNT
CXXFLAGS += -DTHREAD_COUNT=$(THREAD_COUNT)
endif

CFLAGS_NATIVE_PW := $(CFLAGS)
CFLAGS_NATIVE_PW += -DWITH_HWMON
CFLAGS_NATIVE_PW += -I/opt/homebrew/Cellar/boost/1.82.0_1/include -L/opt/homebrew/Cellar/boost/1.82.0_1/lib -lboost_regex -lglog

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

HC_ARCHIVE = external/hashcat/obj/combined.NATIVE.a

GENGRAPH_SRCS = src/rule.cc src/util.cc src/rule_loader.cc src/password_loader.cc src/password_node.cc src/graph.cc src/password_node_hash.cc src/graph_builder.cc src/graph_db_writer.cc src/gengraph.cc
GENGRAPH_OBJS = $(subst .cc,.o,$(GENGRAPH_SRCS))

GENTREE_SRCS = src/gentree.cc src/util.cc src/rule_loader.cc src/password_loader.cc src/rule.cc src/password_data.cc src/rule_data.cc src/tree_builder.cc src/analyze_tree.cc src/partial_guessing.cc src/genetic.cc
GENTREE_OBJS = $(subst .cc,.o,$(GENTREE_SRCS)) src/rax.o

GENETIC_SRCS = src/run_genetic.cc src/genetic.cc src/util.cc src/rule_loader.cc src/password_loader.cc src/rule.cc src/password_data.cc src/rule_data.cc src/tree_builder.cc src/analyze_tree.cc src/partial_guessing.cc
GENETIC_OBJS = $(subst .cc,.o,$(GENETIC_SRCS)) src/rax.o

all: genetic

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
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/graph_builder.cc -o src/graph_builder.o

src/graph_db_writer.o: src/graph_db_writer.cc src/graph_db_writer.h src/rule.h src/util.h src/password_node.h src/graph.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/graph_db_writer.cc -o src/graph_db_writer.o

src/rule_loader.o: src/rule_loader.cc src/rule_loader.h src/rule.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c src/rule_loader.cc -o src/rule_loader.o

src/password_loader.o: src/password_loader.cc src/password_loader.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c src/password_loader.cc -o src/password_loader.o

src/util.o: src/util.cc src/util.h $(RADIX_ROOT)/rax.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) -c src/util.cc -o src/util.o

src/genetic.o: src/genetic.cc src/genetic.h $(RADIX_ROOT)/rax.h src/rule.h src/partial_guessing.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) -c src/genetic.cc -o src/genetic.o

src/gengraph.o: src/gengraph.cc src/rule.h src/rule_loader.h src/password_loader.h src/util.h src/password_node.h src/graph.h src/graph_builder.h src/graph_db_writer.h src/genetic.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c src/gengraph.cc -o src/gengraph.o

gengraph: $(GENGRAPH_OBJS) $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -o gengraph $(GENGRAPH_OBJS) $(HC_ARCHIVE)

src/rax.o: $(RADIX_ROOT)/rax.h
	$(CC) -c $(RADIX_ROOT)/rax.c -o src/rax.o

src/password_data.o: src/password_data.cc src/password_data.h
	$(CXX) $(CXXFLAGS) -c src/password_data.cc -o src/password_data.o

src/rule_data.o: src/rule_data.cc src/rule_data.h
	$(CXX) $(CXXFLAGS) -c src/rule_data.cc -o src/rule_data.o

src/tree_builder.o: src/tree_builder.cc src/tree_builder.h $(RADIX_ROOT)/rax.h src/password_data.h src/rule_data.h src/rule.h src/partial_guessing.h $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(RADIX_FLAGS) $(LFLAGS_NATIVE) -c src/tree_builder.cc -o src/tree_builder.o $(HC_ARCHIVE)

src/run_genetic.o: src/run_genetic.cc $(RADIX_ROOT)/rax.h src/rule_loader.h src/password_loader.h src/genetic.h src/password_data.h src/partial_guessing.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(RADIX_FLAGS) $(LFLAGS_NATIVE) -c src/run_genetic.cc -o src/run_genetic.o $(HC_ARCHIVE)

src/analyze_tree.o: src/analyze_tree.cc $(RADIX_ROOT)/rax.h src/analyze_tree.h src/rule_data.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(RADIX_FLAGS) $(LFLAGS_NATIVE) -c src/analyze_tree.cc -o src/analyze_tree.o

src/gentree.o: src/gentree.cc src/rule.h src/password_loader.h src/rule_loader.h src/util.h src/password_data.h src/tree_builder.h src/analyze_tree.h src/partial_guessing.h $(RADIX_ROOT)/rax.h src/genetic.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) -c src/gentree.cc -o src/gentree.o

gentree: $(GENTREE_OBJS) $(HC_ARCHIVE) 
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) -o gentree $(GENTREE_OBJS) $(HC_ARCHIVE)

rule_regex_exp: src/rule_regex_exp.cc src/rule.h src/rule_loader.h src/rule.o src/rule_loader.o $(HC_ARCHIVE) $(RADIX_ROOT)/rax.h src/rax.o
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) src/rule_regex_exp.cc -o rule_regex_exp src/rule.o src/rule_loader.o $(HC_ARCHIVE) src/rax.o

genetic: $(GENETIC_OBJS) $(HC_ARCHIVE)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(RADIX_FLAGS) -o bin/genetic $(GENETIC_OBJS) $(HC_ARCHIVE)
