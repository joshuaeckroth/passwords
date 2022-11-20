include ../external/hashcat/src/Makefile

CXXFLAGS += -std=c++20
CFLAGS_NATIVE_PW := $(CFLAGS)
CFLAGS_NATIVE_PW += -DWITH_HWMON

ifeq ($(UNAME),Darwin)
ifeq ($(shell test $(DARWIN_VERSION) -le 15; echo $$?), 0)
CFLAGS_NATIVE_PW += -DMISSING_CLOCK_GETTIME
endif
ifeq ($(IS_APPLE_SILICON),1)
CFLAGS_NATIVE_PW += -arch arm64
endif
endif

CFLAGS_NATIVE_PW += -I ../external/hashcat/include -I ../external/hashcat/deps/LZMA-SDK/C -I ../external/hashcat/deps/zlib -I ../external/hashcat/deps/zlib/contrib -I ../external/hashcat/deps/OpenCL-Headers -I ../external/hashcat/deps/xxHash -I ../external/hashcat/deps/unrar -I ../external/hashcat/OpenCL

NEO4J_FLAGS = $(shell PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@1.1/lib/pkgconfig:../external/libneo4j-client-v4-install/lib/pkgconfig/ pkg-config --cflags --libs neo4j-client)
HC_ARCHIVE = ../external/hashcat/obj/combined.NATIVE.a

GENGRAPH_SRCS = rule.cc util.cc rule_loader.cc password_loader.cc password_node.cc graph.cc password_node_hash.cc graph_builder.cc
GENGRAPH_OBJS = $(subst .cc,.o,$(GENGRAPH_SRCS))
BIN = ../bin/

rule.o: rule.cc rule.h #obj/combined.NATIVE.a
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c rule.cc $(HC_ARCHIVE)

password_node.o: password_node.cc password_node.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c password_node.cc

password_node_hash.o: password_node_hash.cc password_node_hash.h password_node.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c password_node_hash.cc

graph.o: graph.cc graph.h password_node.h password_node_hash.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c graph.cc

graph_builder.o: graph_builder.cc graph_builder.h graph.h password_node.h rule.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) -c graph_builder.cc

rule_loader.o: rule_loader.cc rule_loader.h rule.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c rule_loader.cc

password_loader.o: password_loader.cc password_loader.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) -c password_loader.cc

util.o: util.cc util.h
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -c util.cc

gengraph: gengraph.cc rule.h rule_loader.h password_loader.h util.h password_node.h graph.h graph_builder.h $(GENGRAPH_OBJS)
	$(CXX) $(CXXFLAGS) $(CFLAGS_NATIVE_PW) $(LFLAGS_NATIVE) $(NEO4J_FLAGS) -g -o $(BIN)gengraph gengraph.cc $(HC_ARCHIVE) $(GENGRAPH_OBJS)

 
