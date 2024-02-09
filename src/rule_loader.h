#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <vector>
#include <cstring>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include "rule.h"

namespace RuleLoader {
    // Intended to take either std::string or Rule 
    template<typename T>
    std::vector<T> load_rules(const char* path) {
        FILE *fp_rules;
        if ((fp_rules = fopen(path, "r")) == nullptr) {
            std::cerr << "Couldn't open rule file " << path << ": " << strerror(errno) << std::endl;
            throw std::runtime_error(strerror(errno));
        }
        int rule_count = 0;
        char *rule_line = nullptr;
        size_t read_amount = 0;
        while(getline(&rule_line, &read_amount, fp_rules) != -1) {
            if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
                rule_count++;
            }
            free(rule_line);
            rule_line = nullptr;
        }
        free(rule_line);
        rule_line = nullptr;
        char **rules = (char**)malloc(rule_count*sizeof(char*));
        rewind(fp_rules);
        int rule_num = 0;
        size_t rule_len;
        while(getline(&rule_line, &read_amount, fp_rules) != -1) {
            if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
                rule_line[strlen(rule_line)-1] = 0; // kill delimiter
                rule_len = strlen(rule_line);
                rules[rule_num] = (char*)malloc(rule_len+1);
                strcpy(rules[rule_num], rule_line);
                rule_num++;
            }
            free(rule_line);
            rule_line = nullptr;
        }
        free(rule_line);
        fclose(fp_rules);
        std::vector<T> rule_vec;
        rule_vec.reserve(rule_count);
        for (int idx = 0; idx < rule_count; idx++) {
            rule_vec.emplace_back(rules[idx]);
            free(rules[idx]);
        }
        free(rules);
        return rule_vec;
    }
}

#endif /* RULE_LOADER_H */
