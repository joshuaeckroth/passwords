#include <string>
#include <vector>
#include <iostream>
#include <errno.h>
#include <stdio.h>
#include "rule_loader.h"

using std::cout, std::cerr, std::endl, std::string, std::vector;

std::vector<Rule> RuleLoader::load_rules(const char *path) {
    FILE *fp_rules;
    if ((fp_rules = fopen(path, "r")) == NULL) {
        cerr << "Couldn't open rule file: " << strerror(errno) << endl;
        throw std::runtime_error(strerror(errno));
    }
    int rule_count = 0;
    char *rule_line = NULL;
    size_t read_amount = 0;
    while(getline(&rule_line, &read_amount, fp_rules) != -1) {
        if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
            rule_count++;
        }
        free(rule_line);
        rule_line = NULL;
    }
    free(rule_line);
    rule_line = NULL;
    char **rules = (char**)malloc(rule_count*sizeof(char*));
    rewind(fp_rules);
    int rule_num = 0;
    int rule_len;
    while(getline(&rule_line, &read_amount, fp_rules) != -1) {
        if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
            rule_line[strlen(rule_line)-1] = 0; // kill delimiter
            rule_len = strlen(rule_line);
            rules[rule_num] = (char*)malloc(rule_len+1);
            strcpy(rules[rule_num], rule_line);
            rule_num++;
        }
        free(rule_line);
        rule_line = NULL;
    }
    free(rule_line);
    fclose(fp_rules);
    vector<Rule> rule_vec;
    rule_vec.reserve(rule_count);
    for (int idx = 0; idx < rule_count; idx++) {
        rule_vec.push_back(Rule(rules[idx]));
    }
    return rule_vec;
}
