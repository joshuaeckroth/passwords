#include <iostream>
#include <vector>
#include <string>
#include <set>
#include "rule.h"
#include "rule_loader.h"

extern "C" {
#include <rax.h>
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

using std::set, std::vector, std::string, std::cout, std::endl;

void gen(int i, size_t &gensize, rax *generated_rules, rax *simplified_rules, const set<string> &primitive_rules) {
    if(i <= 3) {
        rax *new_generated_rules = raxNew();
        raxIterator iter;
        raxStart(&iter, generated_rules);
        raxSeek(&iter, "^", NULL, 0);
        while(raxNext(&iter)) {
            for(auto & pr : primitive_rules) {
                string gr = string((char*)iter.key);
                string gr_new = gr + " " + pr;
                raxInsert(new_generated_rules, (unsigned char*)gr_new.c_str(), gr_new.size()+1, NULL, NULL);
                gensize++;
                string s_new = simplify_rule(gr_new);
                if(!s_new.empty()) {
                    raxInsert(simplified_rules, (unsigned char*)s_new.c_str(), s_new.size()+1, NULL, NULL);
                }
                /*
                if(s_new != gr_new) {
                    cout << gr_new << " -> " << s_new << endl;
                }
                 */

                if(gensize % 1000 == 0) {
                    cout << i << "," << gensize << "," << raxSize(simplified_rules) << endl;
                }
            }
        }
        return gen(i+1, gensize, new_generated_rules, simplified_rules, primitive_rules);
    }
}

int main(int argc, const char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <rule list>\n", argv[0]);
        return -1;
    }
    initialize_rule_replacements();
    vector<string> rules_vec = RuleLoader::load_rules<string>(argv[1]);
    set<string> primitive_rules;
    rax *generated_rules = raxNew();
    for (const auto &r: rules_vec) {
        primitive_rules.insert(r);
        raxInsert(generated_rules, (unsigned char *) r.c_str(), r.size() + 1, NULL, NULL);
    }
    rax *simplified_rules = raxNew();
    size_t gensize = 0;
    cout << "iter,generated,simplified" << endl;
    gen(1, gensize, generated_rules, simplified_rules, primitive_rules);
}
