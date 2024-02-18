#include <string>
#include <regex>
#include <iostream>
#include <utility>
#include <vector>
#include <boost/regex.hpp>
#include <set>
#include <cstdlib>
#include "rule.h"

extern "C" {
#include <types.h>
#include <rp.h>
#include <rp_cpu.h>
}

using std::string, std::endl, std::cout, std::vector, std::pair, std::get, std::set, std::atoi;
using boost::regex, boost::regex_replace, boost::smatch;

Rule::Rule(string s) : raw(std::move(s)) {
    clean_rule = regex_replace(regex_replace(raw, regex("\""), "QUOTE"), regex("\t"), "\\t");
    tokens = tokenize();
}

Rule::Rule(const char* s) : raw(string(s)) {
    clean_rule = regex_replace(regex_replace(raw, regex("\""), "QUOTE"), regex("\t"), "\\t");
    tokens = tokenize();
}

Rule::Rule(const Rule& r) : raw(r.raw), clean_rule(r.clean_rule), weight(r.weight), score(r.score) {
    tokens = tokenize();
}

Rule::Rule(Rule&& r) : raw(std::move(r.raw)),
    clean_rule(std::move(r.clean_rule)),
    weight(r.weight),
    score(r.score),
    tokens(std::move(r.tokens)) {
    //tokens = tokenize();
}

Rule& Rule::operator=(const Rule &r) {
    this->raw = r.raw;
    this->clean_rule = r.clean_rule;
    this->weight = r.weight;
    this->score = r.score;
    return *this;
}

const string& Rule::get_rule_raw() const {
    return this->raw;
}

const string& Rule::get_rule_clean() const {
    return this->clean_rule;
}

float Rule::get_weight() const {
    return this->weight;
}

string Rule::apply_rule(const string& password) const {
    char *pw_cstr = (char*) calloc(password.size()+1, sizeof(char)); // +1 to make space for \0
    strcpy(pw_cstr, password.c_str());
    char new_password[RP_PASSWORD_SIZE];
//    cout << "raw rule is: " << this->raw << endl;
//    cout << "RP_PASSWORD_SIZE is: " << RP_PASSWORD_SIZE << endl;
//    cout << "password size is: " << password.size() << endl;
    _old_apply_rule(this->raw.c_str(), this->raw.size(), pw_cstr, password.size(), new_password);
    string result(new_password);
    free(pw_cstr);
    return result;
}

void Rule::decay_weight() {
    this->weight *= 0.99999;
}

void Rule::reset_weight() {
    this->weight = 1.0;
}

bool Rule::operator<(const Rule &r) const {
    //return this->weight < r.get_weight();
    return this->clean_rule < r.get_rule_clean();
}

std::ostream& operator<<(std::ostream &os, const Rule &r) {
    os << "hashcat function: " << r.get_rule_raw() << ", weight: " << r.get_weight();
    return os;
}

vector<pair<regex, string>> rule_replacements;
void initialize_rule_replacements() {
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ulcCt] ([\[\]\{\}r] )?([ulcC]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ul] ([\$\^]. |s.. )+([ul]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([ulcCt]) ([\[\]\{\}r]))", "$1$3 $2 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([ulcCt]) ([\$\^][^A-Za-z] )+([ulcCt]))", "$1$2 $4 $3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[ulcC] ([\$\^][^A-Za-z] )+([ulcC]))", "$1$2$3 "));
    rule_replacements.push_back(pair<regex, string>(R"((^| )([\$\^][^A-Za-z] )+([ulcC]))", "$1$3 $2 "));
    rule_replacements.push_back(pair<regex, string>("(^| )l t", "$1u"));
    rule_replacements.push_back(pair<regex, string>("(^| )u t", "$1l"));
    rule_replacements.push_back(pair<regex, string>("(^| )c t", "$1C"));
    rule_replacements.push_back(pair<regex, string>("(^| )C t", "$1c"));
    rule_replacements.push_back(pair<regex, string>("(^| )([rkKt]) \\2", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[\^\$](.) @\2)", "$1@$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^. \[)", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(.) \] \^(.))", "$1^$2 ^$3 ]"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$(.) \[ \$(.))", "$1[ \\$$2 \\$$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$. \])", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^. r \])", "$1r"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$. r \[)", "$1r"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$(.) \$(.) K)", "$1\\$$3 \\$$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(.) \^(.) k)", "$1^$3 ^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$(.) s\2(.))", "$1\\$$3 s$2$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(.) s\2(.))", "$1^$3 s$2$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \] \^(.) r)", "$1[ \\$$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \] r)", "$1["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \[ r)", "$1]"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \[ \] r)", "$1] ["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \] \[ r)", "$1] ["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\] \[ r)", "$1r ] ["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \^(.) r)", "$1\\$$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )r \$(.) r)", "$1^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\[ \])", "$1] [")); // right always before left bracket
    rule_replacements.push_back(pair<regex, string>("(^| )\\{ \\}", "$1"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\} \\{", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^. (\$. |[\]ulcCt] |s.. |K )+\[)", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$. (\^. |[\[ulcCt] |o.. |s.. |k )+\])", "$1$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$. \} \[)", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^. \{ \])", "$1"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\} \\[", "$1]"));
    rule_replacements.push_back(pair<regex, string>("(^| )\\{ \\]", "$1["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\} s(..) \[)", "$1$2 ]"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\{ s(..) \])", "$1$2 ["));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\] \^(.) \{)", "$1] $$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\[ \$(.) \})", "$1[ ^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$(.) \})", "$1^$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(.) \{)", "$1$$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )[\$\^](.) ([\$\^\@]. |[\{\}\]\[r] |[D,]\d )*@\2)", "$1$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )@(.) ([\[\]\{\}] |[\^\$]. |[\.,]\d )*@\2)", "$1$3@$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )o(\d)(.) (D[1-9] )*o\2(.))", "$1o$2$5"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )o0. \[)", "$1"));
    rule_replacements.push_back(pair<regex, string>("(^| )o.(.) @\\2", "$1@$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\^(.) o0(.))", "$1^$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )s(..) s\2)", "$1s$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )s(..) ([rcCult]))", "$1$3 s$2"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )s(..) s(..) s\2)", "$1s$2 s$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )s(.)(.) s\3(.))", "$1s$2$4"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )s(.)(.) s\2.)", "$1s$2$3"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )3(..) 3\2)", "$1"));
    rule_replacements.push_back(pair<regex, string>(R"((^| )\$. ,\d)", "$1")); // not equiv, but dumb to have a , operator after an append
    rule_replacements.push_back(pair<regex, string>(R"((^| )(z\d) z\d)", "$1$2")); // not equiv, but dumb to have two z operators back to back
    rule_replacements.push_back(pair<regex, string>(R"((^| )(Z\d) Z\d)", "$1$2")); // not equiv, but dumb to have two Z operators back to back

    // canonical ordering of symmetric operations
    // insert-front comes before insert-back
    rule_replacements.push_back(pair<regex, string>(R"((^| )(\$\S) (\^\S))", "$1$3 $2"));
    // chop-right comes before various other options
    rule_replacements.push_back(pair<regex, string>(R"((^| )\] (\[|s\S\S|\^\S|C|c|t|u|l|3))", "$1] $2"));
    // chop-left comes before various other options
    rule_replacements.push_back(pair<regex, string>(R"((^| )(s\S\S|\$\S|C|c|t|u|l|3) \[)", "$1[ $2"));
    // switching a char you just inserted
    rule_replacements.push_back(pair<regex, string>(R"((^| )(\$\^)(\S) s\3(\S))", "$1$2$4 s$3$4"));

    // not equiv, but don't let ] appear anywhere but the end, and [ anywhere but the beginning
    // make result invalid
    //rule_replacements.push_back(pair<regex, string>(".*\\] [^\\]]+ \\].*", ""));
    //rule_replacements.push_back(pair<regex, string>(".*\\[ [^\\[]+ \\[.*", ""));
    //rule_replacements.push_back(pair<regex, string>(".*\\] [^\\]]+$", ""));
    //rule_replacements.push_back(pair<regex, string>("^[^\\[]+ \\[.*", ""));

    // cleanup spaces
    rule_replacements.push_back(pair<regex, string>(" +", " "));
    rule_replacements.push_back(pair<regex, string>(" $", ""));
    rule_replacements.push_back(pair<regex, string>("^ ", ""));
}

string simplify_rule(string rule) {
    string result;
    bool done = false;
    while(!done) {
        bool changed = false;
        for(const auto &rep : rule_replacements) {
            result = regex_replace(rule, get<0>(rep), get<1>(rep));
            if(result != rule) {
                rule = result;
                changed = true;
                break;
            }
        }
        if(!changed) {
            done = true;
        }
    }
    return rule;
}

pair<size_t, size_t> count_distinct_rule_kinds(const string& rule) {
    set<char> kinds;
    size_t rule_count = 1;
    bool next_is_kind = true;
    for(size_t i = 0; i < rule.size(); i++) {
        if(next_is_kind) {
            kinds.insert(rule[i]);
        }
        if(rule[i] == ' ') {
            next_is_kind = true;
            rule_count++;
        } else {
            next_is_kind = false;
        }
    }
    return {kinds.size(), rule_count};
}

const regex position_validity_regex("(?:^| )[\\.,TD'yY](\\d+)");

bool check_rule_position_validity(const string& rule, const string& password) {
    smatch m;
    if(regex_search(rule, m, position_validity_regex)) {
        for(size_t i = 1; i < m.size(); ++i) {
            int pos = atoi(m[i].str().c_str());
            if(pos > password.size()) {
                return false;
            }
        }
    }
    return true;
}

vector<string> Rule::get_primitives() const {
    vector<string> primitives;
    char delim = ' ';
    size_t start = 0;
    for (size_t idx = 0; idx < this->clean_rule.size(); idx++) {
        if (this->clean_rule[idx] == ' ') {
            string sub = this->clean_rule.substr(start, idx - start);
            primitives.push_back(sub);
            start = idx + 1;
        }
    }
    primitives.push_back(this->clean_rule.substr(start, this->clean_rule.size() - start));
    return primitives;
}

vector<string> Rule::tokenize() {
    vector<string> local_tokens;
    std::smatch matches;
    string s = this->clean_rule;;
    for (std::smatch sm; regex_search(s, sm, Rule::tokenize_regex);) {
        local_tokens.push_back(sm.str());
        s = sm.suffix();
    }
    return local_tokens;
}

const vector<string>& Rule::get_tokens() const {
    return this->tokens;
}

Rule Rule::join_primitives(vector<string> primitives) {
    string full_rule_str = "";
    for (size_t idx = 0; idx < primitives.size(); idx++) {
        string primitive = primitives[idx];
        full_rule_str += (((idx > 0) ? " " : "") + primitive);
    }
    return Rule(full_rule_str);
}

float Rule::get_score() const {
    return this->score;
}

void Rule::set_score(float score) {
    this->score = score;
}

bool Rule::operator==(const Rule &r) const {
    return this->clean_rule == r.get_rule_clean();
}


