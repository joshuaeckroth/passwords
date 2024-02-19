#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <unordered_map>
#include <stack>
#include <cmath>
#include <cstdlib>
#include <cctype>
#include <numeric>
#include <limits>
#include <algorithm>
#include <glog/logging.h>
#include "partial_guessing.h"

using std::cout, std::endl, std::string, std::vector;

PartialGuessData::PartialGuessData(string password, size_t occur_cnt) : password(password), occur_cnt(occur_cnt) {} 

void print_pgd(const PGV &v) {
    for (const auto &element : v) {
        cout << "Password: " << element.password
            << "\n - Index: " << element.index
            << "\n - Count: " << element.occur_cnt
            << "\n - Probability: " << element.probability
            << "\n - Strength: " << element.strength << endl;
    }
}

StrengthMap make_strength_map(const PGV &v) {
    StrengthMap m;
    for (const auto &element : v) {
        m.insert({element.password, element.strength});
    }
    return m;
}

PGV read_pguess_cache(string path) {
    PGV v;
    std::ifstream in_f(path);
    string line;
    while (std::getline(in_f, line)) {
        vector<string> tokens;
        std::stringstream stream(line);
        string token;
        while (std::getline(stream, token, '\t')) {
            tokens.push_back(token);
        }
        PartialGuessData d = {tokens[0], static_cast<size_t>(atoi(tokens[2].c_str()))};
        d.index = atof(tokens[1].c_str());
        d.probability = atof(tokens[3].c_str());
        d.cumulative_probability = atof(tokens[4].c_str());
        d.strength = atof(tokens[5].c_str());
        v.push_back(d);
    }
    return v;
}

void cache_pguess_metrics(const PGV &probabilities, string path) {
    LOG(INFO) << "Caching partial guess metric results...";
    std::ofstream file(path);
    auto str_precise = [](double d) {
        const size_t precision = 14;
        std::ostringstream out;
        out.precision(precision);
        out << std::fixed << d;
        return out.str();
    };
    if (file.is_open()) {
        for (const auto &element : probabilities) {
            string line = element.password
                + "\t" + str_precise(element.index)
                + "\t" + std::to_string(element.occur_cnt)
                + "\t" + str_precise(element.probability)
                + "\t" + str_precise(element.cumulative_probability)
                + "\t" + str_precise(element.strength);
            file << line << endl;
        }
        file.close();
        LOG(INFO) << "Finished caching partial guess metric results...";
    } else {
        LOG(ERROR) << "Unable to open file at path "
            << path
            << " to cache partial guess results..."
            << endl;
        return;
    }
}

size_t alpha_work_factor(const PGV &probabilities, double alpha, size_t &awf_start_idx) {
    //size_t idx = (0 < awf_start_idx - 1 || awf_start_idx - 1 == std::numeric_limits<size_t>::max()) ? 0 : awf_start_idx - 1;
    size_t idx = (awf_start_idx - 1 == std::numeric_limits<size_t>::max()) ? 0 : awf_start_idx - 1;
    if (idx != 0) {
    //cout << "idx is: " << idx << endl;
    } else {
      //  cout << "idxxxx is: " << idx << endl;
    }
    if (alpha == 1.0) return probabilities.size();
    double cumulative_probability = probabilities[idx].cumulative_probability; //0.0;
    idx++;
    while (cumulative_probability < alpha) {
        cumulative_probability += probabilities[idx].probability;
        idx++;
    }
    awf_start_idx = idx;
    return idx;
}

double alpha_guesswork(const PGV &probabilities, double alpha, size_t &awf_start_idx, bool uniform_dist = false) {
    if (uniform_dist) {
        const size_t N = probabilities.size();
        return std::log2(N);
    } else {
        const size_t awf = alpha_work_factor(probabilities, alpha, awf_start_idx);
        //cout << "awf is: " << awf << endl;
        double summation = 0.0;
        for (size_t idx = 1; idx <= awf; idx++) {
            summation += probabilities[idx-1].probability * idx;
        }
        //cout << "summation is: " << summation << endl;
        // sum of p_sub_i from i=1 to alpha-work-factor
        const double alpha_up = probabilities[awf-1].cumulative_probability;
        double agw = ((1.0 - alpha_up) * (double) awf) + summation;
        //cout << "alpha_up is: " << alpha_up << endl;
        double agw2 = std::log2(((2.0 * agw) / alpha_up) - 1.0) - std::log2(2.0 - alpha_up);
        return agw2;
    }
}

bool unseen_computed = false;
double strength_unseen_cached = 0.0;

double get_strength_unseen() {
    return strength_unseen_cached;
}

double compute_strength_unseen(const PGV &probabilities) {
    LOG(INFO) << "Computing strength of unseen passwords";
    if (unseen_computed) {
        return strength_unseen_cached;
    }
    size_t idx = 0;
    double agw = alpha_guesswork(probabilities, 1.0, idx);
    strength_unseen_cached = agw;
    unseen_computed = true;
//    const size_t N = probabilities.size();
//    const double alpha = 1.0;
//    const size_t awf = N;
//    double summation = 0.0;
//    for (size_t idx = 1; idx < awf; idx++) {
//        summation += probabilities[idx-1].probability * idx;
//    }
//    const double alpha_up = alpha;
//    double agw = ((1.0 - alpha_up) * (double) awf) + summation;
//    double agw2 = std::log2(((2.0 * agw) / alpha_up) - 1.0) - std::log2(2.0 - alpha_up);
//    strength_unseen_cached = agw2;
//    unseen_computed = true;
    //return strength_unseen_cached;
    return strength_unseen_cached; //std::log2(N + 1);
}

void generate_partial_guessing_strengths(PGV &probabilities) {
    const size_t N = probabilities.size();
    size_t awf_start_idx = 0;
    for (size_t idx = 0; idx < N; idx++) {
        const double alpha = probabilities[idx].cumulative_probability;
        //cout << "alpha for pw " << probabilities[idx].password << " is " << alpha << endl;
        const double strength = alpha_guesswork(probabilities, alpha, awf_start_idx);
        probabilities[idx].strength = strength;
        if (idx % 10000 == 0) {
            LOG(INFO) << "Generated strength for " << idx << " passwords";
        }
    }
    LOG(INFO) << "lg N is: " << std::log2(N);
}

// assumes input rows are sorted by frequency
PGV get_pguess_metrics(string path_to_distribution,
                       size_t pw_col_idx,
                       size_t freq_col_idx,
                       const char delim,
                       bool skip_headers,
                       bool use_cache,
                       string cache_path,
                       bool lc_password) {
    if (use_cache) {
        std::ifstream f(cache_path);
        if (f.good()) {
            f.close();
            LOG(INFO) << "Using password guess metrics cache...";
            return read_pguess_cache(cache_path);
        }
    }
    LOG(INFO) << "Computing password guess metrics...";
    PGV v;
    std::ifstream in_f(path_to_distribution);
    string line;
    size_t idx = 0;
    size_t sample_space_size = 0;
    std::stack<PartialGuessData> dup_stack;
    auto empty_stack = [&](size_t idx) {
        // each event in seq of equiprobable events x_i...x_i+j
        // gets index (i+j)/2, event indices start at, idx passed
        // is already 1 gt 0-based index in dist file
        size_t stack_size = dup_stack.size();
        size_t i = idx - stack_size + 1;
        size_t j = i + stack_size - 1;
        while (!dup_stack.empty()) {
            auto top = dup_stack.top();
            top.index = (stack_size == 1) ? i : (i + j) / 2.0; 
            v.push_back(top);
            dup_stack.pop();
        }
    };
    bool skipped_headers = false;
    while (std::getline(in_f, line)) {
        if (skip_headers && !skipped_headers) {
            skipped_headers = true;
            continue;
        }
        vector<string> tokens;
        std::stringstream stream(line);
        string token;
        while (std::getline(stream, token, delim)) {
            tokens.push_back(token);
        }
        string password = tokens[pw_col_idx];
        if (lc_password) {
            std::transform(password.begin(), password.end(), password.begin(), ::tolower);
        }
        const size_t count = atoi(tokens[freq_col_idx].c_str());
        sample_space_size += count;
        if (!dup_stack.empty()) {
            auto top = dup_stack.top();
            if (top.occur_cnt != count) {
                empty_stack(idx);
            }
        }
        dup_stack.push({password, count});
        idx++;
    }
    empty_stack(idx);
    double c_prob = 0.0;
    double old_c_prob = 0.0;
    double prev_p = 0.0;
    for (auto &ele : v) {
        // events with same probability should have the same
        // cumulative probability while subsequent events need
        // a c_prob taking the sum of previous probabilities
        // into account
        double p = ele.occur_cnt / (double) sample_space_size;
        ele.probability = p;
        if (prev_p == p) {
            c_prob += p;
            ele.cumulative_probability = old_c_prob;
        } else {
            c_prob += p;
            old_c_prob = c_prob;
            prev_p = p;
            ele.cumulative_probability = c_prob;
        }
    }
    LOG(INFO) << v.size() << " distinct events in password distribution";
    // event indices, probabilities, and cumulative probabilities
    // have now been computed... compute G ̃α
    generate_partial_guessing_strengths(v);
    cache_pguess_metrics(v, cache_path);
    //print_pgd(v);
    return v;
}
