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
#include <algorithm>
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
    cout << "Caching partial guess metric results..." << endl;
    std::ofstream file(path);
    if (file.is_open()) {
        for (const auto &element : probabilities) {
            string line = element.password
                + "\t" + std::to_string(element.index)
                + "\t" + std::to_string(element.occur_cnt)
                + "\t" + std::to_string(element.probability)
                + "\t" + std::to_string(element.cumulative_probability)
                + "\t" + std::to_string(element.strength);
            file << line << endl;
        }
        file.close();
        cout << "Finished caching partial guess metric results..." << endl;
    } else {
        std::cerr << "Unable to open file at path "
            << path
            << " to cache partial guess results..."
            << endl;
        return;
    }
}

size_t alpha_work_factor(const PGV &probabilities, double alpha, size_t &awf_start_idx) {
    size_t idx = (0 < awf_start_idx - 1) ? 0 : awf_start_idx - 1;
    double cumulative_probability = 0.0;
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
        double summation = 0.0;
        for (size_t idx = 1; idx <= awf; idx++) {
            summation += probabilities[idx-1].probability * idx;
        }
        // sum of p_sub_i from i=1 to alpha-work-factor
        const double alpha_up = probabilities[awf-1].cumulative_probability;
        double agw = ((1.0 - alpha_up) * (double) awf) + summation;
        double agw2 = std::log2(((2.0 * agw) / alpha_up) - 1.0) - std::log2(2.0 - alpha_up);
        return agw2;
    }
}

void generate_partial_guessing_strengths(PGV &probabilities) {
    const size_t N = probabilities.size();
    size_t awf_start_idx = 0;
    for (size_t idx = 0; idx < N; idx++) {
        const double alpha = probabilities[idx].cumulative_probability;
        const double strength = alpha_guesswork(probabilities, alpha, awf_start_idx);
        probabilities[idx].strength = strength;
        if (idx % 10000 == 0) {
            cout << "Generated strength for " << idx << " passwords" << endl;
        }
    }
    cout << "lg N is: " << std::log2(N) << endl;
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
            cout << "Using password guess metrics cache..." << endl;
            return read_pguess_cache(cache_path);
        }
    }
    cout << "Computing password guess metrics..." << endl;
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
    cout << v.size() << " distinct events in password distribution" << endl;
    // event indices, probabilities, and cumulative probabilities
    // have now been computed... compute G ̃α
    generate_partial_guessing_strengths(v);
    cache_pguess_metrics(v, cache_path);
    //print_pgd(v);
    return v;
}

//PGV to_probability_vec(const PGM &m, bool sort) {
//    PGV m_elements;
//    for (const auto &element : m) {
//        m_elements.push_back(element.second);
//    }
//    if (sort) {
//        std::sort(m_elements.begin(), m_elements.end(), [](const auto &a, const auto &b) {
//            return a.index < b.index;
//        });
//        double cumulative_probability = 0.0;
//        for (auto &element : m_elements) {
//            element.cumulative_probability = cumulative_probability;
//            cumulative_probability += element.probability;
//        }
//    }
//    return m_elements;
//}

//void print_pgd(const PGM &m) {
//    PGV m_elements = to_probability_vec(m);
//    print_pgd(m_elements);
//}

//PGV get_pguess_metrics(string path) {
//    PGV v;
//    std::stack<PartialGuessData> dup_stack;
//    auto empty_stack = [&](size_t idx) {
//        size_t stack_size = dup_stack.size();
//        size_t j = idx - 1;
//        size_t i = idx - stack_size + 1;
//        double index = (stack_size == 1) ? v.size() - idx // 
//            : (j + i) / 2.0;
//        while (!dup_stack.empty()) {
//            PartialGuessData top = dup_stack.top();
//            top.index = index;
//            //v.insert({top.password, top});
//            v.push_back(top);
//            dup_stack.pop();
//        }
//    };
//    const char delim = ':';
//    std::ifstream in_f(path);
//    string line;
//    size_t idx = 0; //0;
//    size_t sample_space_size = 0;
//    while (std::getline(in_f, line)) {
//        //std::transform(line.begin(), line.end(), line.begin(), ::tolower);
//        string token;
//        std::istringstream token_stream(line);
//        std::getline(token_stream, token, delim);
//        const string password = token;
//        std::getline(token_stream, token, delim);
////        cout << "token c_str: " << token.c_str() << endl;
//        const size_t count = atoi(token.c_str());
////        cout << "count: " << count << endl;
//        sample_space_size += count;
////        cout << "sample_space_size: " << sample_space_size << endl;
//        if (dup_stack.empty()) {
//            dup_stack.push({password, 0.0, count, 0.0, 0.0});
//        } else {
//            auto top = dup_stack.top();
//            if (top.occur_cnt != count) {
//                empty_stack(idx); //- 1);
//            }
//            dup_stack.push({password, 0.0, count, 0.0, 0.0});
//        }
//        idx++;
//    }
//    empty_stack(idx); //- 1);
////    double cumulative_probability = 0.0;
////    size_t duplicate_count = 1;
////    double last_probability = 0.0;
////    for (auto &element : v) {
////        double p = (double) element.occur_cnt / sample_space_size;
////        element.probability = p;
//        // ensure events with the same p also have the same cumulative probability
//        // and that the cumulative probability of events after duplicates incorporate
//        // the sum of probabilities of events w/ duplicate probabilities
////        if (last_probability != p) {
////            cumulative_probability += p * duplicate_count;
////            last_probability = p;
////            duplicate_count = 1;
////            element.cumulative_probability = cumulative_probability;
////        } else {
////            duplicate_count++;
////            element.cumulative_probability = cumulative_probability;
////        }
//        //cumulative_probability += p;
//        //element.cumulative_probability = cumulative_probability;
////    }
//
//    double cp = 0.0; // cumulative probability
//    double ocp = 0.0; // 'old' cumulative probability - make sure events with the same probability have identical cp values
//    double lp = 0.0; // last probability
//    for (auto &ele : v) {
//        double p = (double) ele.occur_cnt / (double) sample_space_size;
//        ele.probability = p;
//        if (lp == p) {
//            cp += p;
//            ele.cumulative_probability = ocp;
//        } else {
//            cp += p;
//            ocp = cp;
//            lp = p;
//            ele.cumulative_probability = cp;
//        }
//    }
//
//    return v;
//}

/*
 * the definition of G ̃α requires several parts. The α-work-factor
 * μα reflects the required size μ of a dictionary needed to have a
 * cumulative probability α of success in an optimal guessing attack
 */

//size_t alpha_work_factor(const PGV &probabilities, double alpha) {
//    // indexes probabilities and will return as min size when cumulative_probability exceeds alpha
//    size_t idx = 0;
//    double cumulative_probability = 0.0;
//    // TODO: binsearch
////    auto binsearch = [&]() {
////        size_t l = 0;
////        size_t r = probabilities.size() - 1;
////        while (l < r) {
////            size_t mid = l + (r - l) / 2;
////            if (probabilities[mid].cumulative_probability < alpha) {
////                l = mid + 1;
////            } else {
////                r = mid;
////            }
////        }
////        return l;
////    };
//    while (cumulative_probability < alpha) {
//        cumulative_probability += probabilities[idx].probability;
//        idx++;
//    }
//    return idx; //binsearch();
//}

//double alpha_guesswork(const PGV &probabilities, double alpha, bool uniform_dist = false) {
//    if (uniform_dist) {
//        const size_t N = probabilities.size();
//        return std::log2(N);
//    } else {
//        const size_t a_ceil = std::max((int) std::ceil(alpha), 1);
//        size_t awf = alpha_work_factor(probabilities, alpha);
//        cout << "alpha work factor is: " << awf << endl; // *****
//        double summation = 0.0;
//        for (size_t idx = 1; idx <= awf; idx++) {
//            cout << "probability of idx: " << idx << " is: " << probabilities[idx-1].probability << endl;
//            summation += probabilities[idx-1].probability * probabilities[idx-1].index;
//        }
//        cout << "summation is: " << summation << endl;
//        // avg guesses per acc
//        double agw = ((1 - a_ceil) * awf) + summation;
//        cout << "agw is: " << agw << endl;
//        double agw2 = std::log2(((2.0 * agw) / a_ceil) + 1) - std::log2(2 - a_ceil);
//        return agw2;
//    }
//}

//void generate_partial_guessing_strengths(PGV &probabilities) {
//    const size_t N = probabilities.size();
//    //double cumulative_prob = 0.0;
//    for (size_t idx = 0; idx < N; idx++) {
//        //cumulative_prob += probabilities[idx].probability;
//        const double alpha = probabilities[idx].cumulative_probability; //cumulative_prob;
//         cout << "For password " << idx << " alpha is: " << alpha << endl; // *****
//        const double strength = alpha_guesswork(probabilities, alpha); /// alpha;
//        probabilities[idx].strength = strength;
//        if (idx % 10000 == 0) {
//            cout << "Generated strength for " << idx << " passwords" << endl;
//        }
//    }
//    cout << "lg N is: " << std::log2(N) << endl;
//}

double strength_unseen(const PGV &probabilities) {
    const size_t N = probabilities.size();
    return std::log2(N + 1);
}
