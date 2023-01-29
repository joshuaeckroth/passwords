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

PartialGuessData::PartialGuessData(string hash, double index, size_t occur_cnt, double probability, double strength)
    : hash(hash), index(index), occur_cnt(occur_cnt), probability(probability) {}

PGV to_probability_vec(const PGM &m, bool sort) {
    PGV m_elements;
    for (const auto &element : m) {
        m_elements.push_back(element.second);
    }
    if (sort) {
        std::sort(m_elements.begin(), m_elements.end(), [](const auto &a, const auto &b) {
            return a.index < b.index;
        });
    }
    return m_elements;
}

void print_dist(const PGM &m) {
    PGV m_elements = to_probability_vec(m);
    for (const auto &element : m_elements) {
        cout << "Hash: " << element.hash
            << ", Index: " << element.index
            << ", Count: " << element.occur_cnt
            << ", Probability: " << element.probability << endl;
    }
}

PGM read_distribution(string path) {
    PGM dist;
    std::stack<PartialGuessData> dup_stack;
    auto empty_stack = [&](size_t i) {
        size_t stack_size = dup_stack.size();
        size_t j = i - stack_size + 1;
        double idx = (stack_size == 1) ? i : (i + j) / 2.0;
        while (!dup_stack.empty()) {
            PartialGuessData top = dup_stack.top();
            top.index = idx;
            dist.insert({top.hash, top});
            dup_stack.pop();
        }
    };
    const char delim = ':';
    std::ifstream in_f(path);
    string line;
    size_t idx = 0;
    size_t sample_space_size;
    while (std::getline(in_f, line)) {
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        string token;
        std::istringstream token_stream(line);
        std::getline(token_stream, token, delim);
        const string hash = token;
        std::getline(token_stream, token, delim);
        const size_t count = atoi(token.c_str());
        sample_space_size += count;
        if (dup_stack.empty()) {
            dup_stack.push({hash, 0.0, count, 0.0, 0.0});
        } else {
            auto top = dup_stack.top();
            if (top.occur_cnt != count) {
                empty_stack(idx - 1);
            }
            dup_stack.push({hash, 0.0, count, 0.0, 0.0});
        }
        idx++;
    }
    for (auto &element : dist) {
        double p = (double) element.second.occur_cnt / (double) sample_space_size;
        cout << "p: " << p << endl;
        element.second.probability = p;
    }
    empty_stack(idx);
    // print_dist(dist);
    return dist;
}

/*
 * the definition of G ̃α requires several parts. The α-work-factor
 * μα reflects the required size μ of a dictionary needed to have a
 * cumulative probability α of success in an optimal guessing attack
 */

size_t alpha_work_factor(const PGV &probabilities, double alpha) {
    // indexes probabilities and will return as min size when cumulative_probability exceeds alpha
    size_t idx = 0;
    double cumulative_probability = 0.0;
    while (cumulative_probability < alpha) {
        cumulative_probability += probabilities[idx].probability;
        idx++;
    }
    return idx;
}

double alpha_guesswork(const PGV &probabilities, double alpha, bool uniform_dist = false) {
    if (uniform_dist) {
        const size_t N = probabilities.size();
        return std::log2(N);
    } else {
        const size_t a_ceil = std::ceil(alpha);
        size_t awf = alpha_work_factor(probabilities, alpha);
        double summation = 0.0;
        for (size_t idx = 1; idx <= awf; idx++) {
            summation += probabilities[idx-1].probability * idx;
        }
        // avg guesses per acc
        double agw = ((1 - a_ceil) * awf) + summation;
        agw = std::log2(((2.0 * agw) / a_ceil) - 1) - std::log2(2 - a_ceil);
        return agw;
    }
}

void generate_partial_guessing_strengths(PGV &probabilities) {
    const size_t N = probabilities.size();
    double cumulative_prob = 0.0;
    for (size_t idx = 0; idx < N; idx++) {
        const double alpha = cumulative_prob;
        const double strength = alpha_guesswork(probabilities, alpha) / alpha;
        probabilities[idx].strength = strength;
        cumulative_prob += probabilities[idx].probability;
    }
}





