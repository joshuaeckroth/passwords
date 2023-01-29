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

using std::cout, std::endl, std::string;

// first is i_sub_x, index is a float because all events in a seq x_sub_i...x_sub_i+j
// of equiprobable events are given the index (i + j) / 2
typedef std::pair<float, size_t> idx_cnt;

void print_dist(std::unordered_map<string, idx_cnt> m) {
    std::vector<std::pair<string, idx_cnt>> m_elements;
    for (const auto &element : m) {
        m_elements.push_back({element.first, element.second});
    }
    std::sort(m_elements.begin(), m_elements.end(), [](const auto &a, const auto &b) {
        return a.second.first < b.second.first;
    });
    for (const auto &element : m_elements) {
        cout << "Hash: " << element.first
            << ", Index: " << element.second.first
            << ", Count: " << element.second.second << endl;
    }
}

std::unordered_map<string, idx_cnt> read_distribution(string path) {
    std::unordered_map<string, idx_cnt> dist;
    std::stack<std::pair<string, size_t>> dup_stack;
    auto empty_stack = [&](size_t i) {
        size_t stack_size = dup_stack.size();
        size_t j = i - stack_size + 1;
        float idx = (stack_size == 1) ? i : (i + j) / 2.0f;
        while (!dup_stack.empty()) {
            auto top = dup_stack.top();
            string hash = top.first;
            size_t count = top.second;
            dist[hash] = {idx, count};
            dup_stack.pop();
        }
    };
    const char delim = ':';
    std::ifstream in_f(path);
    string line;
    size_t idx = 0;
    while (std::getline(in_f, line)) {
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        string token;
        std::istringstream token_stream(line);
        std::getline(token_stream, token, delim);
        const string hash = token;
        std::getline(token_stream, token, delim);
        const size_t count = atoi(token.c_str());
        if (dup_stack.empty()) {
            dup_stack.push({hash, count});
        } else {
            auto top = dup_stack.top();
            if (top.second != count) {
                empty_stack(idx - 1);
            }
            dup_stack.push({hash, count});
        }
        idx++;
    }
    empty_stack(idx);
    print_dist(dist);
    return dist;
}

