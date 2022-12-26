#include <cmath>
#include <algorithm>
#include <numeric>
#include <vector>
#include <string>
#include "password_data.h"

using std::string, std::vector;

PasswordData::PasswordData(string password, bool is_target, int max_rule_size)
    : password(password), is_target(is_target), max_rule_size(max_rule_size) {
        complexity = estimate_password_strength();
    }

/*
 * From "Statistical metrics for individual password strength" and
 * "The science of guessing: analyzing an anonymized corpus of 70 million passwords"
 * by Joseph Bonneau
 */

/*
 * the definition of G ̃α requires several parts. The α-work-factor
 * μα reflects the required size μ of a dictionary needed to have a
 * cumulative probability α of success in an optimal guessing attack
 */
size_t alpha_work_factor(const vector<double> &probabilities, double alpha) {
    // indexes probabilities and will return as min size when cumulative_probability exceeds alpha
    size_t idx = 0;
    double cumulative_probability = 0.0;
    while (cumulative_probability < alpha) {
        cumulative_probability += probabilities[idx];
        idx++;
    }
    return idx;
}

double alpha_guesswork(const vector<double> &probabilities, size_t N,  double alpha, bool uniform_distribution = false) {
    // size_t N = probabilities.size();
    if (uniform_distribution) {
        return std::log2(N); // TODO: verify correct
    } else {
        const size_t a_ceil = std::ceil(alpha);
        size_t awf = alpha_work_factor(probabilities, alpha);
        double summation = 0.0;
        for (size_t idx = 1; idx <= awf; idx++) {
            summation += probabilities[idx-1] * i;
        }
        double agw = summation + (awf * (1 - a_ceil)); // avg guesses pec acc
        // g_sub_a converted to bits (TODO: Shannons?) by finding size of uniform dist
        // which would have an equivalent value of g_sub_a and taking a log:
        agw = std::log2(((2 * agw) / a_ceil) - 1) - std::log2(2 - a_ceil);
        return agw;
    }
}

double strength_partial_guessing(const vector<double> &probabilities, size_t N) {
    size_t index_x = 0; // number of items in X of greater probability than p_sub_x
    // TODO: assuming probs sorted for now?
    // TODO: index_x = count(probabilities) - idx_of(thiis->password)
    double alpha_x = 0.0;
    for (size_t idx = 0; idx < index_x; idx++) {
        alpha_x += probabilities[idx];
    }
    double agw = alpha_guesswork(probabilities, N, alpha_x);
    double strength = agw / alpha_x;
    // TODO: i+j/2 tweak?
    return strength;
}

double PasswordData::estimate_password_strength(const std::vector<double> &probabilities,
                                                size_t N,
                                                StrengthMetric metric) const {
    switch (metric) {
        case PROBABILITY:
            return 0.0;
        case INDEX:
            return 0.0;
        case PARTIAL_GUESSING:
            return strength_partial_guessing(probabilities, N);
    }
}

