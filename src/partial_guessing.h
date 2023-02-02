#ifndef PARTIAL_GUESSING
#define PARTIAL_GUESSING

#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

struct PartialGuessData {
    std::string password;
    double index = 0.0;
    size_t occur_cnt;
    double probability = 0.0;
    double cumulative_probability = 0.0;
    double strength = 0.0;
    PartialGuessData(std::string, size_t);
};

typedef std::unordered_map<std::string, PartialGuessData> PGM;
typedef std::vector<PartialGuessData> PGV;
typedef std::unordered_map<std::string, double> StrengthMap;

StrengthMap make_strength_map(const PGV &v);
PGV read_pguess_cache(std::string path);
PGV get_pguess_metrics(std::string path_to_distribution,
                       size_t pw_col_idx = 0,
                       size_t freq_col_idx = 2,
                       const char delim = '\t',
                       bool skip_headers = true,
                       bool use_cache = true,
                       std::string cache_path = "data/pguess_metrics_cache.tsv",
                       bool lc_password = false);
void generate_partial_guessing_strengths(PGV&);
void print_pgd(const PGV &v);
double get_strength_unseen();
double compute_strength_unseen(const PGV&);

#endif /* PARTIAL_GUESSING */
