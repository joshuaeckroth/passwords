#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

struct PartialGuessData {
    std::string hash;
    double index;
    size_t occur_cnt;
    double probability;
    double strength;
    PartialGuessData(std::string, double, size_t, double, double);
};

typedef std::unordered_map<std::string, PartialGuessData> PGM;
typedef std::vector<PartialGuessData> PGV;

PGM read_distribution(std::string path);
PGV to_probability_vec(const PGM &m, bool sort = true);
void generate_partial_guessing_strengths(PGV&);
