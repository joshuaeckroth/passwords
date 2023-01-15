#include "password_data.h"
#include <string>

PasswordData::PasswordData(bool is_target, float score, unsigned int orig_idx)
    : is_target(is_target), hit_count(0), score(score), orig_idx(orig_idx) {}
