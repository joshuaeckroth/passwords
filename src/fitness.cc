#include "fitness.h"

VillageFitness::VillageFitness(double cracked_pct, double rpp) : cracked_pct(cracked_pct), rpp(rpp) {}

double VillageFitness::get_cracked_pct() const {
    return cracked_pct;
}

double VillageFitness::get_rpp() const {
    return rpp;
}

bool VillageFitness::operator>(const VillageFitness& other) const {
    return ((this->cracked_pct > other.cracked_pct) && (this->rpp <= other.rpp))
           || ((this->cracked_pct >= other.cracked_pct) && (this->rpp < other.rpp));
}

const std::string VillageFitness::to_string() const {
    return "Cracked: " + std::to_string(cracked_pct) + " RPP: " + std::to_string(rpp);
}

