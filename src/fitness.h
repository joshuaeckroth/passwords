#ifndef PASSWORDS_FITNESS_H
#define PASSWORDS_FITNESS_H

#include <string>

class VillageFitness {
    public:
        VillageFitness(double cracked_pct, double rpp);
        double get_cracked_pct() const;
        double get_rpp() const;

        bool operator>(const VillageFitness& other) const;
        const std::string to_string() const;

    private:
        double cracked_pct;
        double rpp;
};

#endif // PASSWORDS_FITNESS_H
