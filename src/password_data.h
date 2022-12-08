#ifndef PASSWORD_DATA
#define PASSWORD_DATA

struct PasswordData {
    bool is_target;
    bool did_apply_rules;
    PasswordData(bool, bool);
};

#endif /* PASSWORD_DATA */
