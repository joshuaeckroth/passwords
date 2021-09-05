
#include <stdio.h>
#include <errno.h>

#include <neo4j-client.h>
#include <openssl/md5.h>

#include "types.h"
#include "rp.h"
#include "rp_cpu.h"

void md5_bytes_to_hex(const unsigned char *md5, char *result) {
    char *ptr = result;
    for(int i = 0; i < 16; i++) {
        ptr += sprintf(ptr, "%02x", md5[i]);
    }
}

char *md5(const char *input) {
    unsigned char md5result[16];
    MD5((const unsigned char*)input, strlen(input), md5result);
    char *result = (char*)malloc(33);
    md5_bytes_to_hex(md5result, result);
    return result;
}

int main(int argc, const char** argv) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <password list> <rule list>\n", argv[0]);
        return -1;
    }
    FILE *fp_passwords;
    FILE *fp_rules;
    if((fp_passwords = fopen(argv[1], "r")) == NULL)
    {
        fprintf(stderr, "Cannot open passwords file \"%s\": %s\n", argv[1], strerror(errno));
        return -2;
    }
    if((fp_rules = fopen(argv[2], "r")) == NULL)
    {
        fprintf(stderr, "Cannot open rules file \"%s\": %s\n", argv[1], strerror(errno));
        return -3;
    }

    // load rules, first by counting them, then creating array of pointers
    int rule_count = 0;
    char *rule_line = NULL;
    size_t read_amount = 0;
    while(getline(&rule_line, &read_amount, fp_rules) != -1) {
        if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
            rule_count++;
        }
        free(rule_line);
        rule_line = NULL;
    }
    free(rule_line);
    rule_line = NULL;
    char **rules = (char**)malloc(rule_count*sizeof(char*));
    rewind(fp_rules);
    int rule_num = 0;
    int rule_len;
    while(getline(&rule_line, &read_amount, fp_rules) != -1) {
        if(strlen(rule_line) > 0 && rule_line[0] != '#' && rule_line[0] != '\n' && rule_line[0] != ':') {
            rule_line[strlen(rule_line)-1] = 0; // kill delimiter
            rule_len = strlen(rule_line);
            rules[rule_num] = (char*)malloc(rule_len+1);
            strcpy(rules[rule_num], rule_line);
            rule_num++;
        }
        free(rule_line);
        rule_line = NULL;
    }
    free(rule_line);
    fclose(fp_rules);

    neo4j_client_init();

    neo4j_connection_t *neo4j_con= neo4j_connect("neo4j://neo4j:lambda%0@localhost:7687", NULL, NEO4J_INSECURE);
    if(neo4j_con == NULL)
    {
        neo4j_perror(stderr, errno, "Connection failed");
        return EXIT_FAILURE;
    }

    // clear db
    neo4j_result_stream_t *results;
    results = neo4j_run(neo4j_con, "MATCH (n) DETACH DELETE n", neo4j_null);
    if (results == NULL)
    {
        neo4j_perror(stderr, errno, "Failed to run DELETE statement");
    }
    neo4j_close_results(results);

    char query[1024];
    char *password = NULL;
    size_t line_restrict = 0;
    while(getline(&password, &line_restrict, fp_passwords) != -1) {
        memset(query, 0, 1024);
        password[strlen(password)-1] = 0; // cut off delimiter
        printf("adding password: %s\n", password);
        char *md5pass_hex = md5(password);
        printf("adding password md5: %s\n", md5pass_hex);

        sprintf(query, "merge (p:Password { md5: '%s', password: '%s', iteration: 0})", md5pass_hex, password);
        results = neo4j_run(neo4j_con, query, neo4j_null);
        if (results == NULL)
        {
            neo4j_perror(stderr, errno, "Failed to run CREATE statement");
        }
        neo4j_close_results(results);
        free(password);
        free(md5pass_hex);
        password = NULL;
    }
    free(password);
    fclose(fp_passwords);

    // loop per password found in neo4j
    for(int iter = 0; iter < 10; iter++) {
        printf("\n\n== Iteration %d\n\n", iter);
        sprintf(query, "match (p:Password) where p.iteration = %d return p.password", iter);
        results = neo4j_run(neo4j_con, query, neo4j_null);
        while(1) {
            neo4j_result_t *result = neo4j_fetch_next(results);
            if(result == NULL)
            {
                break;
            }
            neo4j_value_t value = neo4j_result_field(result, 0);
            char password[RP_PASSWORD_SIZE];
            printf("password: %s\n", neo4j_string_value(value, password, RP_PASSWORD_SIZE));
            neo4j_string_value(value, password, RP_PASSWORD_SIZE);
            char *md5pass_hex = md5(password);
            //printf("password md5: %s\n", md5pass_hex);

            neo4j_result_stream_t *sub_results;
            for(int rule_idx = 0; rule_idx < rule_count; rule_idx++) {
                //printf("  rule: %s\n", rules[rule_idx]);
                char password_result[RP_PASSWORD_SIZE];
                memset(password_result, 0, sizeof(password_result));
                _old_apply_rule(rules[rule_idx], strlen(rules[rule_idx]), password, (u32)strlen(password), password_result);
                //printf("  result: %s\n", password_result);
                char *md5result_hex = md5(password_result);
                //printf("  result md5: %s\n", md5result_hex);

                sprintf(query, "merge (p:Password { md5: '%s', password: '%s'}) on create set p.iteration = %d", md5result_hex, password_result, iter+1);
                sub_results = neo4j_run(neo4j_con, query, neo4j_null);
                if (results == NULL)
                {
                    fprintf(stderr, "%s", query);
                    neo4j_perror(stderr, errno, "Failed to run CREATE statement");
                }
                neo4j_close_results(sub_results);

                sprintf(query, "match (before:Password), (after:Password) where before.md5='%s' and after.md5='%s' create (before)-[:RULE{ rule:'%s' }]->(after)",
                        md5pass_hex, md5result_hex, rules[rule_idx]);
                sub_results = neo4j_run(neo4j_con, query, neo4j_null);
                if (results == NULL)
                {
                    fprintf(stderr, "%s", query);
                    neo4j_perror(stderr, errno, "Failed to run CREATE statement");
                }
                neo4j_close_results(sub_results);

                free(md5result_hex);
            }
        }
        neo4j_close_results(results);
    }

    for(int rule_idx = 0; rule_idx < rule_count; rule_idx++) {
        free(rules[rule_idx]);
    }
    free(rules);
    neo4j_close(neo4j_con);
    neo4j_client_cleanup();
}

