# wc -l dive.rule = 99092, 6 lines are comments, 99806 rules
# 'RULESONLY' takes out comments
# $1 is ruleset to concat w/ ORTRTA, should be generated rules
# 99087 because first rule in ORTRTA is ':'
./concat_rules.clj rules/OneRuleToRuleThemAll.RULESONLY.txt $1 99087 > rules/OneRuleToRuleThemAll_Generated.rule
