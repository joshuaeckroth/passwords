import matplotlib.pyplot as plt
import pandas as pd

d = pd.read_csv("rule_regex_exp.csv")
fig, ax = plt.subplots()
ax.plot(d["generated"], d["simplified"]/d["generated"])
plt.savefig("rules_growth.png", dpi=300)
plt.savefig("rules_growth.pdf", dpi=300)

print(d.groupby('iter').tail(1))