import matplotlib.pyplot as plt
import pandas as pd

d = pd.read_csv("stats.csv")
d = d[:1000]

fig, ax = plt.subplots()
ax.plot(d['iteration'], d['seconds'], color="black")
ax.set_xlabel("Cycle")
ax.set_ylabel("Seconds")
fig.tight_layout()
plt.savefig('stats-seconds.pdf', dpi=300)

fig, ax = plt.subplots()
ax.plot(d['iteration'], d['hitpct'], color="black")
ax.set_xlabel("Cycle")
ax.set_ylabel("Target hit %")
fig.tight_layout()
plt.savefig('stats-hitpct.pdf', dpi=300)

fig, ax = plt.subplots()
a, = ax.plot(d['iteration'], d['rules_composites_size'], color="black", label="Complex rules")
ax.set_ylabel('Complex rule count')
ax2 = ax.twinx()
b, = ax2.plot(d['iteration'], d['rules_primitives_size'], color="gray", label="Primitive rules")
ax2.set_ylabel('Primitive rule count')
p = [a, b]
ax.legend(p, [p_.get_label() for p_ in p])
ax.set_xlabel("Cycle")
fig.tight_layout()
plt.savefig('stats-rules_composites_size.pdf', dpi=300)

fig, ax = plt.subplots()
ax.plot(d['iteration'], d['rules_primitives_size'])
plt.savefig('stats-rules_primitives_size.pdf', dpi=300)

fig, ax = plt.subplots()
ax.plot(d['iteration'], d['res_mem_size'], color="black")
ax.set_xlabel("Cycle")
ax.set_ylabel("Resident Memory (KB; 1e7 KB = 10 GB)")
fig.tight_layout()
plt.savefig('stats-res_mem_size.pdf', dpi=300)
