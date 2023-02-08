import matplotlib.pyplot as plt
from matplotlib.offsetbox import AnchoredText
import argparse
import csv
import re
import uuid
import numpy as np
import pprint
pp = pprint.PrettyPrinter(indent=4)

rule_names = {
        'pantagrule.private.v5.popular.prepended.dedup': 'Pantagrule-popular + Ours',
        'pantagrule.private.v5.popular': 'Pantagrule-popular',
        'ortft': 'ORTFT',
        'OneRuleToRuleThemAll.RULESONLY': 'ORTRTA',
        'pack-rockyou-100k': 'PACK top-100k',
        'pack-rockyou-50k': 'PACK top-50k',
        'pack-rockyou-64': 'PACK top-64',
        'generated.dedup.10k': 'Ours top-10k',
        'generated.dedup.50k': 'Ours top-50k',
        'generated.64': 'Ours top-64',
        'best64': 'best64',
        'dive': 'dive',
        'empty': 'No rules'
        }

attempted_plot = {'OneRuleToRuleThemAll.RULESONLY': '--',
                  'pantagrule.private.v5.popular.prepended.dedup': ':',
                  'generated.64': '-'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("top_n_generated_rules", type=str, help="Comma separated paths of tsv result files for generated rules")
    parser.add_argument("top_n_rule_counts", type=str, help="Comma separated rule counts")
    parser.add_argument("additional_rulefiles", type=str, help="Comma separated paths of tsv rsult files for extra rulefiles (ex: dive)")
    parser.add_argument("additional_rule_counts", type=str, help="Comma separated rule counts")
    parser.add_argument("hashed_source", type=str, help="Source of hashes")
    parser.add_argument("words_source", type=str, help="Source of wordlist")
    args = parser.parse_args()
    hashed = args.hashed_source
    words = args.words_source
    top_n_files = args.top_n_generated_rules.split(",")
    top_n_rule_counts = list(map(lambda x: int(x), args.top_n_rule_counts.split(",")))
    additional_files = args.additional_rulefiles.split(",")
    additional_rule_counts = list(map(lambda x: int(x), args.additional_rule_counts.split(",")))
    all_files = top_n_files + additional_files
    all_rule_counts = top_n_rule_counts + additional_rule_counts
    data_map = {}
    rpp_map = {'top_n': [], 'comparison': {}}
    fig, ax = plt.subplots()
    idx = 0
    for file in all_files:
        search_result = re.search(r"data_(.*)\..*$", file)
        key = search_result.group(1)
        if key not in rule_names:
            idx += 1
            continue
        x_vals = []
        y_vals = []
        with open(file) as tsvfile:
            reader = csv.reader(tsvfile, delimiter='\t')
            for row in reader:
                recovered = int(row[0])
                attempted = int(row[1])
                # ratio = recovered / attempted
                y_vals.append(recovered)
                x_vals.append(attempted)
        if key in attempted_plot:
            ax.plot(x_vals, y_vals, attempted_plot[key], label=rule_names[key], color="black")
        rpp = np.round(all_rule_counts[idx] / np.max(100*np.array(y_vals)/100000000 - 6.33))
        cracked_pct = 100*np.max(np.array(y_vals))/100000000
        print(file, "cracked%", cracked_pct, "rules", all_rule_counts[idx], "RPP", rpp)
        if idx < len(top_n_files):
            rpp_map['top_n'].append({'cracked%': cracked_pct, 'rpp': rpp})
        else:
            rpp_map['comparison'][key] = {'cracked%': cracked_pct, 'rpp': rpp}
        idx += 1
    ax.legend(fontsize=10)
    ax.set_ylabel("# cracked")
    ax.set_xlabel("# attempted")
    #ax.set_yscale("log")
    ax.set_xscale("log")
    ax.set_title("cracked / attempted by sets of rules")
    #at = AnchoredText("Hashes: " + hashed + "\n" + "Wordlist: " + words, prop=dict(size=10), frameon=True, loc='lower right')
    #at.patch.set_boxstyle("round,pad=0.,rounding_size=0.2")
    #ax.add_artist(at)
    fileuuid = str(uuid.uuid1())
    fig.tight_layout()
    #plt.legend(prop={'size':5})
    plt.savefig("cracked_attempted_plot_" + fileuuid + ".pdf", dpi=500)

    pp.pprint(rpp_map)
    fig, ax = plt.subplots()
    for key in rpp_map['comparison']:
        if key not in rule_names:
            continue
        if key == 'empty':
            continue
        ax.plot(rpp_map['comparison'][key]['rpp'], rpp_map['comparison'][key]['cracked%'], 'o', color="gray")
        ax.annotate(rule_names[key], xy=(rpp_map['comparison'][key]['rpp']+15, rpp_map['comparison'][key]['cracked%']+0.5), textcoords='data')
    ax.plot(list(map(lambda x: x['rpp'], rpp_map['top_n'])), list(map(lambda x: x['cracked%'], rpp_map['top_n'])), 'o')
    fig.tight_layout()
    plt.savefig("cracked_attempted_rpp_plot_" + fileuuid + ".pdf", dpi=300)


main()

