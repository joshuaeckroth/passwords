import matplotlib.pyplot as plt
from matplotlib.offsetbox import AnchoredText
import argparse
import csv
import re
import uuid
import numpy as np

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
        ax.plot(x_vals, y_vals, label=key, color=plt.cm.rainbow(idx/len(all_files)))
        rpp = np.round(all_rule_counts[idx] / np.max(100*np.array(y_vals)/100000000 - 6.450))
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
    #ax.set_xscale("log")
    ax.set_title("cracked / attempted by sets of rules")
    #at = AnchoredText("Hashes: " + hashed + "\n" + "Wordlist: " + words, prop=dict(size=10), frameon=True, loc='lower right')
    #at.patch.set_boxstyle("round,pad=0.,rounding_size=0.2")
    #ax.add_artist(at)
    fileuuid = str(uuid.uuid1())
    fig.tight_layout()
    plt.savefig("cracked_attempted_plot_" + fileuuid + ".png", dpi=300)
    plt.savefig("cracked_attempted_plot_" + fileuuid + ".pdf", dpi=300)

    print(rpp_map)
    fig, ax = plt.subplots()
    for key in rpp_map['comparison']:
        ax.plot(rpp_map['comparison'][key]['rpp'], rpp_map['comparison'][key]['cracked%'], 'o')
        ax.annotate(key, xy=(rpp_map['comparison'][key]['rpp'], rpp_map['comparison'][key]['cracked%']), textcoords='data')
    ax.plot(list(map(lambda x: x['rpp'], rpp_map['top_n'])), list(map(lambda x: x['cracked%'], rpp_map['top_n'])), 'o')
    fig.tight_layout()
    plt.savefig("cracked_attempted_rpp_plot_" + fileuuid + ".pdf", dpi=300)


main()

