import matplotlib.pyplot as plt
import argparse
import csv
import re

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("top_n_generated_rules", type=str, help="Comma separated paths of tsv result files for generated rules")
    parser.add_argument("additional_rulefiles", type=str, help="Comma separated paths of tsv rsult files for extra rulefiles (ex: dive)")
    args = parser.parse_args()
    top_n_files = args.top_n_generated_rules.split(",")
    additional_files = args.additional_rulefiles.split(",")
    all_files = top_n_files + additional_files
    data_map = {}
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
        idx += 1
    ax.legend()
    ax.set_ylabel("# cracked")
    ax.set_xlabel("# attempted")
    ax.set_xscale("log")
    ax.set_title("cracked / attempted by sets of rules")
    plt.savefig("cracked_attempted_plot.png", dpi=300)

main()

