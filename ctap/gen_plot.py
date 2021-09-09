from os import listdir
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FormatStrFormatter


def generateData(files):
    data_to_plot = []

    for file in files:
        file1 = open(file, 'r')
        lines = file1.readlines()
        key_name = lines[0].strip()
        config = lines[2].split(",")
        is_correct = int(config[0]) > 0
        # if is_correct:
        #     continue
        is_random = int(config[1]) > 0
        # random_bytes = int(config[7])
        is_badorigin = int(config[2]) > 0
        retries = int(config[3])
        # is_broken = int(config[4]) > 0
        # is_block = int(config[5]) > 0
        # blocks = int(config[6])

        lines = [float(l) for l in lines[5:]]
        median = np.median(lines)
        mean = np.mean(lines)
        name = ""
        if is_correct:
            name = "Random\nkey handle"
        if is_random:
            name = "Random\nkey handle"
            # name="Random\nkey handle\n (length "+str(random_bytes)+")"
        if is_badorigin:
            name = "Bad origin\nkey handle"
        # if is_broken:
        #     name="Correct\nkey handle\nwith last\n byte broken"
        # if is_block:
        #     name="Correct\nkey handle\nwith replaced\n block "+str(blocks)
        data_to_plot.append({
            "values": lines,
            "median": median,
            "mean": mean,
            "name": name
        })

    sorted_data = sorted(data_to_plot, key=lambda k: k['name'])
    sorted_data_to_plot = [f["values"] for f in sorted_data]
    names = [f["name"] for f in sorted_data]
    medians = [f["median"] for f in sorted_data]
    means = [f["mean"] for f in sorted_data]

    fig1, ax1 = plt.subplots()
    ax1.boxplot(sorted_data_to_plot, showmeans=False, notch=True, vert=True, whis=0.75)

    plt.xticks(range(1, len(names) + 1), names)

    # plt.yticks(np.arange(10,80,20))
    # plt.gca().ticklabel_format(axis='y', style='sci', scilimits=(0, 0), useOffset=False)
    # plt.gca().yaxis.set_major_formatter(FormatStrFormatter('%d ms'))

    # ax1.set_title('HyperFIDO Titanium PRO\n response times [ms], '+str(retries)+' retries')
    ind = 0
    for tick in range(len(ax1.get_xticklabels())):
        ax1.text(tick + 1.1, medians[ind], round(medians[ind], 2), color="red")
        # ax1.text(tick+1.1, means[ind], round(means[ind],2),color="blue")
        # ax1.text(1, medians[ind]+1, medians[ind])
        ind += 1

    # ax1.set_title(key_name+' Titanium Pro\n response times [ms], '+str(retries)+' retries')
    plt.grid()
    plt.show()


onlyfiles = ["result0.txt", "result1.txt"]

# hyperFido = [f for f in onlyfiles if f.startswith("HyperFIDO")]

generateData(onlyfiles)
# generateData(yubicoFido)
