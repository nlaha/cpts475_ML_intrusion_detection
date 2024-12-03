import matplotlib.pyplot as plt
import numpy as np

# Sample accuracy: groups with varying numbers of intervals
accuracy = {
    "10 seconds - Non-Anomalous ": [92, 91, 89, 89, 87],
    "10 seconds - Anomalous""": [99, 100, 93, 97, 95],
    "30 seconds - Non-Anomalous": [86, 90, 86, 89, 89, 93],
    "30 seconds - Anomalous": [97, 97, 97, 92, 96, 100],
    "60 seconds - Non-Anomalous": [90, 90, 86, 86, 90, 95],
    "60 seconds - Anomalous": [99, 99, 99, 100, 97, 100],
}

accuracy_10 = {
    "10 seconds - Non-Anomalous ": [92, 91, 89, 89, 87],
    "10 seconds - Anomalous""": [99, 100, 93, 97, 95]
}

accuracy_30 = {
    "30 seconds - Non-Anomalous": [86, 90, 86, 89, 89, 93],
    "30 seconds - Anomalous": [97, 97, 97, 92, 96, 100]
}

accuracy_60 = {
    "60 seconds - Non-Anomalous": [90, 90, 86, 86, 90, 95],
    "60 seconds - Anomalous": [99, 99, 99, 100, 97, 100]
}

accuracy_non_anomalous = {
    "10 seconds": [92, 91, 89, 89, 87],
    "30 seconds": [86, 90, 86, 89, 89],
    "60 seconds": [90, 90, 86, 86, 90],
    "Percentages": [0.5, 1, 2.5, 5, 10]
}

accuracy_anomalous = {
    "10 seconds": [99, 100, 93, 97, 95],
    "30 seconds": [97, 97, 97, 92, 96],
    "60 seconds": [99, 99, 99, 100, 97],
    "Percentages": [0.5, 1, 2.5, 5, 10]
}

recall_score = {
    "10 seconds - Non-Anomalous ": [100, 100, 99, 100, 99],
    "10 seconds - Anomalous""": [62, 57, 55, 59, 52],
    "30 seconds - Non-Anomalous": [100, 99, 100, 98, 99, 100],
    "30 seconds - Anomalous": [28, 61.3, 48, 62, 65, 76],
    "60 seconds - Non-Anomalous": [100, 100, 100, 100, 99.5, 100],
    "60 seconds - Anomalous": [56, 66, 50, 52, 78, 80],
}

recall_score_10 = {
    "10 seconds - Non-Anomalous ": [100, 100, 99, 100, 99],
    "10 seconds - Anomalous""": [62, 57, 55, 59, 52],
}

recall_score_30 = {
    "30 seconds - Non-Anomalous": [100, 99, 100, 98, 99, 100],
    "30 seconds - Anomalous": [28, 61.3, 48, 62, 65, 76],
}

recall_score_60 = {
    "60 seconds - Non-Anomalous": [100, 100, 100, 100, 99.5, 100],
    "60 seconds - Anomalous": [56, 66, 50, 52, 78, 80],
}

f1_score = {
    "10 seconds - Non-Anomalous ": [96, 96, 94, 94, 93],
    "10 seconds - Anomalous""": [76, 73, 69, 74, 67],
    "30 seconds - Non-Anomalous": [92, 94, 92, 93, 94, 96],
    "30 seconds - Anomalous": [44, 74, 64, 74, 77, 87],
    "60 seconds - Non-Anomalous": [94, 95, 93, 92, 94.5, 97],
    "60 seconds - Anomalous": [72, 79, 66, 68, 78, 89],
}

f1_score_10 = {
    "10 seconds - Non-Anomalous ": [96, 96, 94, 94, 93],
    "10 seconds - Anomalous""": [76, 73, 69, 74, 67],
}

f1_score_30 = {
    "30 seconds - Non-Anomalous": [92, 94, 92, 93, 94, 96],
    "30 seconds - Anomalous": [44, 74, 64, 74, 77, 87],
}

f1_score_60 = {
    "60 seconds - Non-Anomalous": [94, 95, 93, 92, 94.5, 97],
    "60 seconds - Anomalous": [72, 79, 66, 68, 78, 89],
}

# enum: accuracy = 1, recall = 2, f1 = 3
ACCURACY = 10
ACCURACY_10 = 11
ACCURACY_30 = 12
ACCURACY_60 = 13
RECALL = 20
RECALL_10 = 21
RECALL_30 = 22
RECALL_60 = 23
FSCORE = 30
FSCORE_10 = 31
FSCORE_30 = 32
FSCORE_60 = 33

CURRENT_SCORE = ACCURACY

# list of enum values
plots_to_make = [
    ACCURACY_10, ACCURACY_30, ACCURACY_60, 
    RECALL_10, RECALL_30, RECALL_60, 
    FSCORE_10, FSCORE_30, FSCORE_60
    ]

#list of dictionaries
plotss = [
    accuracy_10, accuracy_30, accuracy_60, 
    recall_score_10, recall_score_30, recall_score_60, 
    f1_score_10, f1_score_30, f1_score_60
    ]

# Parameters
width = 0.2  # Width of bars
interval_counts = [len(accuracy[group]) for group in accuracy]
max_intervals = max(interval_counts)
groups = list(accuracy.keys())
x_positions = np.arange(max_intervals)

# Plotting
fig, ax = plt.subplots(figsize=(15, 6))

for i, (group, values) in enumerate(accuracy.items()):
    x_offset = i * width
    x_vals = x_positions[:len(values)] + x_offset
    ax.bar(x_vals, values, width, label=group)


# Formatting
ax.set_xticks(x_positions + (len(accuracy) - 1) * width / 2)
# ax.set_xticklabels([f"Interval {i+1}" for i in range(max_intervals)])
ax.set_xticklabels(["0.5%", "1%", "2.5%", "5%", "10%", "100%"])
ax.set_xlabel("Time Intervals")
ax.set_ylabel("Percentage")
match CURRENT_SCORE:
    case 10:
        ax.set_title("Precision Scores with Time Intervals")
        ax.legend(title="Groups")
    case 11:
        ax.set_title("Precision Scores with Time Intervals (10s)")
        ax.legend(title="Groups")
    case 12:
        ax.set_title("Precision Scores with Time Intervals (30s)")
        ax.legend(title="Groups")
    case 13:
        ax.set_title("Precision Scores with Time Intervals (60s)")
        ax.legend(title="Groups")
    case 20:
        ax.set_title("Recall Scores with Time Intervals")
        ax.legend(title="Groups")
    case 21:
        ax.set_title("Recall Scores with Time Intervals (10s)")
        ax.legend(title="Groups")
    case 22:
        ax.set_title("Recall Scores with Time Intervals (30s)")
        ax.legend(title="Groups")
    case 23:
        ax.set_title("Recall Scores with Time Intervals (60s)")
        ax.legend(title="Groups")
    case 30:
        ax.set_title("Precision Scores with Time Intervals")
        ax.legend(title="Groups")
    case 31:
        ax.set_title("Precision Scores with Time Intervals (10s)")
        ax.legend(title="Groups")
    case 32:
        ax.set_title("Precision Scores with Time Intervals (30s)")
        ax.legend(title="Groups")
    case 33:
        ax.set_title("Precision Scores with Time Intervals (60s)")
        ax.legend(title="Groups")
    case _:
        ax.set_title("Grouped scores with Time Intervals")
        ax.legend(title="Groups")
ax.legend(title="Groups")
plt.xticks(rotation=45)
plt.tight_layout()

# Save the plot as an image
output_file = "images/grouped_percentages.png"  # Change the filename and extension if needed
plt.savefig(output_file, dpi=300, bbox_inches="tight")  # dpi adjusts resolution
 

# For eachof the enum values in plots_to_make, plot the corresponding data

def plots():
    for idx, data in enumerate(plotss, start=1):
        # Parameters
        width = 0.2  # Width of bars
        interval_counts = [len(data[group]) for group in data]
        # print("interval_counts: ", interval_counts)
        max_intervals = max(interval_counts)
        # print("max_intervals: ", max_intervals)
        groups = list(data.keys())
        x_positions = np.arange(max_intervals)

        # Plotting
        fig, ax = plt.subplots(figsize=(10, 6))
        for i, (group, values) in enumerate(data.items()):
                x_offset = i * width
                x_vals = x_positions[:len(values)] + x_offset
                ax.bar(x_vals, values, width, label=group)

        # Formatting
        ax.set_xticks(x_positions + (len(data) - 1) * width / 2)
        # ax.set_xticklabels([f"Interval {i+1}" for i in range(max_intervals)])
        # Get the number of intervals and set the xticklabels accordingly
        
        if (max_intervals == 5):
            ax.set_xticklabels(["0.5%", "1%", "2.5%", "5%", "10%"])
        else:
            ax.set_xticklabels(["0.5%", "1%", "2.5%", "5%", "10%", "100%"])
        # ax.set_xticklabels(["0.5%", "1%"," 2.5%", "5%" "10%", "100%"])
        ax.set_xlabel("Intervals")
        ax.set_ylabel("Percentage")
        ax.set_title(f"Grouped Bar Plot {idx}")
        ax.legend(title="Groups")
        plt.xticks(rotation=45)
        output_file_name = "images/"
        title_name = ""
        # Time to build the output file name and the title name
        # First 3 plots are accuracy, next 3 are recall, last 3 are f1
        if (idx <= 3):
            output_file_name += "accuracy"
            title_name += "Accuracy "
        elif (idx <= 6):
            output_file_name += "recall"
            title_name += "Recall "
        elif (idx <= 9):
            output_file_name += "f1"
            title_name += "F1 "
        else:
            output_file_name = "other"
            title_name += "Some "
        # For each group of 3, the first is 10s, the second is 30s, the third is 60s
        title_name += "Scores with Time Intervals of"
        if( idx % 3 == 1):
            output_file_name += "_10s"
            title_name += " 10s"
        elif( idx % 3 == 2):
            output_file_name += "_30s"
            title_name += " 30s"
        elif( idx % 3 == 0):
            output_file_name += "_60s"
            title_name += " 60s"
        else:
            output_file_name += "_other"
            title_name += " some time"
        output_file_name += ".png"
        ax.set_title(title_name)
        plt.tight_layout()
            # Save the plot as an image
            # output_file = "images/grouped_percentages.png"  # Change the filename and extension if needed
        output_file = f"images/grouped_bar_plot_{idx}.png"  # Unique filename for each plot
        plt.savefig(output_file_name, dpi=300, bbox_inches="tight")  
    print("Plots have been saved as images in the images folder")

# Restore the function to plot the data in a scatter plot and connect the dots with a line graph
def group_plots():
    # First we'll plot the non-anomalous data

    fig,ax = plt.subplots(figsize=(10, 6))
    ax.plot(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["10 seconds"], marker="o", label="10 seconds")
    ax.plot(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["30 seconds"], marker="o", label="30 seconds")
    ax.plot(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["60 seconds"], marker="o", label="60 seconds")
    ax.scatter(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["10 seconds"])
    ax.scatter(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["30 seconds"])
    ax.scatter(accuracy_non_anomalous["Percentages"], accuracy_non_anomalous["60 seconds"])    
    # Set the precision as y axis


    ax.set_xlabel("Intervals")
    ax.set_ylabel("Percentage")
    ax.set_title("Non-Anomalous Precision Scores with Time Intervals")
    ax.legend(title="Time Intervals")
    ax.set_ylim(80, 100)
    output_file = "images/non_anomalous_precision_scores.png"
    plt.savefig(output_file, dpi=300, bbox_inches="tight")

# plots();
group_plots();