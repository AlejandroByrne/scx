import matplotlib.pyplot as plt
import csv

# Lists to store the data
times = []
num_data_points = []
latencies = []
running_ratios = []
num_dispatches = []

# Read the data from a CSV file
with open('us.csv', 'r') as file:
    csv_reader = csv.reader(file)
    next(csv_reader)  # Skip the header row if it exists
    for row in csv_reader:
        times.append(int(row[0]))
        num_data_points.append(float(row[1]))
        latencies.append(float(row[2]))
        running_ratios.append(float(row[3]))
        num_dispatches.append(float(row[4]))

# Create the plot with multiple y-axes
fig, ax1 = plt.subplots(figsize=(12, 6))

# Plot each line on its own axis
color1, color2, color3, color4 = 'tab:blue', 'tab:orange', 'tab:green', 'tab:red'

# Number of Data Points
ax1.set_xlabel('Time')
ax1.set_ylabel('Number of Data Points', color=color1)
ax1.plot(times, num_data_points, color=color1, label='Number of Data Points')
ax1.tick_params(axis='y', labelcolor=color1)

# Latency
ax2 = ax1.twinx()
ax2.set_ylabel('Latency', color=color2)
ax2.plot(times, latencies, color=color2, label='Latency')
ax2.tick_params(axis='y', labelcolor=color2)

# Running Ratio
ax3 = ax1.twinx()
ax3.spines['right'].set_position(('outward', 60))
ax3.set_ylabel('Running Ratio', color=color3)
ax3.plot(times, running_ratios, color=color3, label='Running Ratio')
ax3.tick_params(axis='y', labelcolor=color3)

# Number of Dispatches
ax4 = ax1.twinx()
ax4.spines['right'].set_position(('outward', 120))
ax4.set_ylabel('Number of Dispatches', color=color4)
ax4.plot(times, num_dispatches, color=color4, label='Number of Dispatches')
ax4.tick_params(axis='y', labelcolor=color4)

# Title and grid
plt.title('Data Visualization Over Time')
ax1.grid(True, alpha=0.3)

# Combine all lines in one legend
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
lines3, labels3 = ax3.get_legend_handles_labels()
lines4, labels4 = ax4.get_legend_handles_labels()
lines = lines1 + lines2 + lines3 + lines4
labels = labels1 + labels2 + labels3 + labels4
ax1.legend(lines, labels, loc='upper left')

# Adjust layout to prevent cutting off labels
plt.tight_layout()

# Save the plot as a PNG file
plt.savefig('data_visualization.png', dpi=300)

print("Visualization saved as 'data_visualization.png'")
