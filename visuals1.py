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

# Create subplots
fig, (ax1, ax2, ax3, ax4) = plt.subplots(4, 1, figsize=(12, 16), sharex=True)

# Plot each line on its own subplot
ax1.plot(times, num_data_points, color='tab:blue')
ax1.set_ylabel('Number of Data Points')
ax1.set_title('Data Visualization Over Time')

ax2.plot(times, latencies, color='tab:orange')
ax2.set_ylabel('Latency')

ax3.plot(times, running_ratios, color='tab:green')
ax3.set_ylabel('Running Ratio')

ax4.plot(times, num_dispatches, color='tab:red')
ax4.set_ylabel('Number of Dispatches')
ax4.set_xlabel('Time')

# Add grid to all subplots
for ax in [ax1, ax2, ax3, ax4]:
    ax.grid(True, alpha=0.3)

# Adjust layout to prevent cutting off labels
plt.tight_layout()

# Save the plot as a PNG file
plt.savefig('data_visualization.png', dpi=300)

print("Visualization saved as 'data_visualization.png'")
