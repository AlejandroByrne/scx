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

# Create the plot
plt.figure(figsize=(12, 6))

# Plot each line
plt.plot(times, num_data_points, label='Number of Data Points')
plt.plot(times, latencies, label='Latency')
plt.plot(times, running_ratios, label='Running Ratio')
plt.plot(times, num_dispatches, label='Number of Dispatches')

# Customize the plot
plt.title('Data Visualization Over Time')
plt.xlabel('Time')
plt.ylabel('Values')
plt.legend()
plt.grid(True)

# Adjust layout to prevent cutting off labels
plt.tight_layout()

# Save the plot as a PNG file
plt.savefig('data_visualization.png', dpi=300)

print("Visualization saved as 'data_visualization.png'")
