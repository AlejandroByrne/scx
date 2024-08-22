import numpy as np
import matplotlib.pyplot as plt

# Function to read data from a file and return it as a numpy array
def read_data(file_name):
    with open(file_name, 'r') as file:
        data = np.array([float(line.strip()) for line in file.readlines()])
    return data

# Read data from the two files
us_data = read_data('us.dat')
ks_data = read_data('ks.dat')

# Ensure we only use the first three data points
us_data = us_data[:3]
ks_data = ks_data[:3]

# Calculate statistics for the first three data points
us_mean = np.mean(us_data)
ks_mean = np.mean(ks_data)

us_std = np.std(us_data)
ks_std = np.std(ks_data)

print(f"User Space - Mean: {us_mean}, Std Dev: {us_std}")
print(f"Kernel Space - Mean: {ks_mean}, Std Dev: {ks_std}")

# Define the x-axis time points, assuming data is sampled every second
time_points = np.arange(1, 4)  # 1st, 2nd, and 3rd seconds

# Plot the data with the same time scale
plt.figure(figsize=(10, 6))
plt.plot(time_points, us_data, marker='o', label='User Space')
plt.plot(time_points, ks_data, marker='o', label='Kernel Space')

# Adjust axes limits to avoid separation
min_value = min(np.min(us_data), np.min(ks_data))
max_value = max(np.max(us_data), np.max(ks_data))
plt.ylim(min_value - 0.1 * abs(min_value), max_value + 0.1 * abs(max_value))

# Ensure the x-axis starts and ends at the same points
plt.xlim(1, 3)

# Labels and title
plt.xlabel('Time (seconds)')
plt.ylabel('Value')
plt.title('Comparison of User Space vs Kernel Space')
plt.legend()

# Show the plot
plt.show()