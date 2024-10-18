import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Read the CSV file, specifying the decimal and thousands separator
df = pd.read_csv('input.csv', decimal='.', thousands=',')

# Convert 'time' to numeric type if it's not already
# df['time'] = pd.to_numeric(df['time'])

# Create a figure with multiple y-axes
fig, ax1 = plt.subplots(figsize=(12, 6))

# Plot each column against time
sns.lineplot(x='time', y='num_data_points', data=df, ax=ax1, color='blue', label='Num Data Points')
ax1.set_ylabel('Num Data Points')

ax2 = ax1.twinx()
sns.lineplot(x='time', y='latency', data=df, ax=ax2, color='red', label='Latency')
ax2.set_ylabel('Latency')

ax3 = ax1.twinx()
ax3.spines['right'].set_position(('axes', 1.1))
sns.lineplot(x='time', y='ratio', data=df, ax=ax3, color='green', label='Ratio')
ax3.set_ylabel('Ratio')

# Set the x-axis label
ax1.set_xlabel('Time')

# Combine legends
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
lines3, labels3 = ax3.get_legend_handles_labels()
ax1.legend(lines1 + lines2 + lines3, labels1 + labels2 + labels3, loc='upper left')

# Set title
plt.title('Data Visualization')

# Adjust layout and display the plot
plt.tight_layout()
plt.show()

