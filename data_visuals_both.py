import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def read_data(filename):
    try:
        df = pd.read_csv(filename, header=None, names=['Time', 'Data Points', 'Elapsed Time (ms)'])
        return df
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

def calculate_statistics(data):
    statistics = {
        'min': np.min(data),
        'max': np.max(data),
        'median': np.median(data),
        'mean': np.mean(data),
        'std_dev': np.std(data)
    }
    return statistics

def main(output_image):
    # Read data from both files
    us_df = read_data('us.dat')
    ks_df = read_data('ks.dat')

    # Synchronize time by using the index as time (0, 1, 2, ...)
    time = list(range(len(us_df)))

    # Calculate statistics for elapsed time
    us_stats = calculate_statistics(us_df['Elapsed Time (ms)'])
    ks_stats = calculate_statistics(ks_df['Elapsed Time (ms)'])

    # Create a figure and axis
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plot elapsed time for User Space and Kernel Space on the same x-axis
    ax1.plot(time, us_df['Elapsed Time (ms)'], label='User Space Elapsed Time', color='blue', marker='o')
    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('User Space Elapsed Time (ms)', color='blue')
    ax1.tick_params(axis='y', labelcolor='blue')

    ax2 = ax1.twinx()
    ax2.plot(time, ks_df['Elapsed Time (ms)'], label='Kernel Space Elapsed Time', color='red', linestyle='--', marker='x')
    ax2.set_ylabel('Kernel Space Elapsed Time (ms)', color='red')
    ax2.tick_params(axis='y', labelcolor='red')

    # Add a title
    plt.title('Comparison of Elapsed Time: User Space vs Kernel Space')

    # Combine legends
    lines_labels = [ax.get_legend_handles_labels() for ax in [ax1, ax2]]
    lines, labels = [sum(lol, []) for lol in zip(*lines_labels)]
    ax1.legend(lines, labels, loc='upper left')

    # Add statistics to the plot
    stats_text = (
        f"User Space Stats:\n"
        f"Min: {us_stats['min']:.2f} ms\n"
        f"Max: {us_stats['max']:.2f} ms\n"
        f"Median: {us_stats['median']:.2f} ms\n"
        f"Mean: {us_stats['mean']:.2f} ms\n"
        f"Std Dev: {us_stats['std_dev']:.2f} ms\n"
        f"\n"
        f"Kernel Space Stats:\n"
        f"Min: {ks_stats['min']:.2f} ms\n"
        f"Max: {ks_stats['max']:.2f} ms\n"
        f"Median: {ks_stats['median']:.2f} ms\n"
        f"Mean: {ks_stats['mean']:.2f} ms\n"
        f"Std Dev: {ks_stats['std_dev']:.2f} ms\n"
    )
    
    plt.gcf().text(0.15, 0.5, stats_text, fontsize=10, bbox=dict(facecolor='white', alpha=0.5))

    # Save the plot to an image file
    fig.tight_layout()  # Adjust layout to make room for the y-axis labels
    plt.savefig(output_image)
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <output_image>")
        sys.exit(1)

    output_image = sys.argv[1]
    main(output_image)