import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def read_data(filename):
    try:
        df = pd.read_csv(filename, header=None, names=['Time', '# of data points', 'average elapsed microseconds', '# of tasks enqueued'])
        return df
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python script_name.py <input_file> <output_image> <title>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_image = sys.argv[2]
    title = " ".join(sys.argv[3:])

    # Read data from the input file
    df = read_data(input_file)

    # Normalize the time to start at 0
    df['Time'] = df['Time'] - df['Time'].iloc[0]

    # Calculate statistics for the second column (average elapsed microseconds)
    mean_val = df['average elapsed microseconds'].mean()
    median_val = df['average elapsed microseconds'].median()
    min_val = df['average elapsed microseconds'].min()
    max_val = df['average elapsed microseconds'].max()
    std_dev_val = df['average elapsed microseconds'].std()

    # Create a figure and axis
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plot the first line
    ax1.plot(df['Time'], df['# of data points'], label='# of data points', color='b', marker='o')
    ax1.set_xlabel('Time')
    ax1.set_ylabel('# of data points', color='b')
    ax1.tick_params(axis='y', labelcolor='b')

    # Create a second y-axis sharing the same x-axis
    ax2 = ax1.twinx()
    ax2.plot(df['Time'], df['average elapsed microseconds'], label='average elapsed microseconds', color='g', marker='o')
    ax2.set_ylabel('average elapsed microseconds', color='g')
    ax2.tick_params(axis='y', labelcolor='g')

    # Create a third y-axis sharing the same x-axis
    ax3 = ax1.twinx()
    ax3.spines['right'].set_position(('outward', 60))  # Offset the third axis
    ax3.plot(df['Time'], df['# of tasks enqueued'], label='# of tasks enqueued', color='r', marker='o')
    ax3.set_ylabel('# of tasks enqueued', color='r')
    ax3.tick_params(axis='y', labelcolor='r')

    # Add a title
    plt.title(title)

    # Add statistics to the plot as text
    stats_text = (
        f"Statistics for average elapsed microseconds:\n"
        f"Mean: {mean_val:.2f}\n"
        f"Median: {median_val:.2f}\n"
        f"Min: {min_val:.2f}\n"
        f"Max: {max_val:.2f}\n"
        f"Standard Deviation: {std_dev_val:.2f}"
    )
    
    plt.gcf().text(0.15, 0.6, stats_text, fontsize=10, bbox=dict(facecolor='white', alpha=0.5))

    # Save plot to an image file specified by the second argument
    fig.tight_layout()  # Adjust layout to make room for the y-axis labels
    plt.savefig(output_image)
    plt.show()

if __name__ == "__main__":
    main()