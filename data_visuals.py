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
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <input_file> <output_image>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_image = sys.argv[2]

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

    # Plot the data
    plt.figure(figsize=(10, 6))
    plt.plot(df['Time'], df['# of data points'], label='# of data points', marker='o')
    plt.plot(df['Time'], df['average elapsed microseconds'], label='average elapsed microseconds', marker='o')
    plt.plot(df['Time'], df['# of tasks enqueued'], label='# of tasks enqueued', marker='o')

    plt.xlabel('Time')
    plt.ylabel('Values')
    plt.title('Metrics Over Time')
    plt.legend()
    plt.grid(True)

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
    plt.savefig(output_image)
    plt.show()

if __name__ == "__main__":
    main()