import sys
import csv
import numpy as np


def analyze_data(file_path):
    # Initialize lists to store data for each column
    columns = [[], [], [], []]

    # Read the CSV file
    with open(file_path, 'r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            # Skip the time column (index 0) and parse the rest
            for i in range(1, 5):
                columns[i-1].append(float(row[i]))

    # Calculate statistics for each column
    for i, column in enumerate(columns):
        column_np = np.array(column)
        min_val = np.min(column_np)
        max_val = np.max(column_np)
        mean_val = np.mean(column_np)
        median_val = np.median(column_np)
        std_dev = np.std(column_np)

        print(f"Column {i+2}:")
        print(f"  Min: {min_val:.4f}")
        print(f"  Max: {max_val:.4f}")
        print(f"  Mean: {mean_val:.4f}")
        print(f"  Median: {median_val:.4f}")
        print(f"  Standard Deviation: {std_dev:.4f}")
        print()


if __name__ == "__main__":
    # Check if a file path is provided as an argument
    if len(sys.argv) < 2:
        print("Please provide the input file path as an argument.")
        sys.exit(1)

    file_path = sys.argv[1]
    analyze_data(file_path)
