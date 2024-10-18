import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import sys

def collect_data(file_path, data_columns):
    """
    Reads data from a CSV file and returns a DataFrame.

    Parameters:
    - file_path (str): Path to the CSV-formatted text file.
    - data_columns (list of str): List of column names to read (excluding 'time').

    Returns:
    - pd.DataFrame: DataFrame containing the 'time' column and specified data columns.
    """
    try:
        # Define all required columns (including 'time')
        # required_columns = ['time'] + data_columns

        # Read the CSV file
        data = pd.read_csv(file_path)

        # Convert 'time' column to datetime
        # data['time'] = pd.to_datetime(data['time'])

        # Sort data by time in case it's unordered
        # data.sort_values('time', inplace=True)

        return data

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading the file: {e}")
        sys.exit(1)

def plot_data(data, data_columns):
    """
    Plots the specified data columns on a time-series graph with individual y-axes.

    Parameters:
    - data (pd.DataFrame): DataFrame containing 'time' and data columns.
    - data_columns (list of str): List of data columns to plot.
    """
    sns.set(style="whitegrid")  # Set Seaborn style for aesthetics

    # Initialize the matplotlib figure and axis
    fig, ax1 = plt.subplots(figsize=(12, 6))

    # Define color palette
    palette = sns.color_palette("tab10", n_colors=len(data_columns))
    
    # Plot the first data column
    color = palette[0]
    ax1.set_xlabel('Time', fontsize=12)
    ax1.set_ylabel(data_columns[0], color=color, fontsize=12)
    sns.lineplot(x='time', y=data_columns[0], data=data, ax=ax1, color=color, label=data_columns[0])
    ax1.tick_params(axis='y', labelcolor=color)

    # Formatter for the x-axis to display dates nicely
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.xticks(rotation=45)

    # Initialize additional y-axes if more than one data column exists
    axes = [ax1]
    for i, column in enumerate(data_columns[1:], start=1):
        # Create a new twin axis
        ax_new = ax1.twinx()
        axes.append(ax_new)

        # Offset the new axis to the right
        ax_new.spines['right'].set_position(('axes', 1 + 0.1 * (i-1)))

        # Make sure the new spines don't overlap
        ax_new.spines['right'].set_visible(True)

        # Assign a color from the palette
        color = palette[i % len(palette)]

        # Plot the data column
        sns.lineplot(x='time', y=column, data=data, ax=ax_new, color=color, label=column)

        # Set the y-axis label and color
        ax_new.set_ylabel(column, color=color, fontsize=12)
        ax_new.tick_params(axis='y', labelcolor=color)

    # Adjust layout to prevent label overlap
    fig.tight_layout()

    # Create a single legend for all lines
    handles = []
    labels = []
    for ax in axes:
        handle, label = ax.get_legend_handles_labels()
        handles += handle
        labels += label
    plt.legend(handles, labels, loc='upper left')

    # Set the title of the plot
    plt.title('Time Series Data Visualization', fontsize=16)

    # Show the plot
    plt.show()

def main():
    """
    Main function to execute the data collection and plotting.
    """
    # Example array of data column names (excluding 'time')
    data_columns = ['time', 'num data points', 'latency', 'ratio']  # Modify as needed

    # Path to the input data file
    file_path = 'input.csv'  # Replace with your actual file path

    # Collect data
    data = collect_data(file_path, data_columns)

    # Plot data
    plot_data(data, data_columns)

if __name__ == "__main__":
    main()
