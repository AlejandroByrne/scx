import sys
import matplotlib.pyplot as plt

# Please use the following command to generate the input file for this parser:
# sudo turbostat --interval X --num_iterations Y --show CPU,Avg_MHz,Busy%,Bzy_MHz > cpu_freq_log.dat

def main():
    if len(sys.argv) != 5:
        print("Usage: python script.py input_file output_image time_slice_duration cpu_to_graph")
        sys.exit(1)

    input_file_name = sys.argv[1]
    output_image_name = sys.argv[2]
    time_slice_duration = float(sys.argv[3])
    cpu_to_graph = sys.argv[4]

    busy_percent_list = []
    bzy_mhz_list = []
    time_points = []
    time_slice_index = 0

    with open(input_file_name, 'r') as f:
        lines = f.readlines()

    i = 0
    total_lines = len(lines)
    while i < total_lines:
        line = lines[i].strip()
        if line == 'CPU\tAvg_MHz\tBusy%\tBzy_MHz':
            # Start of new time slice
            found_cpu_in_slice = False
            i += 1
            while i < total_lines:
                line = lines[i].strip()
                if line == '':
                    i += 1
                    continue
                if line == 'CPU\tAvg_MHz\tBusy%\tBzy_MHz':
                    break  # Next time slice
                tokens = line.split('\t')
                if len(tokens) != 4:
                    i += 1
                    continue
                cpu, avg_mhz, busy_percent, bzy_mhz = tokens
                if cpu == cpu_to_graph:
                    busy_percent_list.append(float(busy_percent))
                    bzy_mhz_list.append(float(bzy_mhz))
                    time_points.append(time_slice_index * time_slice_duration)
                    found_cpu_in_slice = True
                i += 1
            if not found_cpu_in_slice:
                busy_percent_list.append(float('nan'))
                bzy_mhz_list.append(float('nan'))
                time_points.append(time_slice_index * time_slice_duration)
            time_slice_index += 1
        else:
            i += 1

    # Plotting with two Y-axes
    fig, ax1 = plt.subplots()

    color1 = 'tab:blue'
    ax1.set_xlabel('Time')
    ax1.set_ylabel('Busy% (%)', color=color1)
    ax1.plot(time_points, busy_percent_list, marker='o', color=color1, label='Busy%')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_ylim(0, 100)  # Assuming Busy% ranges from 0 to 100

    ax2 = ax1.twinx()  # Create a second y-axis sharing the same x-axis
    color2 = 'tab:red'
    ax2.set_ylabel('Bzy_MHz (MHz)', color=color2)
    ax2.plot(time_points, bzy_mhz_list, marker='x', color=color2, label='Bzy_MHz')
    ax2.tick_params(axis='y', labelcolor=color2)

    plt.title(f'CPU {cpu_to_graph} Busy% and Bzy_MHz over Time')
    fig.tight_layout()
    plt.grid(True)

    # Adding legends for both lines
    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax2.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper left')

    plt.savefig(output_image_name)
    plt.close()

if __name__ == '__main__':
    main()

