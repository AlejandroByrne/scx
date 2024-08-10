import sys
import statistics

def read_numbers_from_file(filename):
    numbers = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                try:
                    # Convert the line to a float and add to the list
                    number = float(line.strip())
                    numbers.append(number)
                except ValueError:
                    # If conversion fails, skip the line
                    pass
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    return numbers

def calculate_stats(numbers):
    if not numbers:
        return 0
    mean = statistics.mean(numbers)
    median = statistics.median(numbers)
    min_n = min(numbers)
    max_n = max(numbers)
    std_dev = statistics.stdev(numbers)

    return mean, median, min_n, max_n, std_dev

def main():
    if len(sys.argv) != 2:
        print("Usage: python average_large_numbers.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    numbers = read_numbers_from_file(filename)
    mean, median, min_n, max_n, std_dev = calculate_stats(numbers)
    # print(f"Mean: {mean}\nMedian: {median}\nMin: {min_n}\nMax: {max_n}\nStandard Deviation: {std_dev}\n")
    # Printing with the specified format
    print(f"        > Mean:                  {mean / 10000:18.10f}")
    print(f"        > Median:                {median / 10000:18.10f}")
    print(f"        > Min:                   {min_n / 10000:18.10f}")
    print(f"        > Max:                   {max_n / 10000:18.10f}")
    print(f"        > Standard Deviation:    {std_dev / 10000:18.10f}\n")

if __name__ == "__main__":
    main()