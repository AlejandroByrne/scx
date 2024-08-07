import sys

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

def calculate_average(numbers):
    if not numbers:
        return 0
    return sum(numbers) / len(numbers)

def main():
    if len(sys.argv) != 2:
        print("Usage: python average_large_numbers.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    numbers = read_numbers_from_file(filename)
    average = calculate_average(numbers)
    print(f"The average of the numbers is: {average}")

if __name__ == "__main__":
    main()