import os
import sys
import re

MATCH = r"warning: `(?P<crate>\w.+)` \((?P<type>\w+)\) generated (?P<count>\d+) warning"

def main(filepath: str):
    warning_count = 0

    with open(filepath, "r") as file:
        # Skip first line, it's a mark
        file.readline()

        while (line := file.readline()):
            if line.startswith("+ Compiling"):
                break

            is_c_warning = line.startswith("/") and (" warning: " in line)
            is_rust_warning = re.match(MATCH, line)

            if is_c_warning:
                warning_count += 1

            if is_rust_warning:
                warning_count += int(is_rust_warning.group('count'))

    print(warning_count)

if __name__ == "__main__":
    if not sys.argv[1:]:
        print("No arguments")
        os.exit(1)

    main(sys.argv[1])