#!/usr/bin/python3

import argparse


def replace_string_in_file(file_path: str, original_str: str, new_str: str):
    # Read the file
    with open(file_path, "rb+") as file:
        content = file.read()

        # Check if the original string exists in the file
        if original_str.encode() not in content:
            raise ValueError("Original string not found in the file")

        # Check if the length of the new string is greater than the original
        if len(new_str) > len(original_str):
            raise ValueError("New string is longer than the original string")

        # If the new string is shorter than the original, fill with null terminators
        null_terminators = ""
        if len(new_str) < len(original_str):
            null_terminators = "\0" * (len(original_str) - len(new_str))

        content = content.replace(
            original_str.encode(), (new_str + null_terminators).encode()
        )

        # Move the file pointer to the beginning and write the modified content
        file.seek(0)
        file.write(content)
        file.truncate()


def main(args):
    try:
        replace_string_in_file(args.file, args.text, args.new_text)
        print("Replacement successful!")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, required=True, help="File name")
    parser.add_argument(
        "-t", "--text", type=str, required=True, help="Original text to be replaced"
    )
    parser.add_argument(
        "-n", "--new_text", type=str, required=True, help="Original text replacement"
    )
    main(parser.parse_args())
