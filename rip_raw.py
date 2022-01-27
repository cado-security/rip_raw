"""
Copyright 2022 Cado Security Ltd. All rights reserved

__________.__         __________                
\______   \__|_____   \______   \_____ __  _  __
 |       _/  \____ \   |       _/\__  \\ \/ \/ /
 |    |   \  |  |_> >  |    |   \ / __ \\     / 
 |____|_  /__|   __/   |____|_  /(____  /\/\_/  
        \/   |__|             \/      \/        

rip_raw.py

Takes a Raw Binary such as a Memoy Dump and Carves files and logs using:
- Text/binary boundaries
- File headers and file magic
- Log entry

Then puts them in a zip file for secondary processing

"""

import string
import os
import os.path
import argparse
import shutil
from datetime import datetime
import logging
from typing import Union
from typing import Optional
import mimetypes

import re2
import magic


# Used to extract strings
ASCII_BYTE = " !\"#\$%&'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
n = 6
combined_reg = "(?:[%s]\x00|[%s]){%d,}" % (ASCII_BYTE, ASCII_BYTE, n)
combined_re = re2.compile(combined_reg)
# Allow lines with 7+ chars
good_line = re2.compile("[ 0-9a-zA-Z\.:]{7,}")

# Place extracted files here
EXTRACT_FOLDER = "/tmp/extracted_files/"

# Start extracted files with this
CARVED_MEMORY_PREPEND_FILENAME = "carved_memory_module_"

# 10 MB max filesize - Increasing this will slow performance
MAX_FILESIZE = 1024 * 10000
# Amount to read each iteration
READ_AMOUNT = 10240

# First files in the list match first
# Used for file carving
file_markers = [
    # elf
    "7f 45 4c 46 02 01 01",
    # jpg
    "ff d8 ff e0",
    # 7z
    "37 7a bc af 27",
    # avi
    "41 56 49 20",
    # bz
    "42 5A 68",
    # docx
    "50 4b 03 04 14",
    # doc
    "d0 cf 11 e0 a1",
    # png
    "89 50 4e 47",
    # rar
    "52 61 72 21",
    # zip
    "50 4b 30 30",
    # exe
    "4d 5a 90 00 03",
    # 2021
    "30 32 31 2d",
    # 2022
    "30 32 32 2d",
    # ElfChnk EVT
    "45 6c 66 43 68 6e 6b",
    # Evtx chunk
    "2a 2a 00 00",
    # PNG
    "89 50 4e 47 0d 0a 1a 0a",
    # doc
    "d0 cf 11 e0 a1 b1",
    # pst
    "21 42 4e a5 6f b5 a6",
    # <html
    "3c 68 74 6d",
    # <HTML
    "3c 48 54 4d",
    # LNK File
    "4c 00 00 00 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46",
    # <plist
    "70 6c 69 73 74",
]


def combined_strings_text(buf: bytes) -> str:
    """ Get strings worth indexing """
    results = []
    buf = buf.replace(b"\xff", b"\x00")
    decoded_text = buf.decode("utf8", "ignore")
    lines = combined_re.findall(decoded_text)
    current_regex = good_line
    for line in lines:
        if current_regex.search(line):
            results.append(line)
    text_output = "\n".join(results)
    # Remove non printable
    text_output = "".join(filter(lambda x: x in string.printable, text_output))
    return text_output


def combined_strings(buf: bytes) -> int:
    """ Returns how many strings are in the buffer """
    return len(combined_strings_text(buf))


def write_file(file_count: int, data_bytes: bytes, text_mode: bool = False) -> None:
    """ Write bytes to a file as text or binary """

    file_extension = ".bin"
    if text_mode:
        file_extension = ".log"

    mime_type = magic.from_buffer(data_bytes, mime=True)

    if mime_type != "application/octet-stream":
        extension = mimetypes.guess_extension(mime_type)
        if extension:
            file_extension = extension

    file_name = CARVED_MEMORY_PREPEND_FILENAME + str(file_count) + file_extension
    file_path = os.path.join(EXTRACT_FOLDER, file_name)

    if text_mode:
        text_content = combined_strings_text(data_bytes)

        # Sub-split the text/log file if it contains dates
        # Into a single file for each possible log entry
        now = datetime.utcnow()
        current_year = str(now.year)
        last_year = str(now.year - 1)
        if current_year in text_content or last_year in text_content:
            log_parts = []
            if current_year in text_content:
                log_parts = text_content.split(current_year)
            if last_year in text_content:
                log_parts = text_content.split(last_year)

            # Append delimeter year at the start of each split text
            file_extension = ".log"

            for split_count, part in enumerate(log_parts):
                text_part = part
                if split_count != 0:
                    text_part = current_year + part

                file_name = (
                    CARVED_MEMORY_PREPEND_FILENAME
                    + str(file_count)
                    + "_"
                    + str(split_count)
                    + file_extension
                )
                file_path = os.path.join(EXTRACT_FOLDER, file_name)

                with open(file_path, "w") as f:
                    f.write(text_part)

        # Text but doesnt contain a date
        else:
            with open(file_path, "w") as f:
                f.write(str(data_bytes))

    else:
        # Cant find a way to stop mypy erroring
        with open(file_path, "wb") as f:  # type: ignore
            f.write(data_bytes)  # type: ignore


def split_buffer(buffer: bytes, start_text: bool) -> int:
    """ Split into text and data halves """

    for file_marker in file_markers:
        byte_marker = bytearray.fromhex(file_marker)

        if byte_marker in buffer:
            before = buffer.split(byte_marker)[0]
            return len(before)

    # No header matches - Split on text vs binary
    count = 0

    for b in buffer:

        is_text = str(chr(b)).isprintable()

        # If it started with text
        if start_text:

            if not is_text:
                # We've found the split point
                return count

        # If starts with binary
        else:
            if is_text:
                # We've found the split point
                return count

        count += 1

    return count


def zip_folder(dir_name: str) -> str:
    """ Zip a folder """
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    return shutil.make_archive(dir_name, "zip", dir_name)


def convert_memory_to_zip(filepath: str) -> Union[str, None]:
    """ Convert memory to zip archive """

    if os.path.exists(EXTRACT_FOLDER):
        shutil.rmtree(EXTRACT_FOLDER)

    os.makedirs(EXTRACT_FOLDER, exist_ok=True)

    if os.path.isdir(filepath):
        logging.warning(
            f"{filepath} is a directory, skipping extraction. Likely already extracted successfully as Windows memory image"
        )
        return None

    with open(filepath, "rb") as input:
        file_count = 0
        text_mode = False
        data_buffer = bytes()

        while True:

            data = input.read(READ_AMOUNT)

            if bytearray(READ_AMOUNT) == data:
                # Skip empty sections
                pass
            else:

                just_split = False
                strings_length = combined_strings(data)

                # TODO: Remove
                split_point = 0

                if text_mode:
                    # We're now looking at strings
                    if strings_length < 1000 or len(data_buffer) > MAX_FILESIZE:
                        # logging.info("Processed " + str(mb_processed) + " Megabytes")
                        # logging.info("Buffer length: " + str(len(data_buffer)))
                        split_point = split_buffer(data, True)
                        text_mode = False
                        file_count += 1
                        data_buffer += data[:split_point]
                        write_file(file_count, data_buffer, True)
                        data_buffer = data[split_point:]
                        just_split = True

                else:
                    # Now we're looking at binary
                    if strings_length >= 1000 or len(data_buffer) > MAX_FILESIZE:
                        # logging.info("Processed " + str(mb_processed) + " Megabytes")
                        # logging.info("Buffer length: " + str(len(data_buffer)))
                        split_point = split_buffer(data, False)
                        text_mode = True
                        file_count += 1
                        write_file(file_count, data_buffer + data[:split_point], False)
                        data_buffer = data[split_point:]
                        just_split = True

                if not just_split:
                    data_buffer += data

            if len(data) < READ_AMOUNT:
                logging.info("Less than expected data, exiting")
                write_file(file_count, data_buffer + data[:split_point], text_mode)
                break

    zipped_evidence = zip_folder(EXTRACT_FOLDER)

    logging.info(f"Returning zip_archive {zipped_evidence}")
    
    return zipped_evidence


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Takes a raw memory image and converts it to a zip archive of individual files"
    )
    parser.add_argument(
        "-f", "--filename", help="The location of the memory image", required=True
    )

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    args = vars(parser.parse_args())
    filename = args["filename"]
    convert_memory_to_zip(filename)
