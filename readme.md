## Prerequisites

Before you begin, ensure you have Python installed on your machine. You can download it from [Official Python Website](https://www.python.org/downloads/) .

To check if Python is installed, run:

```bash
python --version
```


# Amazon VPC Log Parser

This Python script is designed to parse Amazon VPC logs stored in text files, classify them based on predefined lookup tables, and output the results into text files. The script supports two modes of operation: normal mode and interactive mode.

## Features

- **Parsing Amazon VPC Logs**: Processes logs stored in text files to extract relevant information.
- **Lookup Table Integration**: Utilizes a lookup table to assign tags based on protocol and destination port.
- **Two Output Files**: Generates `tag_counts.txt` and `port_protocol_counts.txt` with categorized counts.

## Modes

### Normal Mode

- Assumes default logs of version 2 and has all the default fields mentioned as per this document [AWS VPC Flow Log Records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- Automatically processes logs using default settings(assumes the log files are in "log_files.txt" file and lookuptable is in "lookup_table.txt" file ).

### Interactive Mode

- Provides options to specify a custom log format.
- Requires specifying the header which has the fileds dstport and protocol if using custom logs.
- Allows selecting a filename for the log file and a new lookup table.

## Usage

1. **Run in Normal/Default Mode**:
    ```bash
    python processLogs.py 
    ```

2. **Run in Interactive Mode**:
    ```bash
    python vpc_log_parser.py -i
    ```
    - Follow the prompts to enter custom log format, filename, and lookup table.

## Files

- **`processLogs.py`**: Main script for parsing logs and generating output files.
- **`generate_lookup_table.py`**: Generated lookup table file with 10,000 unique entries.
- **`tag_counts.txt`**: Output file containing counts of each tag.
- **`port_protocol_counts.txt`**: Output file containing counts of ports and protocols.

## Performance

- Tested with a 10 MB log file and a lookup table containing 10,000 unique entries to ensure performance with large files.

## Requirements

- Python 3.x
- No additional libraries are required.

## Example

To use the generated lookup table and log file:

Both the random_10MB_file.txt and generated_10MB_file.txt has custom vpc logs in the format: 

```bash
version vpc-id subnet-id instance-id interface-id account-id type srcaddr dstaddr srcport dstport pkt-srcaddr pkt-dstaddr protocol bytes packets start end action tcp-flags log-status
```

```bash
python processLogs.py -i
