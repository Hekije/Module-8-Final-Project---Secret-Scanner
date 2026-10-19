
# SecretGuard - Hardcoded Secret Scanner

## Overview

SecretGuard is a Python security tool that scans files
and directories for patterns that may indicate hardcoded
secrets.

The application was created to demonstrate secure coding,
regular expressions, file handling, logging, and
command-line development.

It provides two ways to scan files:
1. Tkinter graphical desktop interface
2. Command-line interface using argparse

## Features

- Scan individual files or directories
- Detect passwords, API keys, and tokens
- Recognize common AWS and GitHub key formats
- Identify private key headers
- Display filename, line number, and secret category
- Mask credentials in regular reports
- Export results to CSV
- Log scanning activity and errors
- Run automated unit tests

## Requirements

- Python 3.10 or newer
- Tkinter
- No additional third-party packages required

## Project Files

main.py - Tkinter application
scanner.py - Secret detection and scanning engine
cli.py - Command-line interface and CSV export
tests/test_scanner.py - Automated tests
test_secrets.txt - Sample fake credentials
README.md - Project documentation

## How to Use the GUI

Open a terminal in the project folder and run:

    python main.py

1. Click Browse File or Browse Folder.
2. Select the target to scan.
3. Click START SECURITY SCAN.
4. Review the results in the table.
5. Click EXPORT SCAN REPORT to save a CSV report.

## How to Use the CLI

Scan one file:

    python cli.py test_secrets.txt

Scan an entire directory:

    python cli.py .

Export the findings:

    python cli.py test_secrets.txt --output report.csv

Enable logging:

    python cli.py test_secrets.txt --verbose

Display CLI help:

    python cli.py --help

Full matches can be displayed using --show-secrets,
but this should only be used in a secure environment.

## Detection Logic

SecretGuard uses Python's re module to search for
regular expression patterns.

Password Detection:
Searches for variable assignments containing names
such as password, passwd, pwd, or database_password.

API Key Detection:
Checks assignments with names such as api_key,
apiKey, client_secret, and secret_key.

Token Detection:
Checks variables such as token, access_token,
refresh_token, and auth_token.

AWS Detection:
Recognizes selected AWS access key ID formats
that begin with AKIA or ASIA.

GitHub Detection:
Recognizes selected GitHub token prefixes.

Private Key Detection:
Searches for PEM-style private key headers.

Each finding includes the file location, line number,
column number, secret category, and matched text.

## Report Output

CSV reports include:

- Filename
- Line number
- Column
- Secret type
- Matched string

Sensitive matches are masked by default.

## Logging

SecretGuard uses Python's logging module to display
information about scanning activity and file errors.

The --verbose option enables additional log output.

## Testing

Run the automated tests using:

    python -m unittest discover -s tests -v

The tests cover credential detection, masking,
file scanning, directory scanning, and exclusions.

## Limitations

Regular expressions cannot identify every possible
secret. Some credentials may be missed, while harmless
examples may be incorrectly identified.

The program does not verify whether a detected
credential is active.

It primarily scans supported text-based files and does
not inspect encrypted content or compiled binaries.

Some unreadable files may be skipped with a warning.

## Security Best Practices

- Avoid hardcoding credentials in source code.
- Use environment variables or secret managers.
- Rotate credentials if they are exposed.
- Review scanner findings before making changes.
- Do not upload real credentials or unmasked reports
  to public repositories.

## Technologies

Python, Tkinter, argparse, re, pathlib,
logging, threading, csv, and unittest.

## Author

Henry Escoto
Software Development Final Project