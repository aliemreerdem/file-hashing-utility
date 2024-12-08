# File Hashing Utility

This application is a command-line tool designed to compute SHA-256 hashes of files, either for a single file or all files recursively in a given directory. Depending on the arguments provided, it can either:

1. Compute the SHA-256 hash of a single file and generate a `.sha256` verification file.
2. Recursively traverse a specified directory and compute the SHA-256 hashes of all files it contains, outputting the results in a CSV file.

## Key Features

- **Single File Mode:**  
  When executed with a single argument (a file path), the program calculates the file’s SHA-256 hash and creates a `<filename>.sha256` file containing the computed hash. This feature allows quick verification of a single file's integrity.

- **Directory Mode:**  
  When provided with two arguments (a directory path and a CSV output file path), the program:
  - Recursively enumerates all files in the given directory.
  - Computes the SHA-256 hash for each file.
  - Outputs the file path and its corresponding hash into the specified CSV file.
  - Prints progress information, including how many files have been processed and how many were skipped.

- **Progress and Logging:**  
  The tool provides real-time progress updates on the console, showing how many files have been processed, how many have been skipped, and total files discovered. This is especially helpful when dealing with large directories.

## Underlying Technologies and APIs Used

1. **C and Win32 API:**  
   The application is written in C and uses the Win32 API for:
   - File I/O operations (`CreateFileW`, `ReadFile`).
   - Directory traversal (`FindFirstFileW`, `FindNextFileW`).
   - Character encoding conversions (`WideCharToMultiByte`, `MultiByteToWideChar`).
   - Console I/O code page settings (`SetConsoleOutputCP`, `SetConsoleCP`) to handle UTF-8 output correctly.
   
2. **Windows Cryptography API: Next Generation (CNG) - bcrypt:**  
   The hashing is implemented using the `BCrypt` library provided by Windows. Specifically:
   - **BCryptOpenAlgorithmProvider**: Opens an algorithm handle for SHA-256 hashing.
   - **BCryptCreateHash**, **BCryptHashData**, **BCryptFinishHash**: Used to incrementally process file data and finalize the hash computation.
   These APIs ensure efficient and secure cryptographic operations on Windows without external dependencies.

3. **UTF-8 and Unicode Support:**
   - The application relies on Unicode-aware Win32 functions (`FindFirstFileW`, `FindNextFileW`, `CreateFileW`) to handle file paths with special or non-ASCII characters.
   - It uses `MultiByteToWideChar` and `WideCharToMultiByte` functions to convert between UTF-8 and wide-character (UTF-16) strings, ensuring compatibility with international characters.

4. **CSV Output:**
   When run in directory mode, the tool outputs file paths and their corresponding SHA-256 hashes into a CSV file, allowing easy integration with other tools or ingestion into spreadsheets, databases, or log analyzers.

5. **Progress Feedback:**
   The application prints progress information (files processed/skipped) to the console, updated in-place. This is done by writing carriage returns (`\r`) and flushing output buffers to update the same line dynamically.

## Usage

### Single File Mode

```bash
hash_calc.exe "C:\path\to\file.txt"

Computes the SHA-256 hash of file.txt.
Creates a file.txt.sha256 file containing the computed hash.
Ideal for quick checks or verification of a single file’s integrity.


### Directory Mode

```bash
hash_calc.exe "C:\path\to\directory" "output.csv"

Recursively enumerates directory and computes the SHA-256 hash for every file found.
Writes each file_path,hash pair to output.csv.
Provides ongoing progress updates on the console, including processed and skipped file counts.


### Requirements

Windows OS with the bcrypt library available (usually Windows 7 and above).
A compatible C compiler (such as MinGW-w64 or MSVC).
Basic knowledge of the command-line environment to run and provide arguments.


### Example

For a directory:
```bash
hash_calc.exe "C:\path\to\directory" "output.csv"

The tool scans all files under C:\MyData.
Writes their SHA-256 hashes to hashes.csv.
Shows progress while it runs.

For a single file:
```bash
hash_calc.exe "C:\MyData\example.bin"

Computes the SHA-256 hash of example.bin.
Creates example.bin.sha256 in the same directory.


### Notes

If a file or directory path includes non-ASCII characters, make sure the console code page is set to UTF-8 (e.g., chcp 65001 on Windows CMD) for correct display. The tool sets console output code pages to UTF-8 by default if the environment supports it.
If the specified CSV or .sha256 file already exists, it will be overwritten.

This program leverages native Windows APIs for file and directory operations, modern CNG (bcrypt) for secure hashing, and careful character encoding handling to support a wide range of filenames. It’s a convenient utility for data integrity verification and file inventory hashing.