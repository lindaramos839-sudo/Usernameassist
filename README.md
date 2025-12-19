# Usernameassist

A combined bruteforce wordlist generator and web scraper utility for username research and investigation.

## Overview

Usernameassist is a Python-based tool that provides two main functionalities:
1. **Wordlist Generation**: Create custom wordlists for bruteforce attacks with configurable character sets and lengths
2. **Web Scraping**: Scrape usernames from websites to extract emails and phone numbers

## Features

- **Wordlist Generation**: Generate comprehensive wordlists with custom character sets and length ranges
- **Wordlist Repair**: Clean existing wordlists by removing duplicates and blank lines
- **Username Scraping**: Automatically scrape user profiles for contact information (emails and phone numbers)
- **Flexible Configuration**: Customize character sets, URL patterns, and processing limits
- **Termux Compatible**: Fully functional on Android devices using Termux

## Installation

### Requirements
- Python 3.x
- requests library

### Setup

```bash
# Clone the repository
git clone https://github.com/lindaramos839-sudo/Usernameassist.git
cd Usernameassist

# Install dependencies
pip install requests
```

### Termux Installation (Android)

```bash
# Update packages and install Python and git
pkg update && pkg install python git

# Install requests module
pip install requests

# Clone the repository
git clone https://github.com/lindaramos839-sudo/Usernameassist.git
cd Usernameassist
```

## Usage

### 1. Generate Wordlist

Generate a wordlist using a specific character set and length range:

```bash
python bruteforce_and_scraper.py generate <charset> <min_length> <max_length> <output_file>
```

**Example:**
```bash
python bruteforce_and_scraper.py generate abc123 3 5 mywordlist.txt
```

This generates all combinations of characters 'a', 'b', 'c', '1', '2', '3' with lengths from 3 to 5.

### 2. Repair Wordlist

Clean an existing wordlist by removing duplicates and blank lines:

```bash
python bruteforce_and_scraper.py repair <input_file> <output_file>
```

**Example:**
```bash
python bruteforce_and_scraper.py repair mywordlist.txt cleaned_wordlist.txt
```

### 3. Scrape Usernames

Scrape a list of usernames from a website to extract emails and phone numbers:

```bash
python bruteforce_and_scraper.py scrape <usernames_file> <base_url_with_{username}> <output_file> [max_users]
```

**Example:**
```bash
python bruteforce_and_scraper.py scrape usernames.txt "https://somesite.com/{username}" results.txt 50
```

**Note:** Use quotes around URLs containing curly braces!

The base URL should contain `{username}` which will be replaced with each username from the file.

## Parameters

### Generate Command
- `charset`: Characters to use in the wordlist (e.g., "abc123", "abcdefghijklmnopqrstuvwxyz")
- `min_length`: Minimum length of generated words
- `max_length`: Maximum length of generated words
- `output_file`: File to save the generated wordlist

### Repair Command
- `input_file`: Path to the wordlist to repair
- `output_file`: Path to save the cleaned wordlist

### Scrape Command
- `usernames_file`: Text file containing one username per line
- `base_url`: URL pattern with `{username}` placeholder
- `output_file`: File to save scraped results
- `max_users`: (Optional) Maximum number of usernames to process (default: 100)

## Output Format

### Wordlist Output
Plain text file with one word per line.

### Scrape Output
Text file with structured information:
```
Username: example_user
  Emails:
    user@example.com
    contact@example.org
  Phones:
    +1-234-567-8900

Username: another_user
  ...
```

## Legal Notice

⚠️ **WARNING**: This tool is for educational and authorized security testing purposes only.

- Only use this tool on systems and accounts you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Web scraping may violate website terms of service
- Always respect privacy and data protection laws
- The authors are not responsible for misuse of this tool

## License

This project is licensed under the CC0 1.0 Universal License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Support

For issues, questions, or suggestions, please open an issue on the GitHub repository.

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The developers assume no liability for any misuse or damage caused by this program.
