# Usernameassist

Combined Bruteforce Wordlist Generator & Web Scraper Utility

## Description

This repository contains a Python utility that combines two main functionalities:

1. **Wordlist Generator**: Generate custom wordlists for brute-force testing using specified character sets and length ranges
2. **Web Scraper**: Scrape usernames from websites to extract email addresses and phone numbers

## Features

### Wordlist Generation
- Generate wordlists with custom character sets
- Define minimum and maximum password/username length
- Progress tracking for large wordlist generation
- Duplicate removal and wordlist repair functionality

### Web Scraping
- Extract email addresses using regex pattern matching
- Extract phone numbers using regex pattern matching
- Process multiple usernames from a file
- Configurable user limit to control scraping scope

## Requirements

```bash
pip install requests
```

## Usage

The utility supports three main commands: `generate`, `repair`, and `scrape`.

### Generate a Wordlist

Generate a wordlist using a specific character set with minimum and maximum length:

```bash
python bruteforce_and_scraper.py generate <charset> <min_length> <max_length> <output_file>
```

**Example:**
```bash
python bruteforce_and_scraper.py generate abc123 3 5 mywordlist.txt
```

This generates all combinations of characters 'a', 'b', 'c', '1', '2', '3' with lengths from 3 to 5 characters.

### Repair a Wordlist

Remove duplicates and blank lines from an existing wordlist:

```bash
python bruteforce_and_scraper.py repair <input_file> <output_file>
```

**Example:**
```bash
python bruteforce_and_scraper.py repair mywordlist.txt cleaned_wordlist.txt
```

### Scrape Usernames

Scrape a list of usernames from a website to find email addresses and phone numbers:

```bash
python bruteforce_and_scraper.py scrape <usernames_file> <base_url_with_{username}> <output_file> [max_users]
```

**Example:**
```bash
python bruteforce_and_scraper.py scrape usernames.txt "https://somesite.com/{username}" results.txt 50
```

**Note:** Use quotes around the URL if it contains special characters like curly braces.

The `{username}` placeholder in the URL will be replaced with each username from the file.

## Termux Support

This utility works well on Android devices using Termux:

### Installation on Termux

```bash
# Update packages and install Python
pkg update && pkg install python

# Install required module
pip install requests

# Save and run the script
python bruteforce_and_scraper.py
```

## Important Notes

- **Wordlist Generation**: Large character sets and length ranges can produce very large files. Monitor disk space and be patient with generation time.
- **Web Scraping**: Ensure you have permission to scrape the target website. Respect robots.txt and terms of service.
- **Rate Limiting**: The scraper includes basic timeout handling but does not implement rate limiting. Use responsibly.

## License

See LICENSE file for details.
        
