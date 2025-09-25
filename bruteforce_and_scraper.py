import itertools
import string
import sys
import os
import re
import requests

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
PHONE_REGEX = r"\+?\d[\d\-\(\) ]{7,}\d"

def generate_wordlist(charset, min_length, max_length, output_file):
    with open(output_file, 'w') as f:
        for length in range(min_length, max_length + 1):
            for word in itertools.product(charset, repeat=length):
                f.write(''.join(word) + '\n')
    print(f"[+] Wordlist generated at: {output_file}")

def repair_wordlist(input_file, output_file):
    seen = set()
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            word = line.strip()
            if word and word not in seen:
                outfile.write(word + '\n')
                seen.add(word)
    print(f"[+] Wordlist repaired and saved to: {output_file}")

def scrape_info(username, base_url):
    url = base_url.format(username=username)
    print(f"[*] Searching {url}")
    try:
        response = requests.get(url, timeout=8)
        text = response.text
        emails = re.findall(EMAIL_REGEX, text)
        phones = re.findall(PHONE_REGEX, text)
        return emails, phones
    except Exception as e:
        print(f"[!] Error accessing {url}: {e}")
        return [], []

def scrape_usernames(usernames_file, base_url, output_file, max_users=100):
    with open(usernames_file, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]

    results = []
    for i, username in enumerate(usernames[:max_users]):
        emails, phones = scrape_info(username, base_url)
        if emails or phones:
            results.append({'username': username, 'emails': emails, 'phones': phones})

    with open(output_file, 'w') as out:
        for item in results:
            out.write(f"Username: {item['username']}\n")
            if item['emails']:
                out.write("  Emails:\n")
                for email in set(item['emails']):
                    out.write(f"    {email}\n")
            if item['phones']:
                out.write("  Phones:\n")
                for phone in set(item['phones']):
                    out.write(f"    {phone}\n")
            out.write("\n")
    print(f"[+] Results written to {output_file}")

def print_usage():
    print("""
Combined Bruteforce Wordlist & Scraper Utility

Usage:
  python bruteforce_and_scraper.py generate <charset> <min_length> <max_length> <output_file>
      - Generate a wordlist using charset, min/max length, output to file

  python bruteforce_and_scraper.py repair <input_file> <output_file>
      - Repair an existing wordlist (remove duplicates, blanks)

  python bruteforce_and_scraper.py scrape <usernames_file> <base_url_with_{username}> <output_file> [max_users]
      - Scrape a list of usernames for emails and phone numbers
      - base_url example: https://somesite.com/{username}
      - Optional: max_users (default: 100)

Examples:
  python bruteforce_and_scraper.py generate abc123 3 5 mywordlist.txt
  python bruteforce_and_scraper.py repair mywordlist.txt cleaned_wordlist.txt
  python bruteforce_and_scraper.py scrape usernames.txt "https://somesite.com/{username}" results.txt 50

Note for Termux users:
- Install Python and pip if you haven't:
    pkg update && pkg install python
- Install requests module:
    pip install requests
- Save this script (nano bruteforce_and_scraper.py) and run as shown above.
- Use quotes for URLs with curly braces!
""")

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]
    if command == "generate":
        if len(sys.argv) != 6:
            print_usage()
        else:
            charset = sys.argv[2]
            min_length = int(sys.argv[3])
            max_length = int(sys.argv[4])
            output_file = sys.argv[5]
            generate_wordlist(charset, min_length, max_length, output_file)
    elif command == "repair":
        if len(sys.argv) != 4:
            print_usage()
        else:
            input_file = sys.argv[2]
            output_file = sys.argv[3]
            repair_wordlist(input_file, output_file)
    elif command == "scrape":
        if len(sys.argv) not in [5, 6]:
            print_usage()
        else:
            usernames_file = sys.argv[2]
            base_url = sys.argv[3]
            output_file = sys.argv[4]
            max_users = int(sys.argv[5]) if len(sys.argv) == 6 else 100
            scrape_usernames(usernames_file, base_url, output_file, max_users)
    else:
        print_usage()

if __name__ == "__main__":
    main()