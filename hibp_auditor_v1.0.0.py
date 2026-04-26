#!/usr/bin/env python3
"""
HaveIBeenPwned Breach Auditor
Version: 1.0.0
Purpose: Check email addresses and passwords against the HIBP breach database
Author: ShadowStrike (Strategos)
License: MIT
"""

import argparse
import hashlib
import requests
import sys
import time
from datetime import datetime

# HIBP API endpoints
HIBP_BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range/{}"

def check_email_breaches(email, api_key=None):
    """
    Check if an email address appears in known data breaches.
    
    Args:
        email: Email address to check
        api_key: HIBP API key (required for email checks)
    
    Returns:
        List of breach dictionaries or None if error
    """
    if not api_key:
        print("[ERROR] Email breach checking requires an HIBP API key")
        print("[INFO] Get a free key at: https://haveibeenpwned.com/API/Key")
        return None
    
    url = HIBP_BREACH_API.format(email)
    headers = {
        'hibp-api-key': api_key,
        'user-agent': 'HIBP-Breach-Auditor'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []  # No breaches found (good news!)
        elif response.status_code == 429:
            print("[ERROR] Rate limit exceeded - wait and try again")
            return None
        else:
            print(f"[ERROR] API returned status code: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network error: {e}")
        return None

def check_password_pwned(password):
    """
    Check if a password appears in known breaches using k-anonymity.
    
    This uses the Pwned Passwords API with k-anonymity - only the first 5 
    characters of the SHA-1 hash are sent to the API, protecting privacy.
    
    Args:
        password: Password to check (never sent to API in plain text)
    
    Returns:
        Tuple of (is_pwned: bool, count: int) or (None, None) if error
    """
    # Hash the password locally
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Send only the first 5 characters
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = HIBP_PASSWORD_API.format(prefix)
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            # Parse the response - each line is "suffix:count"
            hashes = response.text.split('\r\n')
            
            for hash_line in hashes:
                if ':' in hash_line:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return (True, int(count))
            
            # Hash not found in response = password not pwned
            return (False, 0)
            
        elif response.status_code == 429:
            print("[ERROR] Rate limit exceeded")
            return (None, None)
        else:
            print(f"[ERROR] API returned status code: {response.status_code}")
            return (None, None)
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network error: {e}")
        return (None, None)

def format_breach_info(breach):
    """Format a breach dictionary into readable output"""
    name = breach.get('Name', 'Unknown')
    domain = breach.get('Domain', 'N/A')
    breach_date = breach.get('BreachDate', 'Unknown')
    pwn_count = breach.get('PwnCount', 0)
    data_classes = ', '.join(breach.get('DataClasses', []))
    
    return f"""
  Breach: {name}
  Domain: {domain}
  Date: {breach_date}
  Accounts: {pwn_count:,}
  Data: {data_classes}
"""

def main():
    parser = argparse.ArgumentParser(
        description='Check email addresses and passwords against HaveIBeenPwned database',
        epilog='Example: python hibp_auditor.py --email test@example.com --api-key YOUR_KEY'
    )
    
    parser.add_argument('--email', type=str,
                        help='Email address to check for breaches')
    parser.add_argument('--password', type=str,
                        help='Password to check (uses k-anonymity - safe)')
    parser.add_argument('--api-key', type=str,
                        help='HIBP API key (required for email checks)')
    parser.add_argument('--output', type=str,
                        help='Write results to file (default: console only)')
    
    args = parser.parse_args()
    
    if not args.email and not args.password:
        parser.print_help()
        sys.exit(1)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []
    results.append(f"HIBP Breach Audit Report - {timestamp}")
    results.append("=" * 60)
    results.append("")
    
    # Check email if provided
    if args.email:
        print(f"\n[*] Checking email: {args.email}")
        results.append(f"Email: {args.email}")
        
        breaches = check_email_breaches(args.email, args.api_key)
        
        if breaches is None:
            results.append("  Status: ERROR - Could not complete check")
        elif len(breaches) == 0:
            print("[OK] No breaches found - this email is clean!")
            results.append("  Status: CLEAN - No breaches found")
        else:
            print(f"[WARNING] Found in {len(breaches)} breach(es):")
            results.append(f"  Status: COMPROMISED - Found in {len(breaches)} breach(es)")
            results.append("")
            
            for breach in breaches:
                breach_info = format_breach_info(breach)
                print(breach_info)
                results.append(breach_info)
        
        results.append("")
        
        # Rate limiting courtesy
        if args.password:
            time.sleep(1.5)
    
    # Check password if provided
    if args.password:
        print(f"\n[*] Checking password (using k-anonymity)...")
        results.append("Password: [REDACTED]")
        
        is_pwned, count = check_password_pwned(args.password)
        
        if is_pwned is None:
            results.append("  Status: ERROR - Could not complete check")
        elif is_pwned:
            print(f"[WARNING] Password found in {count:,} breaches!")
            print("[ADVICE] This password is compromised - change it immediately")
            results.append(f"  Status: PWNED - Found in {count:,} breaches")
            results.append("  Advice: Change this password immediately")
        else:
            print("[OK] Password not found in known breaches")
            results.append("  Status: CLEAN - Not found in known breaches")
        
        results.append("")
    
    # Write to file if requested
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(results))
            print(f"\n[*] Report written to: {args.output}")
        except IOError as e:
            print(f"\n[ERROR] Could not write to file: {e}")
    
    print("\n[*] Audit complete")

if __name__ == "__main__":
    main()
