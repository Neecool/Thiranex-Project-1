#!/usr/bin/env python3
"""
Password Strength Analyzer - CLI Version
Built by Nkul Suthar
Internship Project 2025
"""

import re
import hashlib
import random
import string
import math
import os
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class PasswordStrengthAnalyzer:
    """Password Strength Analyzer - Developed by Nkul Suthar"""
    
    def __init__(self, history_file: str = "password_history.txt"):
        """Initialize the analyzer with password history tracking"""
        self.history_file = history_file
        self.password_hashes = set()
        self.load_history()
    
    def load_history(self):
        """Load previously used password hashes"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    for line in f:
                        self.password_hashes.add(line.strip())
        except Exception as e:
            print(f"Warning: Could not load history - {e}")
    
    def save_password_hash(self, password: str):
        """Save password hash to history"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            with open(self.history_file, 'a') as f:
                f.write(f"{password_hash}\n")
            self.password_hashes.add(password_hash)
            return True
        except Exception as e:
            print(f"Error saving password: {e}")
            return False
    
    def check_reuse(self, password: str) -> bool:
        """Check if password was used before"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash in self.password_hashes
    
    def check_length(self, password: str) -> Tuple[int, str]:
        """Check password length"""
        length = len(password)
        if length >= 16:
            return 25, f"✓ Excellent ({length} characters)"
        elif length >= 12:
            return 20, f"✓ Good ({length} characters)"
        elif length >= 8:
            return 15, f"⚠ Moderate ({length} characters)"
        else:
            return 0, f"✗ Too short ({length}/8 minimum)"
    
    def check_complexity(self, password: str) -> Tuple[int, Dict, int]:
        """Check character types"""
        checks = {
            'Uppercase': bool(re.search(r'[A-Z]', password)),
            'Lowercase': bool(re.search(r'[a-z]', password)),
            'Numbers': bool(re.search(r'\d', password)),
            'Special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        score = sum(checks.values())
        
        # Score based on number of types (max 40 points)
        if score == 4:
            points = 40
            rating = "Excellent"
        elif score == 3:
            points = 30
            rating = "Good"
        elif score == 2:
            points = 15
            rating = "Poor"
        else:
            points = 0
            rating = "Very Poor"
        
        return points, checks, rating
    
    def check_patterns(self, password: str) -> Tuple[int, List[str]]:
        """Check for common patterns and weaknesses"""
        warnings = []
        score = 35  # Base score for patterns
        
        lower_pass = password.lower()
        
        # Check for common passwords
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein', 
                           'welcome', 'monkey', 'dragon', 'master', 'football',
                           '12345678', '123456789', 'password123', 'admin123']
        
        if lower_pass in common_passwords:
            warnings.append("❌ Common password detected!")
            score -= 30
        
        # Check for sequential patterns
        sequences = ['123', '234', '345', '456', '567', '678', '789', 
                    'abc', 'bcd', 'cde', 'def', 'efg', 'qwe', 'wer', 'ert',
                    'asd', 'sdf', 'dfg', 'zxc', 'xcv', 'cvb']
        
        for seq in sequences:
            if seq in lower_pass:
                warnings.append(f"⚠ Contains sequential pattern: '{seq}'")
                score -= 15
                break
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            warnings.append("⚠ Contains repeated characters (e.g., 'aaa')")
            score -= 10
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl']
        for pattern in keyboard_patterns:
            if pattern in lower_pass:
                warnings.append("⚠ Keyboard pattern detected!")
                score -= 20
                break
        
        # Check for same case
        if password.isupper() or password.islower():
            warnings.append("⚠ All characters are same case")
            score -= 10
        
        # Check for common words
        common_words = ['password', 'admin', 'user', 'login', 'secret', 'hello', 'world']
        for word in common_words:
            if word in lower_pass:
                warnings.append(f"⚠ Contains common word: '{word}'")
                score -= 10
                break
        
        return max(0, score), warnings
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def evaluate(self, password: str) -> Dict:
        """Complete password evaluation"""
        results = {
            'password': '*' * len(password),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'score': 0,
            'max_score': 100,
            'feedback': [],
            'warnings': []
        }
        
        # Check length (max 25 points)
        length_score, length_msg = self.check_length(password)
        results['score'] += length_score
        results['feedback'].append(f"📏 Length: {length_msg}")
        
        # Check complexity (max 40 points)
        complexity_score, checks, complexity_rating = self.check_complexity(password)
        results['score'] += complexity_score
        results['feedback'].append(f"🔤 Complexity: {complexity_rating} ({complexity_score}/40)")
        results['complexity_checks'] = checks
        
        # Check patterns (max 35 points)
        pattern_score, warnings = self.check_patterns(password)
        results['score'] += pattern_score
        results['warnings'] = warnings
        
        if pattern_score >= 30:
            results['feedback'].append(f"🎯 Patterns: Good ({pattern_score}/35)")
        elif pattern_score >= 20:
            results['feedback'].append(f"🎯 Patterns: Moderate ({pattern_score}/35)")
        else:
            results['feedback'].append(f"🎯 Patterns: Weak ({pattern_score}/35)")
        
        # Check for password reuse
        if self.check_reuse(password):
            results['score'] = max(0, results['score'] - 50)
            results['warnings'].append("🔴 CRITICAL: This password has been used before!")
            results['reused'] = True
        else:
            results['reused'] = False
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        results['entropy'] = entropy
        
        # Entropy feedback
        if entropy >= 60:
            results['feedback'].append(f"🔐 Entropy: {entropy} bits (Excellent)")
        elif entropy >= 40:
            results['feedback'].append(f"🔐 Entropy: {entropy} bits (Good)")
        elif entropy >= 20:
            results['feedback'].append(f"🔐 Entropy: {entropy} bits (Moderate)")
        else:
            results['feedback'].append(f"🔐 Entropy: {entropy} bits (Weak)")
        
        # Determine strength rating
        if results['score'] >= 80:
            results['strength'] = "VERY STRONG"
            results['strength_color'] = "green"
            results['emoji'] = "🟢"
        elif results['score'] >= 60:
            results['strength'] = "STRONG"
            results['strength_color'] = "blue"
            results['emoji'] = "🔵"
        elif results['score'] >= 40:
            results['strength'] = "MODERATE"
            results['strength_color'] = "yellow"
            results['emoji'] = "🟡"
        elif results['score'] >= 20:
            results['strength'] = "WEAK"
            results['strength_color'] = "orange"
            results['emoji'] = "🟠"
        else:
            results['strength'] = "VERY WEAK"
            results['strength_color'] = "red"
            results['emoji'] = "🔴"
        
        return results
    
    def suggest_stronger(self, password: str) -> List[str]:
        """Generate stronger password suggestions"""
        suggestions = []
        
        # Analyze missing character types
        missing = []
        if not re.search(r'[A-Z]', password):
            missing.append('uppercase')
        if not re.search(r'[a-z]', password):
            missing.append('lowercase')
        if not re.search(r'\d', password):
            missing.append('digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            missing.append('special')
        
        # Suggestion 1: Add missing characters
        if missing:
            add_chars = []
            if 'uppercase' in missing:
                add_chars.append('X')
            if 'lowercase' in missing:
                add_chars.append('x')
            if 'digit' in missing:
                add_chars.append('7')
            if 'special' in missing:
                add_chars.append('!')
            
            suggestion = password + ''.join(add_chars)
            suggestions.append(suggestion)
        
        # Suggestion 2: Make longer with random chars
        if len(password) < 12:
            random_suffix = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%', k=4))
            suggestions.append(password + random_suffix)
        
        # Suggestion 3: Replace letters with numbers/symbols
        leet_map = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$',
            'A': '@', 'E': '3', 'I': '1', 'O': '0', 'S': '$'
        }
        leet_pass = ''.join(leet_map.get(c, c) for c in password)
        if leet_pass != password:
            suggestions.append(leet_pass)
        
        # Suggestion 4: Add random word + numbers
        words = ['Blue', 'Tiger', 'Coffee', 'Summer', 'Mountain', 'Elephant', 'Dragon']
        random_word = random.choice(words)
        random_num = random.randint(10, 999)
        suggestions.append(f"{password}{random_word}{random_num}!")
        
        # Suggestion 5: Capitalize first letter and add special chars
        if password[0].islower():
            suggestions.append(password[0].upper() + password[1:] + "@@")
        
        # Remove duplicates and limit
        unique_suggestions = []
        for s in suggestions:
            if s not in unique_suggestions and s != password:
                unique_suggestions.append(s)
        
        return unique_suggestions[:5]


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print fancy banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║           ██▓███   ▄▄▄       ██████   ██████  █     █░               ║
║          ▓██░  ██▒▒████▄   ▒██    ▒ ▒██    ▒ ▓█░ █ ░█░               ║
║          ▓██░ ██▓▒▒██  ▀█▄ ░ ▓██▄   ░ ▓██▄   ▒█░ █ ░█                ║
║          ▒██▄█▓▒ ▒░██▄▄▄▄██  ▒   ██▒  ▒   ██▒░█░ █ ░█                ║
║          ▒██▒ ░  ░ ▓█   ▓██▒██████▒▒▒██████▒▒░░██▒██▓                ║
║          ▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▓░▒ ▒                 ║
║          ░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░  ▒ ░ ░                 ║
║          ░░         ░   ▒   ░  ░  ░  ░  ░  ░    ░   ░                 ║
║                         ░  ░      ░        ░    ░                   ║
║                                                                      ║
║              🔐 PASSWORD STRENGTH ANALYZER 🔐                        ║
║                                                                      ║
║                    Built by Nkul Suthar                              ║
║                   Internship Project 2025                            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_results(results: Dict):
    """Display analysis results beautifully"""
    print("\n" + "=" * 70)
    print(f" 📊 ANALYSIS RESULTS - {results['timestamp']}")
    print("=" * 70)
    
    # Strength display
    print(f"\n {results['emoji']} STRENGTH: {results['strength']}")
    print(f" 📈 SCORE: {results['score']}/{results['max_score']}")
    print(f" 🔐 ENTROPY: {results['entropy']} bits")
    
    # Progress bar
    bar_length = 50
    filled = int(bar_length * results['score'] / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"\n [{bar}] {results['score']}%")
    
    # Feedback
    print("\n" + "-" * 70)
    print(" 📝 DETAILED FEEDBACK:")
    print("-" * 70)
    for feedback in results['feedback']:
        print(f"   {feedback}")
    
    # Complexity details
    print("\n" + "-" * 70)
    print(" 🔍 CHARACTER TYPES CHECK:")
    print("-" * 70)
    for char_type, used in results['complexity_checks'].items():
        status = "✅" if used else "❌"
        print(f"   {status} {char_type}")
    
    # Warnings
    if results['warnings']:
        print("\n" + "-" * 70)
        print(" ⚠️  SECURITY WARNINGS:")
        print("-" * 70)
        for warning in results['warnings']:
            print(f"   {warning}")
    else:
        print("\n" + "-" * 70)
        print(" ✅ NO SECURITY WARNINGS DETECTED")
        print("-" * 70)
    
    # Reuse warning
    if results.get('reused', False):
        print("\n" + "!" * 70)
        print(" 🔴 CRITICAL: This password has been used before!")
        print("    Please choose a completely new password.")
        print("!" * 70)


def print_suggestions(suggestions: List[str], analyzer: PasswordStrengthAnalyzer):
    """Display password suggestions"""
    print("\n" + "=" * 70)
    print(" 💡 STRONGER PASSWORD SUGGESTIONS:")
    print("=" * 70)
    
    for i, suggestion in enumerate(suggestions, 1):
        # Preview strength of suggestion
        temp_results = analyzer.evaluate(suggestion)
        strength_indicator = ""
        if temp_results['strength'] == "VERY STRONG":
            strength_indicator = "🟢"
        elif temp_results['strength'] == "STRONG":
            strength_indicator = "🔵"
        elif temp_results['strength'] == "MODERATE":
            strength_indicator = "🟡"
        else:
            strength_indicator = "🔴"
        
        print(f"\n {i}. {strength_indicator} {suggestion}")
        print(f"    → Score: {temp_results['score']}/100 | {temp_results['strength']}")


def main():
    """Main program loop"""
    analyzer = PasswordStrengthAnalyzer()
    
    while True:
        clear_screen()
        print_banner()
        
        print("\n" + "=" * 70)
        print(" 📋 INSTRUCTIONS:")
        print("=" * 70)
        print(" • Enter a password to analyze its strength")
        print(" • Password will be checked for length, complexity, and patterns")
        print(" • SHA-256 hashing prevents password reuse")
        print(" • Type 'quit' to exit")
        print(" • Type 'history' to see stats")
        print("=" * 70)
        
        password = input("\n🔑 Enter password to analyze: ").strip()
        
        if password.lower() == 'quit':
            print("\n👋 Thank you for using Password Strength Analyzer!")
            print("   Stay secure! - Nkul Suthar\n")
            break
        
        if password.lower() == 'history':
            try:
                with open(analyzer.history_file, 'r') as f:
                    lines = f.readlines()
                    print(f"\n📊 Password History Stats:")
                    print(f"   Total passwords saved: {len(lines)}")
                    print(f"   History file: {analyzer.history_file}")
            except:
                print("\n📊 No password history found yet.")
            input("\nPress Enter to continue...")
            continue
        
        if not password:
            print("\n⚠ Please enter a valid password!")
            input("\nPress Enter to continue...")
            continue
        
        # Analyze password
        print("\n🔍 Analyzing password...")
        results = analyzer.evaluate(password)
        
        # Display results
        print_results(results)
        
        # Suggest stronger alternatives for weak passwords
        if results['score'] < 60:
            print_suggestions(analyzer.suggest_stronger(password), analyzer)
            
            # Ask if user wants to use a suggestion
            print("\n" + "-" * 70)
            choice = input("❓ Would you like to try a suggested password? (y/n): ").strip().lower()
            if choice == 'y':
                suggestions = analyzer.suggest_stronger(password)
                if suggestions:
                    print("\n📋 Select a suggestion to analyze:")
                    for i, sug in enumerate(suggestions[:3], 1):
                        print(f"   {i}. {sug}")
                    
                    try:
                        sug_choice = int(input("\nEnter choice (1-3): ").strip())
                        if 1 <= sug_choice <= len(suggestions[:3]):
                            print("\n🔍 Analyzing suggestion...")
                            new_results = analyzer.evaluate(suggestions[sug_choice - 1])
                            print_results(new_results)
                    except:
                        pass
        
        # Offer to save strong password
        if results['score'] >= 60 and not results.get('reused', False):
            print("\n" + "-" * 70)
            save = input("💾 Save this password to history? (y/n): ").strip().lower()
            if save == 'y':
                if analyzer.save_password_hash(password):
                    print("✅ Password hash saved successfully!")
                    print("   (Only SHA-256 hash stored, not plaintext)")
                else:
                    print("❌ Failed to save password")
        
        input("\n📌 Press Enter to analyze another password...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Stay Secure! - Nkul Suthar\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        print("Please restart the program.\n")
        sys.exit(1)
