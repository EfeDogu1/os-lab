import os
import sys
import re

DANGEROUS_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexecuteScript\s*\('),
    re.compile(r'innerHTML\s*='),
    re.compile(r'document\.write\s*\(')
]

def scan_directory(target_dir):
    findings = []
    print(f"[*] Scanning directory: {target_dir}")
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if file.endswith(('.js', '.ts', '.html', '.json')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            for pattern in DANGEROUS_PATTERNS:
                                if pattern.search(line):
                                    findings.append({
                                        'file': file_path,
                                        'line': line_num,
                                        'content': line.strip()
                                    })
                except Exception as e:
                    print(f"[!] Error reading {file_path}: {e}")
    return findings

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_directory(target)
    print("\n[+] Scan Results:")
    for res in results:
        print(f"  [!] Found in {res['file']} (Line {res['line']}): {res['content']}")
