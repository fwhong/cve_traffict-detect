#!/usr/bin/env python3
"""
Improved CVE Detection Script
Detects CVE vulnerabilities in HTTP traffic using Nuclei YAML rules.
Reads directly from test_payload.json and decodes payloads.
All CVE IDs are normalized to CVE-YYYY-NNNNN format.
"""

import os
import re
import json
import csv
import yaml
import base64
import zlib
from pathlib import Path
from collections import defaultdict
import sys


class ImprovedCVEDetector:
    def __init__(self, rules_dir):
        """Initialize CVE detector with rules directory."""
        self.rules_dir = Path(rules_dir)
        self.cve_patterns = defaultdict(list)
        self.load_rules()
    
    def normalize_cve_id(self, cve_id):
        """
        Normalize CVE ID to standard format: CVE-YYYY-NNNNN
        Removes any additional suffixes like hashes or extra identifiers.
        Examples:
        - CVE-2025-47468-703D36B388F921919447A461B9E7A11B -> CVE-2025-47468
        - CVE-2017-17562-61.yaml -> CVE-2017-17562
        - cve-2019-6340 -> CVE-2019-6340
        """
        if not cve_id:
            return None
        
        # Extract standard CVE format: CVE-YYYY-NNNNN
        # Use word boundary or non-digit to prevent matching extra digits
        match = re.search(r'CVE-(\d{4})-(\d+)(?:\D|$)', cve_id, re.IGNORECASE)
        if match:
            return f"CVE-{match.group(1)}-{match.group(2)}"
        
        return None
    
    def extract_cve_id(self, filename, yaml_data):
        """Extract and normalize CVE ID from filename or YAML data."""
        # Try to get from YAML data first
        if yaml_data and 'id' in yaml_data:
            cve_id = yaml_data['id']
            if cve_id and 'CVE' in cve_id.upper():
                normalized = self.normalize_cve_id(cve_id)
                if normalized:
                    return normalized
        
        # Extract from filename
        normalized = self.normalize_cve_id(filename)
        if normalized:
            return normalized
        
        return None
    
    def normalize_path(self, path):
        """Normalize URL path by removing placeholders, keeps query parameters."""
        if not path:
            return ''
        
        # Remove placeholders but keep query parameters
        path = path.replace('{{BaseURL}}', '')
        path = path.replace('{{Hostname}}', '')
        path = path.replace('{{Host}}', '')
        path = path.strip().strip('/')
        
        # Keep full URL including query parameters
        return path.lower()
    
    def extract_param_names(self, query_string):
        """Fast parameter name extraction (replaces regex for performance)."""
        if not query_string or '=' not in query_string:
            return set()
        
        params = set()
        for pair in query_string.split('&'):
            if '=' in pair:
                param_name = pair.split('=', 1)[0]
                if param_name:  # Skip empty parameter names
                    params.add(param_name)
        return params
    
    def extract_http_request_line(self, payload):
        """Extract HTTP request line from payload."""
        if not payload:
            return None, None, None
        
        lines = payload.split('\n')
        if not lines:
            return None, None, None
        
        first_line = lines[0].strip()
        match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', first_line, re.IGNORECASE)
        if match:
            return match.group(1).upper(), match.group(2), first_line
        
        return None, None, first_line
    
    def load_rules(self):
        """Load all YAML rules from the rules directory."""
        print("Loading CVE detection rules...")
        yaml_files = list(self.rules_dir.glob('**/*.yaml')) + list(self.rules_dir.glob('**/*.yml'))
        print(f"Found {len(yaml_files)} YAML files...")
        
        loaded_count = 0
        skipped_no_cve = 0
        skipped_no_requests = 0
        
        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    
                if not data:
                    continue
                
                cve_id = self.extract_cve_id(yaml_file.name, data)
                if not cve_id:
                    skipped_no_cve += 1
                    continue
                
                # Extract patterns from both 'requests' and 'http' fields
                request_list = data.get('requests') or data.get('http')
                
                if request_list:
                    for request in request_list:
                        if not isinstance(request, dict):
                            continue
                        
                        pattern = {
                            'cve_id': cve_id,
                            'paths': [],
                            'method': request.get('method', 'GET').upper()
                        }
                        
                        # Extract from 'path' field
                        if 'path' in request:
                            paths = request['path'] if isinstance(request['path'], list) else [request['path']]
                            for path in paths:
                                normalized = self.normalize_path(path)
                                if normalized:
                                    pattern['paths'].append(normalized)
                        
                        # Extract from 'raw' field
                        if 'raw' in request:
                            raw_reqs = request['raw'] if isinstance(request['raw'], list) else [request['raw']]
                            for raw_req in raw_reqs:
                                if isinstance(raw_req, str):
                                    lines = raw_req.strip().split('\n')
                                    if lines:
                                        match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', lines[0].strip(), re.IGNORECASE)
                                        if match:
                                            path = match.group(2)
                                            normalized = self.normalize_path(path)
                                            if normalized:
                                                pattern['paths'].append(normalized)
                        
                        if pattern['paths']:
                            self.cve_patterns[cve_id].append(pattern)
                            loaded_count += 1
                else:
                    skipped_no_requests += 1
                
            except:
                continue
        
        print(f"Loaded {loaded_count} CVE patterns from {len(self.cve_patterns)} unique CVEs")
    
    def match_url_fuzzy(self, request_path, pattern_path):
        """Fuzzy match full URLs (including query params) with confidence scoring."""
        if not request_path or not pattern_path:
            return 0
        
        req_lower = request_path.lower().strip('/')
        pat_lower = pattern_path.lower().strip('/')
        
        if len(pat_lower) < 4:
            return 100 if pat_lower == req_lower else 0
        
        # Exact match (highest score)
        if pat_lower == req_lower:
            return 100
        
        # Substring match - pattern is substring of request
        if pat_lower in req_lower:
            return int(90 * len(pat_lower) / len(req_lower))
        
        # Split into path and query for more nuanced matching
        req_parts = req_lower.split('?', 1)
        pat_parts = pat_lower.split('?', 1)
        
        req_path_part = req_parts[0]
        pat_path_part = pat_parts[0]
        req_query = req_parts[1] if len(req_parts) > 1 else ''
        pat_query = pat_parts[1] if len(pat_parts) > 1 else ''
        
        # Path segment matching
        req_segs = [s for s in req_path_part.split('/') if s]
        pat_segs = [s for s in pat_path_part.split('/') if s]
        
        if not pat_segs:
            return 0
        
        path_matched = 0
        for i, pat_seg in enumerate(pat_segs):
            if i < len(req_segs):
                if pat_seg == req_segs[i]:
                    path_matched += 1
                elif len(pat_seg) > 4 and (pat_seg in req_segs[i] or req_segs[i] in pat_seg):
                    path_matched += 0.7
        
        path_score = int((path_matched / len(pat_segs)) * 70) if path_matched > 0 else 0
        
        # Query parameter matching - strict matching required
        query_score = 0
        if pat_query and req_query:
            # Exact query match (best case)
            if pat_query == req_query:
                query_score = 30
            else:
                # Extract parameter names and check overlap (optimized)
                pat_params = self.extract_param_names(pat_query)
                req_params = self.extract_param_names(req_query)
                
                if pat_params and req_params:
                    # All pattern params must be present in request
                    if pat_params.issubset(req_params):
                        param_overlap = len(pat_params & req_params) / len(pat_params)
                        query_score = int(param_overlap * 20)  # Reduced from 30
                    else:
                        # Missing required parameters - significant penalty
                        query_score = -30
        elif not pat_query and not req_query:
            # Both have no query params - perfect match
            query_score = 30
        elif pat_query and not req_query:
            # Pattern has query but request doesn't - reject
            query_score = -40
        elif not pat_query and req_query:
            # Pattern has no query but request does - minor penalty
            query_score = -10
        
        total_score = max(0, path_score + query_score)
        return total_score
    
    def match_payload(self, payload):
        """Match payload against CVE patterns, return top 3 matches."""
        if not payload:
            return []
        
        method, path, _ = self.extract_http_request_line(payload)
        if not method or not path:
            return []
        
        cve_scores = {}
        
        for cve_id, patterns in self.cve_patterns.items():
            max_conf = 0
            for pattern in patterns:
                if pattern['method'] and pattern['method'] != method:
                    continue
                
                for pat_path in pattern['paths']:
                    conf = self.match_url_fuzzy(path, pat_path)
                    max_conf = max(max_conf, conf)
                
                if max_conf >= 70:
                    break
            
            if max_conf >= 70:
                cve_scores[cve_id] = max_conf
        
        sorted_cves = sorted(cve_scores.items(), key=lambda x: x[1], reverse=True)
        return [cve for cve, _ in sorted_cves[:3]]
    
    def decode_payload(self, encoded_payload):
        """Decode base64 and zlib compressed payload."""
        try:
            payload_bytes = base64.b64decode(encoded_payload)
            decompressed = zlib.decompress(payload_bytes)
            return decompressed.decode('utf-8', errors='replace')
        except:
            return None
    
    def process_json_file(self, input_file, output_file, batch_size=1000):
        """Process JSON file and output CVE detections."""
        print(f"Processing {input_file}...")
        print(f"Output: {output_file}")
        print("-" * 60)
        
        processed = 0
        detected = 0
        
        with open(input_file, 'r', encoding='utf-8') as f_in:
            with open(output_file, 'w', newline='', encoding='utf-8') as f_out:
                writer = csv.writer(f_out)
                writer.writerow(['id', 'cve_labels'])
                
                batch = []
                for line in f_in:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        batch.append(data)
                    except:
                        continue
                    
                    if len(batch) >= batch_size:
                        for record in batch:
                            rec_id = record.get('id', '')
                            payload = self.decode_payload(record.get('payload', ''))
                            
                            if payload:
                                cves = self.match_payload(payload)
                                cve_labels = ' '.join(sorted(cves)) if cves else ''
                            else:
                                cve_labels = ''
                            
                            writer.writerow([rec_id, cve_labels])
                            processed += 1
                            if cve_labels:
                                detected += 1
                        
                        batch = []
                        print(f"Processed {processed:,} records, detected {detected:,} CVEs...")
                        if processed % 10000 == 0:
                            print(f"Processed {processed:,} records, detected {detected:,} CVEs...")
                
                # Process remaining
                for record in batch:
                    rec_id = record.get('id', '')
                    payload = self.decode_payload(record.get('payload', ''))
                    
                    if payload:
                        cves = self.match_payload(payload)
                        cve_labels = ' '.join(sorted(cves)) if cves else ''
                    else:
                        cve_labels = ''
                    
                    writer.writerow([rec_id, cve_labels])
                    processed += 1
                    if cve_labels:
                        detected += 1
        
        print(f"\nComplete!")
        print(f"Total: {processed:,} records")
        print(f"Detected: {detected:,} CVEs ({detected/processed*100:.2f}%)")
        print(f"Saved to: {output_file}")


def main():
    rules_dir = '../datacon25/cve'
    input_file = 'data/test_payload.json'
    output_file = 'test_label.csv'
    
    
    if not os.path.exists(rules_dir):
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    
    detector = ImprovedCVEDetector(rules_dir)
    detector.process_json_file(input_file, output_file, batch_size=1000)


if __name__ == '__main__':
    main()
