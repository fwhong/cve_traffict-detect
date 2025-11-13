#!/usr/bin/env python3
"""
Local CVE Verification Script (Rule-based, No LLM)
Strictly verifies CVE detections using rule-based pattern matching.
Removes false positives by checking critical features from POC files.
"""

import os
import json
import csv
import base64
import zlib
import yaml
import re
from glob import glob
from collections import defaultdict


class LocalCVEVerifier:
    """Local rule-based CVE verifier."""
    
    def __init__(self, poc_dir):
        self.poc_dir = poc_dir
        self.poc_cache = {}
        
        # False positive indicators (blacklist)
        self.fp_patterns = {
            'version_check_only': [
                r'/version\b', r'/api/version', r'/v\d+/info',
                r'/info\b', r'/health\b', r'/status\b', r'/ping\b'
            ],
            'generic_login': [
                r'^POST /login$', r'^POST /auth$', r'^POST /signin$',
                r'^GET /login$', r'^GET /auth$'
            ],
            'simple_directory_scan': [
                r'^GET /$', r'^GET /admin$', r'^GET /api$',
                r'^GET /uploads$', r'^GET /backup$', r'^GET /tmp$'
            ],
            'generic_file_access': [
                r'^GET /robots\.txt$', r'^GET /sitemap\.xml$',
                r'^GET /favicon\.ico$', r'^GET /\.well-known'
            ]
        }
        
    def decode_payload(self, encoded_payload):
        """Decode base64 and zlib compressed payload."""
        try:
            payload_bytes = base64.b64decode(encoded_payload)
            decompressed = zlib.decompress(payload_bytes)
            return decompressed.decode('utf-8', errors='replace')
        except Exception as e:
            return None
    
    def load_payload_by_id(self, payload_file, target_id):
        """Load specific payload by ID from JSON file."""
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if str(data.get('id', '')) == str(target_id):
                            return self.decode_payload(data.get('payload', ''))
                    except:
                        continue
        except Exception as e:
            print(f"    [ERROR] Load payload failed: {e}")
        return None
    
    def find_poc_file(self, cve_id):
        """Find POC file for given CVE."""
        try:
            pattern = f"*{cve_id}*.yaml"
            files = glob(os.path.join(self.poc_dir, pattern))
            
            if files:
                sorted_files = sorted(files)
                for f in sorted_files:
                    basename = os.path.basename(f)
                    if basename.endswith(f"{cve_id}.yaml"):
                        return f
                return sorted_files[0]
        except Exception as e:
            print(f"    [ERROR] Finding POC failed: {e}")
        return None
    
    def load_poc_yaml(self, poc_file):
        """Load and cache POC YAML file."""
        if poc_file in self.poc_cache:
            return self.poc_cache[poc_file]
        
        try:
            with open(poc_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
                self.poc_cache[poc_file] = data
                return data
        except Exception as e:
            print(f"    [ERROR] Load POC YAML failed: {e}")
            return None
    
    def extract_critical_features(self, poc_yaml):
        """Extract critical features from POC YAML."""
        features = {
            'required_paths': set(),
            'required_params': set(),
            'danger_keywords': set(),
            'http_methods': set(),
            'path_patterns': []
        }
        
        if not poc_yaml:
            return features
        
        # Extract from 'requests' or 'http' field
        request_list = poc_yaml.get('requests') or poc_yaml.get('http')
        if not request_list:
            return features
        
        for request in request_list:
            if not isinstance(request, dict):
                continue
            
            # Extract HTTP method
            method = request.get('method', 'GET').upper()
            features['http_methods'].add(method)
            
            # Extract from 'path' field
            if 'path' in request:
                paths = request['path'] if isinstance(request['path'], list) else [request['path']]
                for path in paths:
                    cleaned_path = self._clean_path(path)
                    if cleaned_path:
                        features['required_paths'].add(cleaned_path)
                        # Extract path segments
                        segments = [s for s in cleaned_path.split('/') if s and len(s) > 2]
                        features['path_patterns'].extend(segments)
                        # Extract parameters
                        if '?' in cleaned_path:
                            params = self._extract_params(cleaned_path.split('?', 1)[1])
                            features['required_params'].update(params)
            
            # Extract from 'raw' field
            if 'raw' in request:
                raw_reqs = request['raw'] if isinstance(request['raw'], list) else [request['raw']]
                for raw_req in raw_reqs:
                    if isinstance(raw_req, str):
                        lines = raw_req.strip().split('\n')
                        if lines:
                            # Extract from first line (request line)
                            match = re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s+(\S+)', lines[0].strip(), re.IGNORECASE)
                            if match:
                                path = match.group(2)
                                cleaned_path = self._clean_path(path)
                                if cleaned_path:
                                    features['required_paths'].add(cleaned_path)
                                    if '?' in cleaned_path:
                                        params = self._extract_params(cleaned_path.split('?', 1)[1])
                                        features['required_params'].update(params)
                        
                        # Extract danger keywords from raw content
                        danger_keywords = self._extract_danger_keywords(raw_req)
                        features['danger_keywords'].update(danger_keywords)
        
        return features
    
    def _clean_path(self, path):
        """Clean and normalize path."""
        if not path:
            return ''
        # Remove placeholders
        path = re.sub(r'\{\{[^}]+\}\}', '', path)
        path = path.strip().strip('/')
        return path.lower()
    
    def _extract_params(self, query_string):
        """Extract parameter names from query string."""
        params = set()
        if not query_string:
            return params
        
        for pair in query_string.split('&'):
            if '=' in pair:
                param_name = pair.split('=', 1)[0]
                if param_name:
                    params.add(param_name.lower())
        return params
    
    def _extract_danger_keywords(self, text):
        """Extract danger keywords indicating exploitation."""
        danger_patterns = [
            r'\$\{jndi:', r'\$\{', r'eval\s*\(',
            r'exec\s*\(', r'system\s*\(', r'passthru\s*\(',
            r'base64_decode', r'<\?php', r'<%',
            r'\.\./\.\./', r'\.\.\\\.\.\\',
            r'cmd=', r'command=', r'exec=',
            r'/etc/passwd', r'/bin/bash', r'/bin/sh',
            r'%00', r'0x', r'\x00',
            # Additional patterns
            r'shell_exec', r'popen', r'proc_open',
            r'\$_GET', r'\$_POST', r'\$_REQUEST',
            r'<script', r'javascript:', r'onerror=',
            r'union.*select', r'1=1', r'or.*1=1'
        ]
        
        keywords = set()
        text_lower = text.lower()
        for pattern in danger_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                keywords.add(pattern)
        
        return keywords
    
    def _extract_payload_patterns(self, poc_yaml):
        """Extract payload patterns from POC raw requests."""
        payload_patterns = set()
        
        if not poc_yaml:
            return payload_patterns
        
        request_list = poc_yaml.get('requests') or poc_yaml.get('http')
        if not request_list:
            return payload_patterns
        
        for request in request_list:
            if not isinstance(request, dict):
                continue
            
            # Extract from 'raw' field (contains full HTTP request with body)
            if 'raw' in request:
                raw_reqs = request['raw'] if isinstance(request['raw'], list) else [request['raw']]
                for raw_req in raw_reqs:
                    if isinstance(raw_req, str):
                        lines = raw_req.strip().split('\n')
                        # Body starts after empty line
                        body_started = False
                        for line in lines:
                            if not body_started and line.strip() == '':
                                body_started = True
                                continue
                            if body_started and line.strip():
                                # Extract meaningful payload patterns
                                patterns = self._extract_meaningful_patterns(line)
                                payload_patterns.update(patterns)
            
            # Extract from 'body' field if exists
            if 'body' in request:
                body = request['body']
                if isinstance(body, str):
                    patterns = self._extract_meaningful_patterns(body)
                    payload_patterns.update(patterns)
        
        return payload_patterns
    
    def _extract_meaningful_patterns(self, text):
        """Extract meaningful patterns from payload text."""
        patterns = set()
        
        if not text or len(text) < 3:
            return patterns
        
        # Extract specific exploit strings (longer than 5 chars)
        tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{4,}', text)
        patterns.update(tokens[:10])  # Limit to first 10 tokens
        
        # Extract specific symbols/operators
        if '${' in text:
            patterns.add('${')
        if '../' in text:
            patterns.add('../')
        if 'eval(' in text.lower():
            patterns.add('eval')
        if 'exec(' in text.lower():
            patterns.add('exec')
        
        return patterns
    
    def parse_http_request(self, traffic):
        """Parse HTTP request from traffic, including body/payload."""
        if not traffic:
            return None
        
        lines = traffic.split('\n')
        if not lines:
            return None
        
        first_line = lines[0].strip()
        match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', first_line, re.IGNORECASE)
        
        if not match:
            return None
        
        # Extract HTTP body (payload)
        body = ""
        body_started = False
        for i, line in enumerate(lines):
            # Body starts after empty line
            if not body_started and line.strip() == '':
                body_started = True
                continue
            if body_started:
                body += line + '\n'
        
        return {
            'method': match.group(1).upper(),
            'path': match.group(2),
            'full_content': traffic.lower(),
            'body': body.strip(),
            'headers': '\n'.join(lines[1:]).lower() if len(lines) > 1 else ''
        }
    
    def verify_cve_match(self, traffic, cve_id, poc_features):
        """
        Verify if traffic truly matches CVE using strict rules.
        Returns (is_valid, confidence, reason)
        """
        request = self.parse_http_request(traffic)
        if not request:
            return False, 0, "Cannot parse HTTP request"
        
        method = request['method']
        path = request['path']
        content = request['full_content']
        
        # Check false positive patterns first
        if self._is_false_positive(method, path, content):
            return False, 0, "Matches false positive pattern"
        
        # Multi-dimensional verification
        score = 0
        reasons = []
        
        # 1. HTTP Method verification (不强制，但加分)
        if poc_features['http_methods']:
            if method in poc_features['http_methods']:
                score += 15
                reasons.append(f"Method match: {method}")
            else:
                score -= 5
                reasons.append(f"Method mismatch: {method} not in {poc_features['http_methods']}")
        
        # 2. Path verification (降低要求)
        path_score, path_reason = self._verify_path(path, poc_features)
        score += path_score
        if path_reason:
            reasons.append(path_reason)
        
        if path_score < 15:  # Path must have at least 15 points (降低from 20)
            return False, score, "Path match too weak: " + path_reason
        
        # 3. Parameter verification
        param_score, param_reason = self._verify_params(path, poc_features)
        score += param_score
        if param_reason:
            reasons.append(param_reason)
        
        # 4. Danger keywords verification
        danger_score, danger_reason = self._verify_danger_keywords(content, poc_features)
        score += danger_score
        if danger_reason:
            reasons.append(danger_reason)
        
        # 5. Payload verification (new)
        if request.get('body'):
            payload_score, payload_reason = self._verify_payload(request['body'], cve_id, poc_features)
            score += payload_score
            if payload_reason:
                reasons.append(payload_reason)
        
        # 6. Path length check (避免太短的通用路径，但不要太严格)
        if len(path.strip('/')) < 5:
            score -= 15
            reasons.append("Path too short (generic scan)")
        
        # Final judgment
        is_valid = score >= 40  # Need at least 40 points
        
        reason_text = " | ".join(reasons) if reasons else "No match"
        return is_valid, score, reason_text
    
    def _is_false_positive(self, method, path, content):
        """Check if matches false positive patterns."""
        request_line = f"{method} {path}"
        
        for category, patterns in self.fp_patterns.items():
            for pattern in patterns:
                if re.search(pattern, request_line, re.IGNORECASE):
                    return True
        
        # Too short path is usually generic scan (降低from 4 to 3)
        if len(path.strip('/')) < 3:
            return True
        
        return False
    
    def _verify_path(self, request_path, poc_features):
        """Verify path matching."""
        request_path_clean = self._clean_path(request_path)
        
        if not request_path_clean:
            return 0, "Empty path"
        
        # Exact match (best)
        for poc_path in poc_features['required_paths']:
            if poc_path == request_path_clean:
                return 40, f"Exact path match: {poc_path}"
        
        # Path segments match
        request_segments = set(s for s in request_path_clean.split('/') if s and len(s) > 2)
        poc_segments = set(poc_features['path_patterns'])
        
        if poc_segments:
            match_count = len(request_segments & poc_segments)
            match_rate = match_count / len(poc_segments)
            
            if match_rate >= 0.8:
                return 35, f"High path segment match: {match_rate:.1%}"
            elif match_rate >= 0.5:
                return 25, f"Medium path segment match: {match_rate:.1%}"
            elif match_rate >= 0.3:
                return 15, f"Low path segment match: {match_rate:.1%}"
        
        # Substring match
        for poc_path in poc_features['required_paths']:
            if len(poc_path) >= 5:
                if poc_path in request_path_clean:
                    return 25, f"POC path in request: {poc_path}"
                elif request_path_clean in poc_path:
                    return 20, f"Request path in POC: {poc_path}"
        
        # Partial segment match (更宽松的匹配)
        if poc_segments:
            for poc_seg in poc_segments:
                if len(poc_seg) > 4:  # 只对较长的段进行匹配
                    for req_seg in request_segments:
                        if poc_seg in req_seg or req_seg in poc_seg:
                            return 15, f"Partial segment match: {poc_seg}"
        
        return 0, "No path match"
    
    def _verify_params(self, request_path, poc_features):
        """Verify parameter matching."""
        if '?' not in request_path:
            if not poc_features['required_params']:
                return 10, "No params needed"
            else:
                return 0, "Missing required parameters"
        
        query_string = request_path.split('?', 1)[1]
        request_params = self._extract_params(query_string)
        
        if not poc_features['required_params']:
            return 5, "Params present but not required"
        
        match_count = len(request_params & poc_features['required_params'])
        required_count = len(poc_features['required_params'])
        
        if match_count == required_count:
            return 30, f"All params match ({match_count}/{required_count})"
        elif match_count >= required_count * 0.8:
            return 20, f"Most params match ({match_count}/{required_count})"
        elif match_count >= required_count * 0.5:
            return 10, f"Some params match ({match_count}/{required_count})"
        else:
            return 0, f"Insufficient param match ({match_count}/{required_count})"
    
    def _verify_danger_keywords(self, content, poc_features):
        """Verify danger keywords presence."""
        if not poc_features['danger_keywords']:
            return 0, None
        
        found_keywords = []
        for keyword in poc_features['danger_keywords']:
            if re.search(keyword, content, re.IGNORECASE):
                found_keywords.append(keyword)
        
        if found_keywords:
            return 20, f"Danger keywords found: {len(found_keywords)}"
        
        return 0, None
    
    def _verify_payload(self, request_body, cve_id, poc_features):
        """Verify payload/body content matches POC patterns."""
        if not request_body or len(request_body) < 3:
            return 0, None
        
        score = 0
        
        # Check if body contains danger keywords
        body_lower = request_body.lower()
        danger_in_body = 0
        
        common_exploits = [
            '../', '${', 'eval(', 'exec(', 'system(',
            '/etc/passwd', 'union select', '<script',
            'base64_decode', '<?php', 'shell_exec'
        ]
        
        for exploit in common_exploits:
            if exploit in body_lower:
                danger_in_body += 1
        
        if danger_in_body > 0:
            score = min(25, danger_in_body * 8)  # Max 25 points
            return score, f"Exploit patterns in payload: {danger_in_body}"
        
        # Check for substantial POST data (likely an exploit attempt)
        if len(request_body) > 50:
            # Has meaningful payload content
            return 5, "Substantial payload present"
        
        return 0, None
    
    def process_csv(self, input_csv, payload_json, output_csv, max_rows=136521):
        """Process CSV and verify CVE labels."""
        print(f"Local CVE Verification (Rule-based)")
        print(f"Input: {input_csv}")
        print(f"Output: {output_csv}")
        print(f"Processing first {max_rows} rows")
        print("-" * 60)
        
        processed = 0
        checked = 0
        removed_fp = 0
        kept_valid = 0
        no_cve = 0
        
        with open(input_csv, 'r', encoding='utf-8') as f_in, \
             open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
            
            reader = csv.reader(f_in)
            writer = csv.writer(f_out)
            
            # Write header
            header = next(reader)
            writer.writerow(header)
            
            for row in reader:
                if processed >= max_rows:
                    break
                
                if len(row) < 2:
                    writer.writerow(row)
                    continue
                
                record_id, cve_labels = row[0], row[1]
                processed += 1
                
                # Check if has CVE label
                cves = [c.strip() for c in cve_labels.split() if c.strip()]
                
                if not cves:
                    writer.writerow(row)
                    no_cve += 1
                    continue
                
                # Has CVE label - need to verify
                print(f"\n[{processed}] ID: {record_id}, CVE: {cve_labels}")
                checked += 1
                
                # Load traffic
                traffic = self.load_payload_by_id(payload_json, record_id)
                if not traffic:
                    print(f"    [SKIP] Cannot load traffic, removing label")
                    writer.writerow([record_id, ""])
                    removed_fp += 1
                    continue
                
                print(f"    Traffic: {len(traffic)} bytes")
                
                # Verify first CVE (or could verify all)
                cve_to_check = cves[0]
                
                # Load POC
                poc_file = self.find_poc_file(cve_to_check)
                if not poc_file:
                    print(f"    [SKIP] No POC found, removing label")
                    writer.writerow([record_id, ""])
                    removed_fp += 1
                    continue
                
                poc_yaml = self.load_poc_yaml(poc_file)
                if not poc_yaml:
                    print(f"    [SKIP] Cannot load POC, removing label")
                    writer.writerow([record_id, ""])
                    removed_fp += 1
                    continue
                
                print(f"    POC: {os.path.basename(poc_file)}")
                
                # Extract critical features
                features = self.extract_critical_features(poc_yaml)
                
                # Extract payload patterns
                payload_patterns = self._extract_payload_patterns(poc_yaml)
                features['payload_patterns'] = payload_patterns
                
                print(f"    Features: {len(features['required_paths'])} paths, "
                      f"{len(features['required_params'])} params, "
                      f"{len(features['danger_keywords'])} keywords, "
                      f"{len(payload_patterns)} payload patterns")
                
                # Verify
                is_valid, score, reason = self.verify_cve_match(traffic, cve_to_check, features)
                
                if is_valid:
                    print(f"    ✓ VALID (score={score}): {reason}")
                    writer.writerow(row)
                    kept_valid += 1
                else:
                    print(f"    ✗ FALSE POSITIVE (score={score}): {reason}")
                    writer.writerow([record_id, ""])
                    removed_fp += 1
                
                # Progress
                if processed % 10 == 0:
                    print(f"\n{'='*60}")
                    print(f"Progress: {processed}/{max_rows}")
                    print(f"Checked: {checked}, Removed: {removed_fp}, Kept: {kept_valid}")
                    print(f"{'='*60}")
        
        print(f"\n{'='*60}")
        print(f"Complete!")
        print(f"Total: {processed}")
        print(f"No CVE: {no_cve}")
        print(f"Checked: {checked}")
        print(f"Removed false positives: {removed_fp}")
        print(f"Kept valid: {kept_valid}")
        if checked > 0:
            print(f"FP removal rate: {removed_fp}/{checked} = {removed_fp/checked*100:.1f}%")
        print(f"Output: {output_csv}")
        print(f"{'='*60}")


def main():
    TEST_LABEL_CSV = "test_label_ml_enhanced.csv"
    TEST_PAYLOAD_JSON = "../datacon25/test_payload.json"
    POC_DIR = "../datacon25/cve"
    OUTPUT_CSV = "test_label_local_verified.csv"
    MAX_ROWS = 136521
    
    # Check files
    if not os.path.exists(TEST_LABEL_CSV):
        print(f"Error: {TEST_LABEL_CSV} not found!")
        return
    
    if not os.path.exists(TEST_PAYLOAD_JSON):
        print(f"Error: {TEST_PAYLOAD_JSON} not found!")
        return
    
    if not os.path.exists(POC_DIR):
        print(f"Error: {POC_DIR} not found!")
        return
    
    print(f"Files check passed:")
    print(f"  ✓ {TEST_LABEL_CSV}")
    print(f"  ✓ {TEST_PAYLOAD_JSON}")
    print(f"  ✓ {POC_DIR}")
    print()
    
    # Process
    verifier = LocalCVEVerifier(POC_DIR)
    verifier.process_csv(TEST_LABEL_CSV, TEST_PAYLOAD_JSON, OUTPUT_CSV, MAX_ROWS)


if __name__ == "__main__":
    main()
