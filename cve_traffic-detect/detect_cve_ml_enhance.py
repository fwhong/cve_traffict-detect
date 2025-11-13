#!/usr/bin/env python3
"""
ML-Enhanced CVE Detection Script
Uses FastText-based machine learning to refine CVE detections from detect_cve_final.py
Trains on POC rules and enhances detection confidence before false positive filtering.


"""

import os
import re
import json
import csv
import yaml
import base64
import zlib
import hashlib
import tempfile
from pathlib import Path
from collections import defaultdict, Counter
import sys
import math


class CVEFeatureExtractor:
    """Extract rich features from HTTP payloads for ML training."""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'\.\./', r'%2e%2e', r'%00', r'<script', r'javascript:', 
            r'onerror=', r'eval\(', r'exec\(', r'union\s+select',
            r'<\?php', r'${', r'{{', r'cmd=', r'exec=', r'/etc/passwd',
            r'../../', r'file://', r'data:', r'base64,', r'alert\(',
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns]
    
    def extract_http_components(self, payload):
        """Extract structured HTTP components."""
        if not payload:
            return None, None, None, None, {}
        
        lines = payload.split('\n')
        if not lines:
            return None, None, None, None, {}
        
        first_line = lines[0].strip()
        match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/([\d.]+))?', 
                        first_line, re.IGNORECASE)
        
        if not match:
            return None, None, None, None, {}
        
        method = match.group(1).upper()
        full_path = match.group(2)
        http_version = match.group(3) if match.group(3) else '1.1'
        
        if '?' in full_path:
            path, query = full_path.split('?', 1)
        else:
            path, query = full_path, ''
        
        headers = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return method, path, query, http_version, headers
    
    def extract_path_features(self, path):
        if not path:
            return {}
        
        path_clean = path.strip('/')
        segments = [s for s in path_clean.split('/') if s]
        
        features = {
            'path_depth': len(segments),
            'path_length': len(path),
            'has_extension': 1 if (segments and '.' in path_clean.split('/')[-1]) else 0,
            'has_special_chars': 1 if re.search(r'[^a-zA-Z0-9/._-]', path) else 0,
            'num_dots': path.count('.'),
            'num_slashes': path.count('/'),
            'num_dashes': path.count('-'),
            'num_underscores': path.count('_'),
        }
        
        if segments:
            last_seg = segments[-1]
            if '.' in last_seg:
                ext = last_seg.split('.')[-1].lower()
                features['extension'] = ext
            else:
                features['extension'] = 'none'
        else:
            features['extension'] = 'none'
        
        # Path pattern
        features['path_pattern'] = '/'.join(['*' if re.search(r'\d', s) else s for s in segments[:3]])
        
        return features
    
    def extract_query_features(self, query):
        """Extract features from query parameters."""
        if not query:
            return {'num_params': 0, 'has_query': 0}
        
        params = query.split('&')
        param_names = []
        param_values = []
        
        for param in params:
            if '=' in param:
                name, value = param.split('=', 1)
                param_names.append(name)
                param_values.append(value)
        
        features = {
            'num_params': len(params),
            'has_query': 1,
            'query_length': len(query),
            'avg_param_length': len(query) / len(params) if params else 0,
            'max_value_length': max([len(v) for v in param_values]) if param_values else 0,
        }
        
        # Parameter name pattern
        features['param_pattern'] = '_'.join(sorted(param_names[:5]))
        
        return features
    
    def extract_attack_features(self, payload):
        """Extract attack pattern features."""
        if not payload:
            return {}
        
        payload_lower = payload.lower()
        
        features = {
            'payload_length': len(payload),
            'num_suspicious_patterns': sum(1 for p in self.compiled_patterns if p.search(payload)),
            'entropy': self.calculate_entropy(payload[:500]),  # Check first 500 chars
            'has_encoding': 1 if any(x in payload_lower for x in ['%', 'base64', 'urlencode']) else 0,
            'has_traversal': 1 if '../' in payload or '%2e%2e' in payload_lower else 0,
            'has_sql': 1 if any(x in payload_lower for x in ['union', 'select', 'insert', 'update', 'delete']) else 0,
            'has_xss': 1 if any(x in payload_lower for x in ['<script', 'javascript:', 'onerror']) else 0,
            'has_cmd': 1 if any(x in payload_lower for x in ['cmd=', 'exec=', '|', ';']) else 0,
        }
        
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 3)
    
    def extract_all_features(self, payload):
        """Extract all features from payload."""
        method, path, query, http_version, headers = self.extract_http_components(payload)
        
        if not method:
            return None
        
        features = {
            'method': method,
            'http_version': http_version,
        }
        
        path_features = self.extract_path_features(path)
        features.update(path_features)
        
        query_features = self.extract_query_features(query)
        features.update(query_features)
        
        attack_features = self.extract_attack_features(payload)
        features.update(attack_features)
        
        features['num_headers'] = len(headers)
        features['has_user_agent'] = 1 if 'user-agent' in headers else 0
        features['has_referer'] = 1 if 'referer' in headers else 0
        
        return features
    
    def features_to_text(self, features):
        """Convert features to FastText format text."""
        if not features:
            return ''
        
        parts = []
        
        parts.append(f"method_{features.get('method', 'unknown').lower()}")
        parts.append(f"http_{features.get('http_version', '1.1').replace('.', '_')}")
        
        if features.get('extension'):
            parts.append(f"ext_{features['extension']}")
        
        if features.get('path_pattern'):
            parts.append(f"path_{features['path_pattern'].replace('/', '_')}")
        
        if features.get('param_pattern'):
            parts.append(f"params_{features['param_pattern']}")
        
        parts.append(f"depth_{min(features.get('path_depth', 0), 10)}")
        parts.append(f"params_{min(features.get('num_params', 0), 20)}")
        
        if features.get('has_special_chars'):
            parts.append('has_special_chars')
        if features.get('has_encoding'):
            parts.append('has_encoding')
        if features.get('has_traversal'):
            parts.append('path_traversal')
        if features.get('has_sql'):
            parts.append('sql_injection')
        if features.get('has_xss'):
            parts.append('xss_attack')
        if features.get('has_cmd'):
            parts.append('cmd_injection')
        
        entropy = features.get('entropy', 0)
        if entropy > 4.5:
            parts.append('high_entropy')
        elif entropy > 3.5:
            parts.append('medium_entropy')
        else:
            parts.append('low_entropy')
        
        return ' '.join(parts)


class FastTextModelTrainer:
    """Train FastText model on CVE POC rules."""
    
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.feature_extractor = CVEFeatureExtractor()
        self.cve_patterns = defaultdict(list)
        self.cve_categories = {}
    
    def normalize_cve_id(self, cve_id):
        if not cve_id:
            return None
        match = re.search(r'CVE-(\d{4})-(\d+)(?:\D|$)', cve_id, re.IGNORECASE)
        if match:
            return f"CVE-{match.group(1)}-{match.group(2)}"
        return None
    
    def categorize_cve(self, cve_id):
        if not cve_id:
            return 'unknown'
        
        match = re.match(r'CVE-(\d{4})-(\d+)', cve_id)
        if match:
            year = int(match.group(1))
            num = int(match.group(2))
            
            # Category by year
            if year >= 2020:
                year_cat = 'recent'
            elif year >= 2015:
                year_cat = 'medium'
            else:
                year_cat = 'old'
            
            return year_cat
        
        return 'unknown'
    
    def load_cve_rules(self):
        """Load CVE rules and generate training samples."""
        print("Loading CVE POC rules for training...")
        yaml_files = list(self.rules_dir.glob('**/*.yaml')) + list(self.rules_dir.glob('**/*.yml'))
        print(f"Found {len(yaml_files)} YAML files")
        
        training_samples = []
        cve_count = 0
        
        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                
                if not data:
                    continue
                
                # Extract CVE ID
                cve_id = self.normalize_cve_id(yaml_file.name)
                if not cve_id and 'id' in data:
                    cve_id = self.normalize_cve_id(data['id'])
                
                if not cve_id:
                    continue
                
                # Categorize CVE
                category = self.categorize_cve(cve_id)
                self.cve_categories[cve_id] = category
                
                # Extract request patterns
                request_list = data.get('requests') or data.get('http')
                if not request_list:
                    continue
                
                for request in request_list:
                    if not isinstance(request, dict):
                        continue
                    
                    # Generate synthetic payload from POC
                    synthetic_payload = self.generate_synthetic_payload(request)
                    if synthetic_payload:
                        self.cve_patterns[cve_id].append(synthetic_payload)
                        training_samples.append((cve_id, synthetic_payload))
                        cve_count += 1
            
            except Exception as e:
                continue
        
        print(f"Loaded {cve_count} training samples from {len(self.cve_patterns)} unique CVEs")
        return training_samples
    
    def generate_synthetic_payload(self, request):
        """Generate synthetic HTTP payload from POC request."""
        method = request.get('method', 'GET').upper()
        paths = request.get('path', [])
        
        if isinstance(paths, str):
            paths = [paths]
        
        if not paths and 'raw' in request:
            raw_reqs = request['raw'] if isinstance(request['raw'], list) else [request['raw']]
            for raw_req in raw_reqs:
                if isinstance(raw_req, str):
                    lines = raw_req.strip().split('\n')
                    if lines:
                        match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', 
                                       lines[0].strip(), re.IGNORECASE)
                        if match:
                            paths.append(match.group(2))
        
        if not paths:
            return None
        
        path = paths[0]
        
        path = path.replace('{{BaseURL}}', '')
        path = path.replace('{{Hostname}}', '')
        path = path.replace('{{Host}}', '')
        path = path.strip()
        
        payload = f"{method} {path} HTTP/1.1\nHost: target.com\n\n"
        
        return payload
    
    def prepare_training_data(self, output_file):
        """Prepare FastText training data format."""
        training_samples = self.load_cve_rules()
        
        if not training_samples:
            print("Error: No training samples generated!")
            return False
        
        print(f"\nGenerating FastText training data...")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for cve_id, payload in training_samples:
                features = self.feature_extractor.extract_all_features(payload)
                if not features:
                    continue
                
                feature_text = self.feature_extractor.features_to_text(features)
                if not feature_text:
                    continue
                
                category = self.cve_categories.get(cve_id, 'unknown')
                label = f"__label__{category}_cve"
                
                f.write(f"{label} {feature_text}\n")
        
        print(f"Training data saved to: {output_file}")
        return True
    
    def train_fasttext_model(self, training_file, model_file):
        """Train FastText model (uses external fasttext library or fallback)."""
        print("\nTraining FastText model...")
        
        try:
            import fasttext
            
            # Train with optimized parameters for CPU
            model = fasttext.train_supervised(
                input=training_file,
                lr=0.1,  
                dim=100,  
                ws=5,  
                epoch=25,  
                minCount=1,  
                wordNgrams=2,  
                loss='softmax',  
                thread=4,  
                verbose=2
            )
            
            model.save_model(model_file)
            print(f"FastText model saved to: {model_file}")
            
            result = model.test(training_file)
            print(f"Training samples: {result[0]}")
            print(f"Precision: {result[1]:.4f}")
            print(f"Recall: {result[2]:.4f}")
            
            return True
            
        except ImportError:
            print("Warning: fasttext library not installed, using fallback simple classifier")
            print("Install with: pip install fasttext")
            return self.train_fallback_model(training_file, model_file)
    
    def train_fallback_model(self, training_file, model_file):
        """Fallback simple pattern-based classifier."""
        print("Using fallback pattern-based classifier...")
        
        # Build simple pattern database
        pattern_db = defaultdict(list)
        
        with open(training_file, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                
                parts = line.strip().split(' ', 1)
                if len(parts) != 2:
                    continue
                
                label = parts[0].replace('__label__', '')
                features = parts[1]
                
                # Extract key patterns
                for feature in features.split():
                    pattern_db[feature].append(label)
        
        # Save pattern database
        import pickle
        with open(model_file, 'wb') as f:
            pickle.dump(dict(pattern_db), f)
        
        print(f"Fallback model saved to: {model_file}")
        return True


class MLEnhancedDetector:
    """Enhance CVE detections using trained ML model."""
    
    def __init__(self, model_file, use_fasttext=True):
        self.model_file = model_file
        self.feature_extractor = CVEFeatureExtractor()
        self.use_fasttext = use_fasttext
        self.model = None
        self.pattern_db = None
        
        self.load_model()
    
    def load_model(self):
        """Load trained model."""
        if not os.path.exists(self.model_file):
            print(f"Error: Model file not found: {self.model_file}")
            return False
        
        try:
            import fasttext
            self.model = fasttext.load_model(self.model_file)
            self.use_fasttext = True
            print("FastText model loaded successfully")
            return True
        except:
            import pickle
            with open(self.model_file, 'rb') as f:
                self.pattern_db = pickle.load(f)
            self.use_fasttext = False
            print("Fallback model loaded successfully")
            return True
    
    def predict_confidence(self, payload):
        if not payload:
            return 0.0
        
        features = self.feature_extractor.extract_all_features(payload)
        if not features:
            return 0.0
        
        feature_text = self.feature_extractor.features_to_text(features)
        if not feature_text:
            return 0.0
        
        if self.use_fasttext and self.model:
            predictions = self.model.predict(feature_text, k=1)
            if predictions and len(predictions) > 0:
                labels, probabilities = predictions
                if probabilities and len(probabilities) > 0:
                    return float(probabilities[0])
        else:
            if self.pattern_db:
                feature_tokens = feature_text.split()
                match_scores = []
                
                for token in feature_tokens:
                    if token in self.pattern_db:
                        labels = self.pattern_db[token]
                        score = len([l for l in labels if 'cve' in l]) / len(labels)
                        match_scores.append(score)
                
                if match_scores:
                    return sum(match_scores) / len(match_scores)
        
        return 0.0
    
    def decode_payload(self, encoded_payload):
        try:
            payload_bytes = base64.b64decode(encoded_payload)
            decompressed = zlib.decompress(payload_bytes)
            return decompressed.decode('utf-8', errors='replace')
        except:
            return None
    
    def enhance_detections(self, input_csv, payload_json, output_csv, ml_threshold=0.95, cve_only=False):
        """Enhance CVE detections with ML confidence scores."""
        print(f"\nEnhancing CVE detections...")
        print(f"Input: {input_csv}")
        print(f"Payload source: {payload_json}")
        print(f"Output: {output_csv}")
        print("-" * 60)
        
        # Load payload data efficiently (streaming)
        payload_cache = {}
        
        print("Loading payloads (streaming)...")
        with open(payload_json, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    rec_id = data.get('id', '')
                    payload = data.get('payload', '')
                    
                    if rec_id is not None and payload:
                        # Convert ID to string for consistent matching
                        payload_cache[str(rec_id)] = payload
                    
                    if line_num % 10000 == 0:
                        print(f"Loaded {line_num:,} payloads...")
                
                except:
                    continue
        
        print(f"Loaded {len(payload_cache):,} payloads\n")
        
        processed = 0
        enhanced = 0
        removed = 0
        
        with open(input_csv, 'r', encoding='utf-8') as f_in:
            with open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
                reader = csv.DictReader(f_in)
                writer = csv.writer(f_out)
                
                writer.writerow(['id', 'cve_labels'])
                
                for row in reader:
                    rec_id = row['id']
                    cve_labels = row['cve_labels']
                    
                    processed += 1
                    
                    # CVE-only mode: skip non-CVE records
                    if cve_only and not cve_labels:
                        writer.writerow([rec_id, ''])
                        continue
                    
                    # Get payload
                    encoded_payload = payload_cache.get(rec_id, '')
                    if not encoded_payload:
                        writer.writerow([rec_id, cve_labels])
                        continue
                    
                    payload = self.decode_payload(encoded_payload)
                    if not payload:
                        writer.writerow([rec_id, cve_labels])
                        continue
                    
                    # Predict ML confidence
                    ml_confidence = self.predict_confidence(payload)
                    
                    final_cve_labels = cve_labels
                    
                    if not cve_labels:
                        if ml_confidence >= ml_threshold:
                            final_cve_labels = ''
                            enhanced += 1
                    else:
                        if ml_confidence < 0.4:
                            final_cve_labels = ''
                            removed += 1
                    
                    writer.writerow([rec_id, final_cve_labels])
                    
                    if processed % 1000 == 0:
                        print(f"Processed {processed:,} | Enhanced: {enhanced:,} | Removed: {removed:,}")
        
        print(f"\nEnhancement complete!")
        print(f"Total processed: {processed:,}")
        print(f"ML enhanced: {enhanced:,}")
        print(f"False positives removed: {removed:,}")
        print(f"Output saved to: {output_csv}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ML-Enhanced CVE Detection')
    parser.add_argument('--mode', choices=['train', 'predict', 'both'], default='both',
                       help='Operation mode: train model, predict, or both')
    parser.add_argument('--rules-dir', default='../datacon25/cve',
                       help='CVE POC rules directory')
    parser.add_argument('--input-csv', default='test_label.csv',
                       help='Input CSV from detect_cve_improved.py')
    parser.add_argument('--payload-json', default='data/test_payload.json',
                       help='Payload JSON file')
    parser.add_argument('--output-csv', default='test_label_ml_enhanced.csv',
                       help='Output enhanced CSV')
    parser.add_argument('--model-file', default='cve_detection_model.bin',
                       help='Model file path')
    parser.add_argument('--ml-threshold', type=float, default=0.95,
                       help='ML confidence threshold for new detection (default: 0.95)')
    parser.add_argument('--cve-only', action='store_true',
                       help='Only process records with CVE labels (faster, validation only)')
    
    args = parser.parse_args()
    
    # Training mode
    if args.mode in ['train', 'both']:
        if not os.path.exists(args.rules_dir):
            print(f"Error: Rules directory not found: {args.rules_dir}")
            sys.exit(1)
        
        trainer = FastTextModelTrainer(args.rules_dir)
        
        # Generate training data
        training_file = 'cve_training_data.txt'
        if not trainer.prepare_training_data(training_file):
            print("Error: Failed to prepare training data")
            sys.exit(1)
        
        # Train model
        if not trainer.train_fasttext_model(training_file, args.model_file):
            print("Error: Failed to train model")
            sys.exit(1)
    
    # Prediction mode
    if args.mode in ['predict', 'both']:
        if not os.path.exists(args.model_file):
            print(f"Error: Model file not found: {args.model_file}")
            print("Run with --mode train first")
            sys.exit(1)
        
        if not os.path.exists(args.input_csv):
            print(f"Error: Input CSV not found: {args.input_csv}")
            sys.exit(1)
        
        if not os.path.exists(args.payload_json):
            print(f"Error: Payload JSON not found: {args.payload_json}")
            sys.exit(1)
        
        detector = MLEnhancedDetector(args.model_file)
        detector.enhance_detections(
            args.input_csv, 
            args.payload_json, 
            args.output_csv,
            ml_threshold=args.ml_threshold,
            cve_only=args.cve_only
        )
    
    print("\n" + "="*60)
    print("ML-Enhanced CVE Detection Complete!")
    print("="*60)


if __name__ == '__main__':
    main()
