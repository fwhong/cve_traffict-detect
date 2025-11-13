#!/usr/bin/env python3
"""
LLM-based Refinement on Local Verified Results
Further reduces false positives by using LLM to verify local verification results.
Only sends POC's HTTP/request section to save tokens.
"""

import os
import json
import csv
import base64
import zlib
import requests
import re
import yaml
from glob import glob
import time

#0.001745*15000=26.175
#13s/200*130000=8450s=2.35h

GATEWAY_BASE_URL = "xxx"
GATEWAY_API_KEY = "xxx"
MODEL_NAME = "your model name"
API_ENDPOINT = f"{GATEWAY_BASE_URL}/v1/chat/completions"

# File paths
INPUT_CSV = "test_label_local_verified.csv"
TEST_PAYLOAD_JSON = "../datacon25/test_payload.json"
POC_DIR = "../datacon25/cve"
OUTPUT_CSV = "test_label.csv"
START_ID = 1  # Start processing from this ID
MAX_ROWS = 136521

# Enhanced system prompt
SYSTEM_PROMPT = """你是一名经验丰富的网络安全专家，专门负责CVE漏洞流量检测的误报识别。

**核心任务：** 判断给定的流量是否为该CVE漏洞的误报。

**判断标准：**

真实的CVE漏洞利用必须满足：
1. 流量中的HTTP请求明确包含该CVE的利用特征（路径、参数、payload等）
2. 或者是针对该特定CVE漏洞的存在性扫描、利用成功性验证

**必须判定为误报的情况：**

1. **通用扫描** - 仅扫描可能存在该CVE的软件服务，但没有针对该CVE的具体利用
2. **间接信息获取** - 仅获取软件版本、token、cookie等，不是直接的漏洞利用
3. **路径/参数不匹配** - 流量的请求路径、参数与POC描述的不一致
4. **缺少关键特征** - 缺少POC中描述的关键利用特征或payload
5. **仅访问相关服务** - 只是访问了相关服务的通用接口，没有漏洞利用的关键步骤

**返回格式：**
只返回以下之一：
- VALID：确认是该CVE的真实利用
- FALSE_POSITIVE：判定为误报"""


def decode_payload(encoded_payload):
    try:
        payload_bytes = base64.b64decode(encoded_payload)
        decompressed = zlib.decompress(payload_bytes)
        return decompressed.decode('utf-8', errors='replace')
    except Exception as e:
        return None


def load_payload_by_id(payload_file, target_id):
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if str(data.get('id', '')) == str(target_id):
                        return decode_payload(data.get('payload', ''))
                except:
                    continue
    except Exception as e:
        print(f"    [ERROR] Load payload failed: {e}")
    return None


def find_poc_file(cve_id, poc_dir):
    try:
        pattern = f"*{cve_id}*.yaml"
        files = glob(os.path.join(poc_dir, pattern))
        
        if files:
            sorted_files = sorted(files)
            # Prefer base file without _1, _2 suffix
            for f in sorted_files:
                basename = os.path.basename(f)
                if basename.endswith(f"{cve_id}.yaml"):
                    return f
            return sorted_files[0]
    except Exception as e:
        print(f"    [ERROR] Finding POC failed: {e}")
    return None


def extract_poc_requests_only(poc_file):
    try:
        with open(poc_file, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)
            
        if not data:
            return None
        
        # Extract only relevant parts
        poc_excerpt = {}
        
        # Basic info
        if 'id' in data:
            poc_excerpt['id'] = data['id']
        if 'info' in data and isinstance(data['info'], dict):
            poc_excerpt['info'] = {
                'name': data['info'].get('name', ''),
                'severity': data['info'].get('severity', '')
            }
        
        # HTTP/requests section (most important)
        request_list = data.get('requests') or data.get('http')
        if request_list:
            simplified_requests = []
            for req in request_list[:3]:  # Only first 3 requests to save tokens
                if isinstance(req, dict):
                    simplified = {}
                    if 'method' in req:
                        simplified['method'] = req['method']
                    if 'path' in req:
                        simplified['path'] = req['path']
                    if 'raw' in req:
                        # Truncate raw if too long
                        raw = req['raw']
                        if isinstance(raw, list):
                            simplified['raw'] = [r[:500] for r in raw[:2]]
                        else:
                            simplified['raw'] = str(raw)[:500]
                    if 'body' in req:
                        simplified['body'] = str(req['body'])[:300]
                    simplified_requests.append(simplified)
            
            poc_excerpt['requests'] = simplified_requests
        
        return yaml.dump(poc_excerpt, default_flow_style=False)
    
    except Exception as e:
        print(f"    [ERROR] Extract POC failed: {e}")
        return None


def call_llm_verify(traffic, cve_id, poc_content):

    user_prompt = f"""请判断以下流量是否为 {cve_id} 的误报。

**CVE编号：** {cve_id}

**POC关键信息：**
```yaml
{poc_content[:2500]}
```

**流量内容：**
```
{traffic[:3500]}
```

请仔细对比流量与POC，判断这是否为真实的漏洞利用还是误报。

只返回：VALID 或 FALSE_POSITIVE"""

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GATEWAY_API_KEY}"
    }
    
    data = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "stream": True,
        "temperature": 0.1
    }
    
    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=data, stream=True, timeout=120)
        response.raise_for_status()
        
        full_response = ""
        for line in response.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                if decoded_line.startswith('data: '):
                    content = decoded_line[len('data: '):].strip()
                    if content == "[DONE]":
                        break
                    try:
                        chunk = json.loads(content)
                        if chunk.get("choices") and chunk["choices"][0].get("delta", {}).get("content"):
                            full_response += chunk["choices"][0]["delta"]["content"]
                    except json.JSONDecodeError:
                        continue
        
        full_response = full_response.strip().upper()
        
        if "FALSE_POSITIVE" in full_response or "FALSE POSITIVE" in full_response or "误报" in full_response:
            return False  # Is false positive
        elif "VALID" in full_response:
            return True  # Is valid
        else:
            print(f"    [WARN] Unclear LLM response: {full_response[:100]}")
            return True  # Keep it (conservative)
            
    except Exception as e:
        print(f"    [ERROR] LLM call failed: {e}")
        return None


def process_csv_with_llm_refinement():
    """Process local verified CSV and refine with LLM, starting from START_ID."""
    print(f"LLM Refinement on Test Label Results")
    print(f"Input: {INPUT_CSV}")
    print(f"Output: {OUTPUT_CSV}")
    print(f"Starting from ID: {START_ID}")
    print(f"Processing up to {MAX_ROWS} rows")
    print("-" * 60)
    
    processed = 0
    checked = 0
    removed_additional_fp = 0
    kept_valid = 0
    no_cve = 0
    skipped_before_start = 0
    
    existing_results = {}
    if os.path.exists(OUTPUT_CSV):
        print(f"Loading existing results from {OUTPUT_CSV}...")
        with open(OUTPUT_CSV, 'r', encoding='utf-8') as f_existing:
            reader = csv.reader(f_existing)
            next(reader)  
            for row in reader:
                if len(row) >= 2:
                    existing_results[row[0]] = row[1]
        print(f"Loaded {len(existing_results)} existing results")
    
    with open(INPUT_CSV, 'r', encoding='utf-8') as f_in, \
         open(OUTPUT_CSV + '.tmp', 'w', newline='', encoding='utf-8') as f_out:
        
        reader = csv.reader(f_in)
        writer = csv.writer(f_out)
        
        header = next(reader)
        writer.writerow(header)
        
        for row in reader:
            if processed >= MAX_ROWS:
                break
            
            if len(row) < 2:
                writer.writerow(row)
                continue
            
            record_id, cve_labels = row[0], row[1]
            processed += 1
            
            try:
                if int(record_id) < START_ID:
                    if record_id in existing_results:
                        writer.writerow([record_id, existing_results[record_id]])
                    else:
                        writer.writerow(row)
                    skipped_before_start += 1
                    continue
            except ValueError:
                writer.writerow(row)
                continue
            
            cves = [c.strip() for c in cve_labels.split() if c.strip()]
            
            if not cves:
                writer.writerow(row)
                no_cve += 1
                continue
            
            print(f"\n[ID: {record_id}] CVE: {cve_labels}")
            checked += 1
            
            traffic = load_payload_by_id(TEST_PAYLOAD_JSON, record_id)
            if not traffic:
                print(f"    [SKIP] Cannot load traffic, removing")
                writer.writerow([record_id, ""])
                removed_additional_fp += 1
                continue
            
            print(f"    Traffic: {len(traffic)} bytes")
            
            cve_to_check = cves[0]
            
            poc_file = find_poc_file(cve_to_check, POC_DIR)
            if not poc_file:
                print(f"    [SKIP] No POC found, removing")
                writer.writerow([record_id, ""])
                removed_additional_fp += 1
                continue
            
            poc_content = extract_poc_requests_only(poc_file)
            if not poc_content:
                print(f"    [SKIP] Cannot extract POC, removing")
                writer.writerow([record_id, ""])
                removed_additional_fp += 1
                continue
            
            print(f"    POC: {os.path.basename(poc_file)} ({len(poc_content)} bytes)")
            
            print(f"    Calling LLM...")
            is_valid = call_llm_verify(traffic, cve_to_check, poc_content)
            
            if is_valid is None:
                print(f"    [ERROR] LLM error, keeping original")
                writer.writerow(row)
                kept_valid += 1
            elif is_valid:
                print(f"    ✓ VALID: Keeping {cve_labels}")
                writer.writerow(row)
                kept_valid += 1
            else:
                print(f"    ✗ FALSE POSITIVE: Removing")
                writer.writerow([record_id, ""])
                removed_additional_fp += 1
            
            time.sleep(0.5)
            
            if processed % 10 == 0:
                print(f"\n{'='*60}")
                print(f"Progress: {processed}/{MAX_ROWS}")
                print(f"Checked: {checked}, Removed: {removed_additional_fp}, Kept: {kept_valid}")
                print(f"{'='*60}")
    
    import shutil
    shutil.move(OUTPUT_CSV + '.tmp', OUTPUT_CSV)
    
    print(f"\n{'='*60}")
    print(f"Complete!")
    print(f"Total rows processed: {processed}")
    print(f"Skipped before START_ID: {skipped_before_start}")
    print(f"No CVE: {no_cve}")
    print(f"LLM checked: {checked}")
    print(f"Removed additional FP: {removed_additional_fp}")
    print(f"Kept valid: {kept_valid}")
    if checked > 0:
        print(f"Additional FP removal rate: {removed_additional_fp}/{checked} = {removed_additional_fp/checked*100:.1f}%")
    print(f"Output saved to: {OUTPUT_CSV}")
    print(f"{'='*60}")


def main():
    if not os.path.exists(INPUT_CSV):
        print(f"Error: {INPUT_CSV} not found!")
        print("Please run local_verify_cve.py first to generate this file.")
        return
    
    if not os.path.exists(TEST_PAYLOAD_JSON):
        print(f"Error: {TEST_PAYLOAD_JSON} not found!")
        return
    
    if not os.path.exists(POC_DIR):
        print(f"Error: {POC_DIR} not found!")
        return
    
    print(f"Files check passed:")
    print(f"  ✓ {INPUT_CSV}")
    print(f"  ✓ {TEST_PAYLOAD_JSON}")
    print(f"  ✓ {POC_DIR}")
    print()
    
    process_csv_with_llm_refinement()


if __name__ == "__main__":
    main()
