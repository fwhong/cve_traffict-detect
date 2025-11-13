#!/usr/bin/env python3
"""
PKUCC战队 - 恶意流量识别
Automated CVE Detection Pipeline
整合三个阶段的CVE检测流程
"""

import os
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path


class PKUCCDetectionPipeline:
    
    def __init__(self):
        self.start_time = None
        self.stage_times = {}
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗  ██╗██╗   ██╗ ██████╗ ██████╗                   ║
║   ██╔══██╗██║ ██╔╝██║   ██║██╔════╝██╔════╝                   ║
║   ██████╔╝█████╔╝ ██║   ██║██║     ██║                        ║
║   ██╔═══╝ ██╔═██╗ ██║   ██║██║     ██║                        ║
║   ██║     ██║  ██╗╚██████╔╝╚██████╗╚██████╗                   ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝                   ║
║                                                               ║
║              恶意流量识别                                       ║
║          Automated CVE Detection Pipeline                     ║
║                                                               ║
║              北京大学                                          ║
║           Peking University                                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
        print(banner)
        print(f"系统启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 65)
        print()
    
    def print_stage_header(self, stage_num, stage_name, description):
        print("\n" + "=" * 65)
        print(f"阶段 {stage_num}: {stage_name}")
        print(f"描述: {description}")
        print("=" * 65)
    
    def run_command(self, cmd, stage_name):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 执行命令:")
        print(f"  {' '.join(cmd)}")
        print()
        
        stage_start = time.time()
        
        try:
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                env=env
            )
            
            for line in process.stdout:
                print(line, end='', flush=True)
            
            process.wait()
            
            if process.returncode != 0:
                print(f"\n❌ 错误: {stage_name} 执行失败 (返回码: {process.returncode})")
                return False
            
            stage_time = time.time() - stage_start
            self.stage_times[stage_name] = stage_time
            
            print(f"\n✅ {stage_name} 完成! 耗时: {stage_time:.2f}秒")
            return True
            
        except Exception as e:
            print(f"\n❌ 错误: {stage_name} 执行异常: {e}")
            return False
    
    def check_file_exists(self, filepath, description=""):
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"✓ 文件存在: {filepath}")
            if description:
                print(f"  {description}")
            print(f"  文件大小: {size:,} bytes")
            return True
        else:
            print(f"✗ 文件不存在: {filepath}")
            return False
    
    def stage1_initial_detection(self):
        """阶段1: 初步筛选CVE流量"""
        self.print_stage_header(
            1, 
            "初步CVE筛选", 
            "使用规则匹配从流量中筛选出潜在的CVE攻击"
        )
        
        print("\n检查输入文件...")
        if not self.check_file_exists("data/test_payload.json", "测试流量数据"):
            return False
        
        cmd = [
            sys.executable,
            "detect_cve_final.py"
        ]
        
        if not self.run_command(cmd, "Stage1_InitialDetection"):
            return False
        
        print("\n检查输出文件...")
        if not self.check_file_exists("test_label.csv", "初步筛选结果"):
            return False
        
        return True
    
    def stage2_ml_enhancement(self, ml_threshold=0.998, cve_only=False):
        """阶段2: ML模型增强筛选"""
        self.print_stage_header(
            2,
            "ML模型增强筛选",
            "使用机器学习模型进行二次筛选和置信度评估"
        )
        
        print("\n检查输入文件...")
        if not self.check_file_exists("test_label.csv", "阶段1输出"):
            return False
        
        cmd = [
            sys.executable,
            "detect_cve_ml_enhance.py",
            "--mode", "predict",
            "--model-file", "test_model.bin",
            "--ml-threshold", str(ml_threshold),
            "--input-csv", "test_label.csv",
            "--payload-json", "data/test_payload.json",
            "--output-csv", "test_label_ml_enhanced.csv"
        ]
        
        if cve_only:
            cmd.append("--cve-only")
        
        if not os.path.exists("test_model.bin"):
            print("\n⚠️  模型文件不存在，将先进行训练...")
            train_cmd = [
                sys.executable,
                "detect_cve_ml_enhance.py",
                "--mode", "train",
                "--rules-dir", "../datacon25/cve",
                "--model-file", "test_model.bin"
            ]
            if not self.run_command(train_cmd, "Stage2_ModelTraining"):
                return False
        
        if not self.run_command(cmd, "Stage2_MLEnhancement"):
            return False
        
        print("\n检查输出文件...")
        if not self.check_file_exists("test_label_ml_enhanced.csv", "ML增强结果"):
            return False
        
        return True
    
    def stage3_local_verification(self):
        """阶段3: 本地验证"""
        self.print_stage_header(
            3,
            "本地验证",
            "使用本地验证脚本进行CVE确认"
        )
        
        print("\n检查输入文件...")
        if not self.check_file_exists("test_label_ml_enhanced.csv", "阶段2输出"):
            return False
        
        cmd = [
            sys.executable,
            "local_verify_cve.py"
        ]
        
        if not self.run_command(cmd, "Stage3_LocalVerification"):
            return False
        
        print("\n检查输出文件...")
        
        return True
    
    def stage4_llm_verification(self):
        """阶段4: LLM辅助验证"""
        self.print_stage_header(
            4,
            "LLM辅助验证",
            "使用大语言模型进行最终验证和精炼"
        )
        
        print("\n检查输入文件...")
        
        cmd = [
            sys.executable,
            "llm_refine_verified.py"
        ]
        
        if not self.run_command(cmd, "Stage4_LLMVerification"):
            return False
        
        print("\n检查输出文件...")
        
        return True
    
    def print_summary(self):
        total_time = time.time() - self.start_time
        
        print("\n" + "=" * 65)
        print("PKUCC CVE检测流程完成!")
        print("=" * 65)
        print(f"\n总耗时: {total_time:.2f}秒 ({total_time/60:.2f}分钟)")
        print("\n各阶段耗时:")
        for stage, duration in self.stage_times.items():
            print(f"  • {stage}: {duration:.2f}秒")
        
        # 显示输出文件
        print("\n生成的文件:")
        output_files = [
            ("test_label.csv", "筛选结果"),
            ("test_label_ml_enhanced.csv", "ML增强结果"),
            ("cve_training_data.txt", "训练数据（如果训练）"),
            ("test_model.bin", "ML模型（如果训练）")
        ]
        
        for filename, description in output_files:
            if os.path.exists(filename):
                size = os.path.getsize(filename) / (1024*1024)  # MB
                print(f"  ✓ {filename} ({size:.2f} MB) - {description}")
        
        print("\n" + "=" * 65)
        print("感谢使用!")
        print("=" * 65)
    
    def run_pipeline(self, ml_threshold=0.998, cve_only=False, skip_llm=False):
        self.start_time = time.time()
        self.print_banner()
        
        try:
            # 阶段1: 初步筛选
            if not self.stage1_initial_detection():
                print("\n❌ 阶段1失败，流程终止")
                return False
            
            # 阶段2: ML增强
            if not self.stage2_ml_enhancement(ml_threshold, cve_only):
                print("\n❌ 阶段2失败，流程终止")
                return False
            
            # 阶段3: 本地验证
            if not self.stage3_local_verification():
                print("\n⚠️  阶段3失败，但前两个阶段已完成")
                # 本地验证失败不终止流程
            
            # 阶段4: LLM验证（可选）
            if not skip_llm:
                if not self.stage4_llm_verification():
                    print("\n⚠️  阶段4失败，但前面阶段已完成")
            else:
                print("\n⏭️  跳过阶段4 (LLM验证)")
            
            self.print_summary()
            return True
            
        except KeyboardInterrupt:
            print("\n\n⚠️  用户中断流程")
            return False
        except Exception as e:
            print(f"\n❌ 流程异常: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PKUCC战队 - 恶意流量识别',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 完整流程（推荐）
  python run_cve_detection_pipeline.py
  
  # 使用更严格的ML阈值
  python run_cve_detection_pipeline.py --ml-threshold 0.999
  
  # 只验证CVE，不发现新CVE（快速模式）
  python run_cve_detection_pipeline.py --cve-only
  
  # 跳过LLM验证阶段
  python run_cve_detection_pipeline.py --skip-llm
        """
    )
    
    parser.add_argument(
        '--ml-threshold',
        type=float,
        default=0.998,
        help='ML模型置信度阈值 (默认: 0.998, 范围: 0.0-1.0)'
    )
    
    parser.add_argument(
        '--cve-only',
        action='store_true',
        help='只验证规则检测的CVE，不发现新CVE（快速模式）'
    )
    
    parser.add_argument(
        '--skip-llm',
        action='store_true',
        help='跳过LLM验证阶段'
    )
    
    args = parser.parse_args()
    
    pipeline = PKUCCDetectionPipeline()
    success = pipeline.run_pipeline(
        ml_threshold=args.ml_threshold,
        cve_only=args.cve_only,
        skip_llm=args.skip_llm
    )
    

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
