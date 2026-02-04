#!/usr/bin/env python
"""
ToxiCR 批量毒性分析脚本 - 改进版（无需 networkx）

此脚本用于分析 oss_graph_construction 项目中 monthly-graphs 的评论毒性。
在 ToxiCR 虚拟环境中运行，将结果缓存到 JSON 文件供 oss_graph_construction 读取。
"""

import argparse
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Any

# 确保 ToxiCR 路径在 sys.path 中
TOXICR_PATH = os.path.dirname(os.path.abspath(__file__))
if TOXICR_PATH not in sys.path:
    sys.path.insert(0, TOXICR_PATH)


def hash_text(text: str) -> str:
    """计算文本的 MD5 哈希值"""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def load_cache(cache_file: Path) -> Dict[str, Dict[str, Any]]:
    """加载已有缓存（兼容新旧格式）"""
    if not cache_file.exists():
        return {}
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 兼容旧格式：{hash: score}
        if data and isinstance(next(iter(data.values())), (int, float)):
            print("检测到旧版缓存格式，将自动迁移")
            # 转换为新格式，但元数据为空（后续扫描时补充）
            return {h: {"toxicity": s, "repo": "", "month": "", "comment": ""} 
                    for h, s in data.items()}
        
        # 新格式：{hash: {repo, month, comment, toxicity}}
        return data
    except Exception as e:
        print(f"警告: 加载缓存失败: {e}")
        return {}


def save_cache(cache: Dict[str, Dict[str, Any]], cache_file: Path):
    """保存缓存（新格式：包含仓库、月份、评论、毒性）"""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    print(f"缓存已保存: {cache_file} ({len(cache)} 条记录)")


def load_top30_repos(top30_file: Path) -> Set[str]:
    """加载 Top30 仓库列表"""
    if not top30_file.exists():
        print(f"警告: Top30 文件不存在: {top30_file}，将分析所有仓库")
        return set()
    try:
        with open(top30_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {item["repo"] for item in data}
    except Exception as e:
        print(f"警告: 加载 Top30 失败: {e}")
        return set()


def extract_comments_from_graphml(graphml_path: Path) -> List[str]:
    """
    从 GraphML 文件中提取所有 comment_body（无需 networkx）
    直接解析 XML
    """
    try:
        tree = ET.parse(str(graphml_path))
        root = tree.getroot()
        
        comments = []
        
        # GraphML 的命名空间（注意：不是 xmlformat/1.0）
        ns = {'graphml': 'http://graphml.graphdrawing.org/xmlns'}
        
        # 查找所有 edge 元素
        for edge in root.findall('.//graphml:edge', ns):
            # 查找 comment_body 属性（key="d20"）
            for data in edge.findall('graphml:data', ns):
                key_attr = data.get('key')
                if key_attr == 'd20':  # d20 是 comment_body 的 key ID
                    text = data.text
                    if text and text.strip() and len(text.strip()) >= 5:
                        comments.append(text.strip())
        
        # 如果没有找到，尝试不使用命名空间的方式
        if not comments:
            for edge in root.findall('.//edge'):
                for data in edge.findall('data'):
                    if 'comment' in str(data.get('key', '')).lower():
                        text = data.text
                        if text and text.strip() and len(text.strip()) >= 5:
                            comments.append(text.strip())
        
        return comments
    except Exception as e:
        print(f"  警告: 无法读取图文件 {graphml_path}: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="ToxiCR 批量毒性分析（改进版）")
    parser.add_argument(
        "--graphs-dir",
        type=str,
        default="C:/Users/dzp/project/oss_graph_construction/output/monthly-graphs",
        help="monthly-graphs 目录路径"
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="C:/Users/dzp/project/oss_graph_construction/output/community-atmosphere-analysis/toxicity.json",
        help="输出缓存文件路径"
    )
    parser.add_argument(
        "--top30-file",
        type=str,
        default="C:/Users/dzp/project/oss_graph_construction/top30.json",
        help="Top30 仓库列表文件路径"
    )
    parser.add_argument(
        "--top30",
        action="store_true",
        default=False,
        help="只分析 Top30 仓库（需要 --top30-file 指定的文件存在）"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=256,
        help="批处理大小"
    )
    args = parser.parse_args()
    
    graphs_dir = Path(args.graphs_dir)
    output_file = Path(args.output_file)
    top30_file = Path(args.top30_file)
    
    print("=" * 60)
    print("ToxiCR 批量毒性分析（改进版 - 无需 networkx）")
    print("=" * 60)
    print(f"图目录: {graphs_dir}")
    print(f"输出文件: {output_file}")
    print(f"Top30 过滤: {'启用' if args.top30 else '禁用'}")
    print()
    
    # 检查目录
    if not graphs_dir.exists():
        print(f"错误: 图目录不存在: {graphs_dir}")
        sys.exit(1)
    
    # 加载索引
    index_file = graphs_dir / "index.json"
    if not index_file.exists():
        print(f"错误: 索引文件不存在: {index_file}")
        sys.exit(1)
    
    with open(index_file, "r", encoding="utf-8") as f:
        index = json.load(f)
    
    print(f"索引加载成功，共 {len(index)} 个仓库")
    
    # 加载 Top30 过滤（仅当 --top30 参数启用时）
    if args.top30:
        top30_repos = load_top30_repos(top30_file)
        if top30_repos:
            print(f"Top30 仓库: {len(top30_repos)} 个")
            index = {k: v for k, v in index.items() if k in top30_repos}
            print(f"过滤后: {len(index)} 个仓库")
        else:
            print("警告: Top30 文件加载失败，将分析所有仓库")
    
    # 加载已有缓存
    cache = load_cache(output_file)
    print(f"已有缓存: {len(cache)} 条记录")
    
    # 第一步：收集所有需要分析的评论 + 更新元数据
    print()
    print("第一步：收集评论并更新元数据...")
    all_comments: List[str] = []
    all_hashes: Set[str] = set()
    comment_metadata: Dict[str, Dict[str, str]] = {}  # hash -> {repo, month, comment}
    
    for repo_idx, (repo_name, graph_types_data) in enumerate(index.items(), 1):
        print(f"[{repo_idx}/{len(index)}] 扫描: {repo_name}", end="")
        
        # 获取 actor-discussion 图路径
        discussion_paths = graph_types_data.get("actor-discussion", {}) or {}
        
        repo_comments = 0
        for month, graph_path in discussion_paths.items():
            full_path = Path(graph_path)
            if not full_path.is_absolute():
                # 尝试相对于项目根目录
                full_path = graphs_dir.parent.parent / graph_path
            
            if not full_path.exists():
                continue
            
            comments = extract_comments_from_graphml(full_path)
            for comment in comments:
                text_hash = hash_text(comment)
                
                # 记录元数据（无论是否已分析）
                if text_hash not in comment_metadata:
                    comment_metadata[text_hash] = {
                        "repo": repo_name,
                        "month": month,
                        "comment": comment[:500]  # 只保存前500字符，节省空间
                    }
                
                # 更新已有缓存的元数据（兼容从旧格式迁移的数据）
                if text_hash in cache and not cache[text_hash].get("repo"):
                    cache[text_hash].update(comment_metadata[text_hash])
                
                # 只有未分析的才加入待分析列表
                if text_hash not in cache and text_hash not in all_hashes:
                    all_comments.append(comment)
                    all_hashes.add(text_hash)
                    repo_comments += 1
        
        print(f" -> {repo_comments} 条新评论")
    
    print()
    print(f"总共需要分析: {len(all_comments)} 条新评论")
    
    if not all_comments:
        print("没有新评论需要分析，但会保存更新后的元数据")
        save_cache(cache, output_file)  # ✅ 保存补充后的元数据
        print()
        print("=" * 60)
        print("元数据更新完成!")
        print(f"缓存总量: {len(cache)} 条")
        print(f"输出文件: {output_file}")
        print("=" * 60)
        return
    
    # 第二步：初始化 ToxiCR 模型
    print()
    print("第二步：初始化 ToxiCR 模型...")
    
    from ToxiCR import ToxiCR
    
    classifier = ToxiCR(
        ALGO="BERT",
        count_profanity=False,
        remove_keywords=True,
        split_identifier=False,
        embedding="bert",
        load_pretrained=True
    )
    classifier.init_predictor()
    print("模型初始化完成")
    
    # 第三步：批量预测
    print()
    print("第三步：批量预测毒性...")
    
    batch_size = args.batch_size
    total_batches = (len(all_comments) + batch_size - 1) // batch_size
    
    new_predictions = 0
    for batch_idx in range(total_batches):
        start = batch_idx * batch_size
        end = min(start + batch_size, len(all_comments))
        batch_comments = all_comments[start:end]
        
        print(f"  批次 {batch_idx + 1}/{total_batches} ({start + 1}-{end}/{len(all_comments)})...", end="", flush=True)
        
        try:
            predictions = classifier.get_toxicity_probability(batch_comments)
            
            # 保存到缓存（包含元数据）
            for i, comment in enumerate(batch_comments):
                text_hash = hash_text(comment)
                metadata = comment_metadata.get(text_hash, {
                    "repo": "unknown",
                    "month": "unknown",
                    "comment": comment[:500]
                })
                cache[text_hash] = {
                    "repo": metadata["repo"],
                    "month": metadata["month"],
                    "comment": metadata["comment"],
                    "toxicity": float(predictions[i])
                }
                new_predictions += 1
            
            print(f" 完成")
            
            # 每 10 个批次保存一次缓存（断点续传）
            if (batch_idx + 1) % 10 == 0:
                save_cache(cache, output_file)
                
        except Exception as e:
            print(f" 失败: {e}")
            continue
    
    # 最终保存
    save_cache(cache, output_file)
    
    print()
    print("=" * 60)
    print("分析完成!")
    print(f"新增预测: {new_predictions} 条")
    print(f"缓存总量: {len(cache)} 条")
    print(f"输出文件: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
