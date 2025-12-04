import requests
import os
import datetime
from datetime import timedelta
import warnings
from bs4 import BeautifulSoup

# 忽略 HTTPS 证书警告 (BadIP 可能会用到 verify=False)
warnings.filterwarnings("ignore")

# ================= 配置区域 =================

# 输出文件名
FILE_WHITE = "spider_white_ips.txt"
FILE_BLACK = "bad_black_ips.txt"

# 请求头 (防止被某些接口拦截)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FeedMyWafIP/1.0; +https://github.com/)"
}

# ----------------- 数据源定义 -----------------

# 1. 爬虫白名单 - JSON 格式源 (Google, Bing, Apple)
WHITE_JSON_SOURCES = {
    "Bing": "https://www.bing.com/toolbox/bingbot.json",
    "Apple": "https://search.developer.apple.com/applebot.json",
    "Google": "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
}

# 2. 爬虫白名单 - 文本/CIDR 格式源
WHITE_TEXT_SOURCES = {
    "Baidu": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/74a45de2d0f04f739ca73b2ecc05930d?format=cidr"
}

# 3. 恶意黑名单 - 文本/CIDR 格式源
BLACK_TEXT_SOURCES = {
    "MaliciousOps": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/9c1a54395c174e94af2b704eda610d95?format=cidr",
    "ThreatIntel": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/d13d2a3f9bb34fc4b2c846e3e0bc03bc?format=cidr",
    "ScannersAttacks": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/0ae14d75480842899342104743d2fc56?format=cidr"
}

# ================= 功能函数 =================

def fetch_json_cidrs(name, url):
    """处理返回 JSON 格式的接口 (Google/Bing/Apple)"""
    cidrs = set()
    print(f"[-] 正在抓取 [JSON]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        if "prefixes" in data:
            for item in data["prefixes"]:
                if "ipv4Prefix" in item:
                    cidrs.add(item["ipv4Prefix"])
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def fetch_text_cidrs(name, url):
    """处理返回纯文本/CIDR 格式的接口 (Chaitin Rivers/Baidu)"""
    cidrs = set()
    print(f"[-] 正在抓取 [TEXT]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        
        lines = resp.text.splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"): 
                cidrs.add(line)
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def fetch_badip_recent_days(days=7):
    """抓取 BadIP 最近 N 天的恶意 IP 列表"""
    cidrs = set()
    print(f"[-] 正在抓取 [BadIP]: 最近 {days} 天的数据 ...")
    
    today = datetime.datetime.today()
    
    for i in range(days):
        date_obj = today - timedelta(days=i)
        date_str = date_obj.strftime('%Y-%m-%d')
        url = f'https://www.badip.com/d-{date_str}.html'
        
        try:
            # BadIP 可能有 SSL 问题，verify=False 是必须的
            # 使用 verify=False 时 headers 依然重要
            response = requests.get(url, headers=HEADERS, verify=False, timeout=20)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                table = soup.find('table')
                
                if table:
                    # 跳过表头
                    rows = table.find_all('tr')[1:]
                    daily_count = 0
                    for row in rows:
                        columns = row.find_all('td')
                        if columns and len(columns) > 1:
                            # IP 通常在第二列
                            ip = columns[1].text.strip()
                            if ip:
                                cidrs.add(ip)
                                daily_count += 1
                    # print(f"    > {date_str}: 获取 {daily_count} 个")
                else:
                    print(f"    > {date_str}: 未找到表格")
            else:
                print(f"    > {date_str}: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"    > {date_str} 抓取异常: {e}")
            
    print(f"    √ BadIP 总计去重后获取 {len(cidrs)} 个 IP")
    return cidrs

def save_to_file(filename, cidr_set):
    """保存数据到文件，始终覆盖，排序"""
    try:
        sorted_cidrs = sorted(list(cidr_set))
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_cidrs))
            f.write("\n")
        print(f"[SUCCESS] 已写入 {filename} (共 {len(sorted_cidrs)} 条数据)")
    except Exception as e:
        print(f"[ERROR] 写入 {filename} 失败: {e}")

# ================= 主程序 =================

def main():
    print(f"=== 开始执行 feed-mywaf-ip 更新任务: {datetime.datetime.now()} ===\n")

    # --- 1. 处理白名单 ---
    white_ips_all = set()
    
    # 1.1 JSON 源
    for name, url in WHITE_JSON_SOURCES.items():
        white_ips_all.update(fetch_json_cidrs(name, url))
        
    # 1.2 文本 源 (百度)
    for name, url in WHITE_TEXT_SOURCES.items():
        white_ips_all.update(fetch_text_cidrs(name, url))

    # 保存白名单 (自动去重)
    save_to_file(FILE_WHITE, white_ips_all)
    print("-" * 30)

    # --- 2. 处理黑名单 ---
    black_ips_all = set()
    
    # 2.1 文本 源 (威胁情报/长亭 API)
    for name, url in BLACK_TEXT_SOURCES.items():
        black_ips_all.update(fetch_text_cidrs(name, url))
    
    # 2.2 BadIP 源 (最近7天)
    black_ips_all.update(fetch_badip_recent_days(days=7))
        
    # 保存黑名单 (自动去重)
    save_to_file(FILE_BLACK, black_ips_all)
    print("-" * 30)
    
    print("\n=== 更新完成 ===")

if __name__ == "__main__":
    main()
