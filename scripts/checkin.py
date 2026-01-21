import os
import sys
import asyncio
import random
import json
from typing import List, Tuple
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import aiohttp
from aiohttp_socks import ProxyConnector
from colorama import init, Fore, Style

init(autoreset=True)

BORDER_WIDTH = 80

API_BASE_URL = "https://hub.veerarewards.com/api"
WEBSITE_ID = "d2c97001-a40d-45b6-b69c-11927e144773"
ORGANIZATION_ID = "3cf0dde2-04c0-424a-a603-13fcf79e440e"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "vi,en-US;q=0.9,en;q=0.8",
    "Content-Type": "application/json",
    "Origin": "https://hub.veerarewards.com",
    "Referer": "https://hub.veerarewards.com/loyalty",
    "Sec-Ch-Ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

CONFIG = {
    "DELAY_BETWEEN_ACCOUNTS": 5,
    "RETRY_ATTEMPTS": 3,
    "RETRY_DELAY": 5,
    "THREADS": 4,
    "BYPASS_SSL": True,
    "TIMEOUT": 30,
}

TASKS = [
    {"id": "0c2c81eb-c631-48a8-9f27-a97d192e0039", "name": "Daily Check-in", "points": 5},
]

LANG = {
    'vi': {
        'title': 'VEERA REWARDS - NHIỆM VỤ CHECK-IN HÀNG NGÀY',
        'info': 'Thông tin',
        'found': 'Tìm thấy',
        'wallets': 'ví',
        'processing_wallets': '⚙ ĐANG XỬ LÝ {count} VÍ',
        'getting_csrf': 'Đang lấy CSRF token...',
        'csrf_success': 'Đã lấy CSRF token thành công!',
        'signing_message': 'Đang ký thông điệp...',
        'sign_success': 'Đã ký tin nhắn thành công!',
        'logging_in': 'Đang đăng nhập...',
        'login_success': 'Đăng nhập thành công!',
        'checking_status': 'Đang kiểm tra trạng thái nhiệm vụ...',
        'status_checked': 'Đã kiểm tra trạng thái nhiệm vụ!',
        'completing_task': 'Đang hoàn thành nhiệm vụ',
        'task_success': 'Nhiệm vụ đã hoàn thành!',
        'task_completed': 'Đã hoàn thành trước đó',
        'task_queued': 'Nhiệm vụ đã được thêm vào hàng đợi',
        'task_processing': 'Đang xử lý',
        'task_failed': 'Thất bại',
        'task_verifying': 'Đang xác minh, vui lòng kiểm tra lại sau',
        'success': '✅ Hoàn thành nhiệm vụ Check-in cho ví {address}',
        'name': 'Tên',
        'points_earned': 'Điểm',
        'total_points': 'Tổng điểm',
        'failure': '❌ Thất bại: {error}',
        'address': 'Địa chỉ ví',
        'pausing': 'Tạm dừng',
        'seconds': 'giây',
        'completed': '✅ HOÀN THÀNH: {successful}/{total} VÍ THÀNH CÔNG',
        'error': 'Lỗi',
        'pvkey_not_found': '❌ Không tìm thấy tệp pvkey.txt',
        'pvkey_empty': '❌ Không tìm thấy khóa riêng hợp lệ',
        'pvkey_error': '❌ Không thể đọc pvkey.txt',
        'invalid_key': 'không hợp lệ, đã bỏ qua',
        'warning_line': 'Cảnh báo: Dòng',
        'found_proxies': 'Tìm thấy {count} proxy trong proxies.txt',
        'found_wallets': 'Thông tin: Tìm thấy {count} ví',
        'no_proxies': 'Không tìm thấy proxy trong proxies.txt',
        'using_proxy': '🔄 Sử dụng Proxy - [{proxy}] với IP công khai - [{public_ip}]',
        'no_proxy': 'Không có proxy',
        'unknown': 'Không xác định',
        'invalid_proxy': '⚠ Proxy không hợp lệ hoặc không hoạt động: {proxy}',
        'ip_check_failed': '⚠ Không thể kiểm tra IP công khai: {error}',
        'checkin_tasks_header': 'NHIỆM VỤ CHECK-IN',
        'tasks_to_complete': 'Nhiệm vụ đã hoàn thành',
        'checking_session': 'Đang kiểm tra phiên...',
        'session_valid': 'Phiên hợp lệ!',
        'all_completed': 'Tất cả nhiệm vụ đã hoàn thành!',
        'getting_user_id': 'Đang lấy User ID...',
        'user_id_success': 'Đã lấy User ID thành công!',
    },
    'en': {
        'title': 'VEERA REWARDS - DAILY CHECK-IN TASKS',
        'info': 'Information',
        'found': 'Found',
        'wallets': 'wallets',
        'processing_wallets': '⚙ PROCESSING {count} WALLETS',
        'getting_csrf': 'Getting CSRF token...',
        'csrf_success': 'Got CSRF token successfully!',
        'signing_message': 'Signing message...',
        'sign_success': 'Signed message successfully!',
        'logging_in': 'Logging in...',
        'login_success': 'Login successful!',
        'checking_status': 'Checking task status...',
        'status_checked': 'Task status checked!',
        'completing_task': 'Completing task',
        'task_success': 'Task completed!',
        'task_completed': 'Already completed',
        'task_queued': 'Task added to queue',
        'task_processing': 'Processing',
        'task_failed': 'Failed',
        'task_verifying': 'Verifying, check back later',
        'success': '✅ Check-in tasks completed for wallet {address}',
        'name': 'Name',
        'points_earned': 'Points',
        'total_points': 'Total Points',
        'failure': '❌ Failed: {error}',
        'address': 'Wallet address',
        'pausing': 'Pausing',
        'seconds': 'seconds',
        'completed': '✅ COMPLETED: {successful}/{total} WALLETS SUCCESSFUL',
        'error': 'Error',
        'pvkey_not_found': '❌ pvkey.txt file not found',
        'pvkey_empty': '❌ No valid private keys found',
        'pvkey_error': '❌ Failed to read pvkey.txt',
        'invalid_key': 'is invalid, skipped',
        'warning_line': 'Warning: Line',
        'found_proxies': 'Found {count} proxies in proxies.txt',
        'found_wallets': 'Info: Found {count} wallets',
        'no_proxies': 'No proxies found in proxies.txt',
        'using_proxy': '🔄 Using Proxy - [{proxy}] with Public IP - [{public_ip}]',
        'no_proxy': 'No proxy',
        'unknown': 'Unknown',
        'invalid_proxy': '⚠ Invalid or unresponsive proxy: {proxy}',
        'ip_check_failed': '⚠ Failed to check public IP: {error}',
        'checkin_tasks_header': 'CHECK-IN TASKS',
        'tasks_to_complete': 'Tasks completed',
        'checking_session': 'Checking session...',
        'session_valid': 'Session valid!',
        'all_completed': 'All tasks already completed!',
        'getting_user_id': 'Getting User ID...',
        'user_id_success': 'Got User ID successfully!',
    }
}

def print_border(text: str, color=Fore.CYAN, width=BORDER_WIDTH, language: str = 'en'):
    text = text.strip()
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA, language: str = 'en'):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(message: str, color=Fore.YELLOW, language: str = 'en'):
    print(f"{color}  {message}{Style.RESET_ALL}")

def print_wallets_summary(count: int, language: str = 'en'):
    print_border(
        LANG[language]['processing_wallets'].format(count=count),
        Fore.MAGENTA, language=language
    )
    print()

def is_valid_private_key(key: str) -> bool:
    key = key.strip()
    if not key.startswith('0x'):
        key = '0x' + key
    try:
        bytes.fromhex(key.replace('0x', ''))
        return len(key) == 66
    except ValueError:
        return False

def load_private_keys(file_path: str = "pvkey.txt", language: str = 'en') -> List[Tuple[int, str]]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_not_found']}{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add private keys here, one per line\n# Example: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n")
            sys.exit(1)
        
        valid_keys = []
        with open(file_path, 'r') as f:
            for i, line in enumerate(f, 1):
                key = line.strip()
                if key and not key.startswith('#'):
                    if is_valid_private_key(key):
                        if not key.startswith('0x'):
                            key = '0x' + key
                        valid_keys.append((i, key))
                    else:
                        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['warning_line']} {i} {LANG[language]['invalid_key']}: {key}{Style.RESET_ALL}")
        
        if not valid_keys:
            print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_empty']}{Style.RESET_ALL}")
            sys.exit(1)
        
        return valid_keys
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_error']}: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def load_proxies(file_path: str = "proxies.txt", language: str = 'en') -> List[str]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add proxies here, one per line\n# Example: socks5://user:pass@host:port or http://host:port\n")
            return []
        
        proxies = []
        with open(file_path, 'r') as f:
            for line in f:
                proxy = line.strip()
                if proxy and not line.startswith('#'):
                    proxies.append(proxy)
        
        if not proxies:
            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_proxies'].format(count=len(proxies))}{Style.RESET_ALL}")
        return proxies
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['error']}: {str(e)}{Style.RESET_ALL}")
        return []

async def get_proxy_ip(proxy: str = None, language: str = 'en') -> str:
    IP_CHECK_URL = "https://api.ipify.org?format=json"
    try:
        if proxy:
            if proxy.startswith(('socks5://', 'socks4://', 'http://', 'https://')):
                connector = ProxyConnector.from_url(proxy)
            else:
                parts = proxy.split(':')
                if len(parts) == 4:
                    proxy_url = f"socks5://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                    connector = ProxyConnector.from_url(proxy_url)
                elif len(parts) == 3 and '@' in proxy:
                    connector = ProxyConnector.from_url(f"socks5://{proxy}")
                else:
                    print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}{Style.RESET_ALL}")
                    return LANG[language]['unknown']
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(IP_CHECK_URL, headers=HEADERS) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('ip', LANG[language]['unknown'])
                    return LANG[language]['unknown']
        else:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(IP_CHECK_URL, headers=HEADERS) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('ip', LANG[language]['unknown'])
                    return LANG[language]['unknown']
    except Exception as e:
        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['ip_check_failed'].format(error=str(e))}{Style.RESET_ALL}")
        return LANG[language]['unknown']

async def veera_checkin(private_key: str, index: int, proxy: str = None, language: str = 'en') -> bool:
    account = Account.from_key(private_key)
    address = account.address
    print_border(f"Check-in for Wallet {index}: {address[:6]}...{address[-4:]}", Fore.YELLOW, language=language)

    public_ip = await get_proxy_ip(proxy, language)
    proxy_display = proxy if proxy else LANG[language]['no_proxy']
    print(f"{Fore.CYAN}🔄 {LANG[language]['using_proxy'].format(proxy=proxy_display, public_ip=public_ip)}{Style.RESET_ALL}")

    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])) as session:
                print(f"{Fore.CYAN}  > {LANG[language]['getting_csrf']}{Style.RESET_ALL}")
                
                headers = HEADERS.copy()
                
                async with session.get(
                    f"{API_BASE_URL}/auth/csrf",
                    headers=headers,
                    ssl=not CONFIG['BYPASS_SSL']
                ) as response:
                    if response.status != 200:
                        print(f"{Fore.RED}  ✖ Get CSRF failed: HTTP {response.status}{Style.RESET_ALL}")
                        if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                            await asyncio.sleep(CONFIG['RETRY_DELAY'])
                            continue
                        return False
                    
                    csrf_data = await response.json()
                    csrf_token = csrf_data.get("csrfToken")
                    print(f"{Fore.GREEN}  ✓ {LANG[language]['csrf_success']}{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}  > {LANG[language]['signing_message']}{Style.RESET_ALL}")
                
                message_dict = {
                    "domain": "hub.veerarewards.com",
                    "address": address,
                    "statement": "Sign in to the app. Powered by Snag Solutions.",
                    "uri": "https://hub.veerarewards.com",
                    "version": "1",
                    "chainId": 1,
                    "nonce": csrf_token,
                    "issuedAt": "2026-01-17T05:51:42.364Z"
                }
                
                message_text = f"{message_dict['domain']} wants you to sign in with your Ethereum account:\n{message_dict['address']}\n\n{message_dict['statement']}\n\nURI: {message_dict['uri']}\nVersion: {message_dict['version']}\nChain ID: {message_dict['chainId']}\nNonce: {message_dict['nonce']}\nIssued At: {message_dict['issuedAt']}"
                
                w3 = Web3()
                message = encode_defunct(text=message_text)
                signed_message = w3.eth.account.sign_message(message, private_key=private_key)
                signature = signed_message.signature.hex()
                if not signature.startswith('0x'):
                    signature = '0x' + signature
                
                print(f"{Fore.GREEN}  ✓ {LANG[language]['sign_success']}{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}  > {LANG[language]['logging_in']}{Style.RESET_ALL}")
                
                login_data = {
                    "message": json.dumps(message_dict),
                    "accessToken": signature,
                    "signature": signature,
                    "walletConnectorName": "MetaMask",
                    "walletAddress": address,
                    "redirect": False,
                    "callbackUrl": "/protected",
                    "chainType": "evm",
                    "walletProvider": "undefined",
                    "csrfToken": csrf_token,
                    "json": True
                }
                
                form_data = aiohttp.FormData()
                for key, value in login_data.items():
                    form_data.add_field(key, str(value))
                
                headers_login = headers.copy()
                headers_login['Content-Type'] = 'application/x-www-form-urlencoded'
                
                async with session.post(
                    f"{API_BASE_URL}/auth/callback/credentials",
                    data=form_data,
                    headers=headers_login,
                    ssl=not CONFIG['BYPASS_SSL']
                ) as response:
                    if response.status != 200:
                        print(f"{Fore.RED}  ✖ Login failed: HTTP {response.status}{Style.RESET_ALL}")
                        if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                            await asyncio.sleep(CONFIG['RETRY_DELAY'])
                            continue
                        return False
                    
                    cookies = session.cookie_jar.filter_cookies(response.url)
                    
                    print(f"{Fore.GREEN}  ✓ {LANG[language]['login_success']}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  - {LANG[language]['address']}: {address}{Style.RESET_ALL}")
                    print()
                
                print(f"{Fore.CYAN}  > {LANG[language]['getting_user_id']}{Style.RESET_ALL}")
                
                user_id = None
                try:
                    async with session.get(
                        f"{API_BASE_URL}/auth/session",
                        headers=headers,
                        ssl=not CONFIG['BYPASS_SSL']
                    ) as response:
                        if response.status == 200:
                            session_data = await response.json()
                            user_id = session_data.get('user', {}).get('id')
                            if user_id:
                                print(f"{Fore.GREEN}  ✓ {LANG[language]['user_id_success']}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}  ⚠ Get User ID error: {str(e)}{Style.RESET_ALL}")
                
                task_status = {}
                if user_id:
                    print(f"{Fore.CYAN}  > {LANG[language]['checking_status']}{Style.RESET_ALL}")
                    try:
                        status_url = f"{API_BASE_URL}/loyalty/rules/status?websiteId={WEBSITE_ID}&organizationId={ORGANIZATION_ID}&userId={user_id}"
                        async with session.get(
                            status_url,
                            headers=headers,
                            ssl=not CONFIG['BYPASS_SSL']
                        ) as response:
                            if response.status == 200:
                                status_data = await response.json()
                                for item in status_data.get('data', []):
                                    rule_id = item.get('loyaltyRuleId')
                                    status = item.get('status')
                                    task_status[rule_id] = status
                                print(f"{Fore.GREEN}  ✓ {LANG[language]['status_checked']}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}  ⚠ Check status error: {str(e)}{Style.RESET_ALL}")
                
                print()
                
                print(f"{Fore.CYAN}┌─ {LANG[language]['checkin_tasks_header']} ─────────────────────────────────────────{Style.RESET_ALL}")
                
                completed_tasks = []
                total_points_earned = 0
                
                for task in TASKS:
                    task_id = task['id']
                    task_name = task['name']
                    task_points = task['points']
                    
                    current_status = task_status.get(task_id, '')
                    if current_status == 'completed':
                        print(f"{Fore.GREEN}│ ✓ {task_name}: {LANG[language]['task_completed']} (+{task_points} {LANG[language]['points_earned']}){Style.RESET_ALL}")
                        completed_tasks.append(task_name)
                        total_points_earned += task_points
                        continue
                    
                    print(f"{Fore.CYAN}│ > {LANG[language]['completing_task']}: {task_name}...{Style.RESET_ALL}")
                    
                    try:
                        async with session.post(
                            f"{API_BASE_URL}/loyalty/rules/{task_id}/complete",
                            json={},
                            headers=headers,
                            ssl=not CONFIG['BYPASS_SSL']
                        ) as response:
                            if response.status == 200:
                                result = await response.json()
                                message = result.get('message', '')
                                
                                if 'queue' in message.lower():
                                    print(f"{Fore.YELLOW}│ ⚠ {task_name}: {LANG[language]['task_queued']} (+{task_points} {LANG[language]['points_earned']}){Style.RESET_ALL}")
                                elif 'verify' in message.lower() or 'later' in message.lower():
                                    print(f"{Fore.YELLOW}│ ⚠ {task_name}: {LANG[language]['task_verifying']} (+{task_points} {LANG[language]['points_earned']}){Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.GREEN}│ ✓ {task_name}: {LANG[language]['task_success']} (+{task_points} {LANG[language]['points_earned']}){Style.RESET_ALL}")
                                    completed_tasks.append(task_name)
                                    total_points_earned += task_points
                            else:
                                print(f"{Fore.YELLOW}│ ⚠ {task_name}: HTTP {response.status}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}│ ⚠ {task_name}: {str(e)}{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────{Style.RESET_ALL}")
                print()
                
                if completed_tasks:
                    print(f"{Fore.GREEN}  ✅ {LANG[language]['success'].format(address=address[:6]+'...'+address[-4:])}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  - {LANG[language]['tasks_to_complete']}: {', '.join(completed_tasks)}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  - {LANG[language]['points_earned']}: +{total_points_earned}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}  ⚠ {LANG[language]['all_completed']}{Style.RESET_ALL}")
                
                print()
                return True

        except Exception as e:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                delay = CONFIG['RETRY_DELAY']
                print(f"{Fore.RED}  ✖ {LANG[language]['failure'].format(error=str(e))}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  ℹ {LANG[language]['pausing']} {delay:.2f} {LANG[language]['seconds']}{Style.RESET_ALL}")
                await asyncio.sleep(delay)
                continue
            print(f"{Fore.RED}  ✖ {LANG[language]['failure'].format(error=str(e))}{Style.RESET_ALL}")
            return False
    return False

async def run_checkin(language: str = 'vi'):
    print()
    print_border(LANG[language]['title'], Fore.CYAN, language=language)
    print()

    proxies = load_proxies(language=language)
    print()

    private_keys = load_private_keys(language=language)
    print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_wallets'].format(count=len(private_keys))}{Style.RESET_ALL}")
    print()

    if not private_keys:
        return

    print_separator(language=language)
    random.shuffle(private_keys)
    print_wallets_summary(len(private_keys), language)

    total_interactions = 0
    successful_interactions = 0

    async def process_wallet(index, profile_num, private_key):
        nonlocal successful_interactions, total_interactions
        proxy = proxies[index % len(proxies)] if proxies else None
        
        async with semaphore:
            success = await veera_checkin(private_key, profile_num, proxy, language)
            total_interactions += 1
            if success:
                successful_interactions += 1
            if index < len(private_keys) - 1:
                print_message(f"{LANG[language]['pausing']} {CONFIG['DELAY_BETWEEN_ACCOUNTS']:.2f} {LANG[language]['seconds']}", Fore.YELLOW, language)
                await asyncio.sleep(CONFIG['DELAY_BETWEEN_ACCOUNTS'])

    semaphore = asyncio.Semaphore(CONFIG['THREADS'])
    tasks = [process_wallet(i, profile_num, key) for i, (profile_num, key) in enumerate(private_keys)]
    await asyncio.gather(*tasks, return_exceptions=True)

    print()
    print_border(
        LANG[language]['completed'].format(successful=successful_interactions, total=total_interactions),
        Fore.GREEN, language=language
    )
    print()

if __name__ == "__main__":
    asyncio.run(run_checkin('vi'))
