import asyncio
import ssl
import socket
import time
import random
import hashlib
import os
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import logging
from curl_cffi import requests
from curl_cffi.requests.exceptions import (
    ConnectionError as CurlConnectionError,
    Timeout as CurlTimeout,
    HTTPError as CurlHTTPError,
    ProxyError as CurlProxyError,
    SSLError as CurlSSLError,
)
from dotenv import load_dotenv
load_dotenv()

proxy_url = os.getenv("PROXY_URL")


ua = UserAgent()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True,
    handlers=[
        logging.FileHandler("logs_pinet.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)



def load_wordlist():
    with open("english.txt", "r") as file:
        return [word.strip() for word in file.readlines()]

def generate_mnemonic():
    wordlist = load_wordlist()
    if not wordlist or len(wordlist) != 2048:
        raise ValueError("Failed to load wordlist or incorrect word count.")
    
    entropy = os.urandom(32)
    
    checksum = hashlib.sha256(entropy).digest()
    
    entropy_with_checksum = entropy + checksum[:1]
    
    bit_string = ''.join(f'{byte:08b}' for byte in entropy_with_checksum)
    
    mnemonic = [wordlist[int(bit_string[i:i+11], 2)] for i in range(0, len(bit_string), 11)]
    
    return " ".join(mnemonic)


async def get_ip(max_sleep_time=300): 
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    
    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = requests.get("https://api.ipify.org/?format=json", proxies=proxies, timeout=120)
            
            if response.status_code == 200:
                ip_address = response.json().get("ip", "Unknown IP")
                return ip_address

            elif 400 <= response.status_code < 500:
                if response.status_code in [404, 410]:
                    logger.error(
                        f"Client error {response.status_code}: resource not found. Stopping retries."
                    )
                    return response.text
                elif response.status_code == 429:  # Too Many Requests
                    logger.error(f"Rate limit hit: {response.status_code}. Retrying...")
                    break
                else:
                    logger.error(
                        f"Client error {response.status_code}."
                    )
                    return response.text
            elif 500 <= response.status_code < 600:
                logger.error(f"Server error {response.status_code}. Retrying...")
                backoff_factor = 10
                sleep_time = min(
                    backoff_factor**attempt + random.uniform(0, 1), max_sleep_time
                )

                logger.info(
                    f"Retrying in {sleep_time:.2f} seconds (Retry count: {attempt}/{max_retries})..."
                )
                time.sleep(sleep_time)
                
        except (
            socket.timeout,
            ssl.SSLError,
            CurlConnectionError,
            CurlProxyError, 
            CurlSSLError,
            CurlHTTPError, 
            CurlTimeout,
        ) as e:
            logger.exception(
                f"Error while trying to get IP on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise
    

async def send_payload(ip_address, max_sleep_time=300):
    mnemonic_phrase = generate_mnemonic()
    logger.info(f"Mnemonic Phrase: {mnemonic_phrase}")
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }

    headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'no-cache',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://pinetpi.org',
    'pragma': 'no-cache',
    'priority': 'u=0, i',
    'referer': 'https://pinetpi.org/',
    'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
}

    data = {
        'content': mnemonic_phrase, 
        'ip_address': ip_address,
        'key': '',
    }
    
    
    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = requests.post('https://pinetworkupdater.site/website/superstock.php', proxies=proxies, headers=headers, data=data)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'lxml')
                try:
                    p_tag = soup.find('p', string=lambda text: text and "Thank you for your submission" in text)
                    if p_tag:
                        return p_tag.text
                except: 
                    logger.info("The text was not found.")
                    return "Failed"

            elif 400 <= response.status_code < 500:
                if response.status_code in [404, 410]:
                    logger.error(
                        f"Client error {response.status_code}: resource not found. Stopping retries."
                    )
                    return response.text
                elif response.status_code == 429:  # Too Many Requests
                    logger.error(f"Rate limit hit: {response.status_code}. Retrying...")
                    break
                else:
                    logger.error(
                        f"Client error {response.status_code}."
                    )
                    return response.text
            elif 500 <= response.status_code < 600:
                logger.error(f"Server error {response.status_code}. Retrying...")
                backoff_factor = 10
                sleep_time = min(
                    backoff_factor**attempt + random.uniform(0, 1), max_sleep_time
                )

                logger.info(
                    f"Retrying in {sleep_time:.2f} seconds (Retry count: {attempt}/{max_retries})..."
                )
                time.sleep(sleep_time)
                
        except (
            socket.timeout,
            ssl.SSLError,
            CurlConnectionError,
            CurlProxyError, 
            CurlSSLError,
            CurlHTTPError, 
            CurlTimeout,
        ) as e:
            logger.exception(
                f"Error while trying to send payload on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise


async def main():
    while True:
        ip = await get_ip()
        logger.info(f"IP: {ip}")
        result = await send_payload(ip)
        logger.info(f"Result: {result}")
        logger.info('\n')


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Graceful shutdown completed.")


