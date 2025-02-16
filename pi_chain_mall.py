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
import requests
from requests.exceptions import (
    ConnectionError,
    Timeout,
    HTTPError,
    ProxyError,
    SSLError,
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
        logging.FileHandler("logs_pi_chain_mall.log"),
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


async def send_payload(max_sleep_time=300):
    mnemonic_phrase = generate_mnemonic()
    logger.info(f"Mnemonic Phrase: {mnemonic_phrase}")
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    user_agent = ua.random
    headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Origin': 'https://gde8wa-0x.myshopify.com',
    'Pragma': 'no-cache',
    'Referer': 'https://gde8wa-0x.myshopify.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'cross-site',
    'User-Agent': user_agent,
    'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
}

    
    files = {
        'data': (None, f'[{{"name":"gjpFrg8vxCjX","value":"{mnemonic_phrase}","required":true,"type":"Paragraph","label":"e.g. alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray"}}]'),
        'project_id': (None, '22081504'),
        'form_id': (None, 'i1ACTtUXvpaD'),
    }
    
    
    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = requests.post('https://msg.formsender.online/form/submit', headers=headers, files=files, proxies=proxies, timeout=120)

            if response.status_code == 200:
                try:
                   return response.text
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
            ConnectionError,
            ProxyError, 
            SSLError,
            HTTPError, 
            Timeout,
        ) as e:
            logger.exception(
                f"Error while trying to send payload on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                pass


async def main():
    while True:
        result = await send_payload()
        logger.info(f"Result: {result}")
        logger.info('\n')


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Graceful shutdown completed.")


