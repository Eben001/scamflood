from bs4 import BeautifulSoup
import asyncio
import socket
import ssl
import logging
import time
import random
import hashlib
import os
import curl_cffi
from curl_cffi.requests.exceptions import (
    ConnectionError as CurlConnectionError,
    Timeout as CurlTimeout,
    HTTPError as CurlHTTPError,
    ProxyError as CurlProxyError,
    SSLError as CurlSSLError,
    RequestException as CurlRequestException,
)
from curl_cffi import requests, CurlMime
from fake_useragent import UserAgent
from dotenv import load_dotenv
load_dotenv()

proxy_url = os.getenv("PROXY_URL")


ua = UserAgent()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True,
    handlers=[
        logging.FileHandler("logs_pi_mainnet.log"),
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

    bit_string = "".join(f"{byte:08b}" for byte in entropy_with_checksum)

    mnemonic = [
        wordlist[int(bit_string[i : i + 11], 2)] for i in range(0, len(bit_string), 11)
    ]

    return " ".join(mnemonic)


async def send_payload(max_sleep_time = 300):
    
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    mnemonic_phrase = generate_mnemonic()
    user_agent = ua.random

    logger.info(f"Mnemonic Phrase: {mnemonic_phrase}")
    
    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        # 'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryqtAU2ZMNNIOIJ1to',
        'origin': 'https://pimainnet.minev2.org',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pimainnet.minev2.org/x-trend%20pi%20site/wallet2',
        'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': user_agent,
        'x-requested-with': 'XMLHttpRequest',
    }
    mp = CurlMime()
    mp.addpart(name="message", data=mnemonic_phrase)



    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(
                'https://pimainnet.minev2.org/x-trend%20pi%20site/api/verify',
                headers=headers,
                multipart=mp,
                impersonate='chrome',
                proxies=proxies,
                # debug=True,
            )

            if response.status_code == 200:
                logger.info(f"Response Status Code: {response.status_code}")
                try:
                    return response.json()
                except Exception as e:
                    logger.error(f"Failed to parse JSON response: {e}")
                    return None

            elif 400 <= response.status_code < 500:
                if response.status_code in [404, 410]:
                    logger.error(
                        f"Client error {response.status_code}: resource not found. Stopping retries."
                    )
                    return None
                elif response.status_code == 429:  # Too Many Requests
                    logger.error(f"Rate limit hit: {response.status_code}. Retrying...")
                    break
                else:
                    logger.error(
                        f"Client error {response.status_code}."
                    )
                    return None
                
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
            curl_cffi.curl.CurlError,
            socket.timeout,
            ssl.SSLError,
            CurlConnectionError,
            CurlProxyError, 
            CurlSSLError,
            CurlHTTPError, 
            CurlTimeout,
            CurlRequestException,
        ) as e:
            logger.exception(
                f"Error while trying to prepare request on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise



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

