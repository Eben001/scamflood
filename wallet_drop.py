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

ua = UserAgent()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True,
    handlers=[
        logging.FileHandler("logs_wallet_drop.log"),
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


async def send_request():
    
    user_agent = ua.random
    mnemonic_phrase = generate_mnemonic()
    logger.info(f"Mnemonic Phrase: {mnemonic_phrase}")


    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://piwalletdrop.com",
        "pragma": "no-cache",
        "priority": "u=0, i",
        "referer": "https://piwalletdrop.com/",
        "sec-ch-ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": user_agent,
    }

    data = {
        "form_message": mnemonic_phrase,
    }

    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(
                "https://pimmytest.buzz/test/exfffm564ail.php",
                headers=headers,
                data=data,
                impersonate="chrome",
            )
            soup = BeautifulSoup(response.text, "lxml")
            try:
                title_tag = soup.find('title', string=lambda text: text and "Just a moment" in text)
                if title_tag:
                    return "Success"
            except: 
                logger.info("The text was not found.")
                return None
            
        except (
            CurlTimeout,
            ssl.SSLError,
            CurlConnectionError,
            CurlProxyError,
            CurlSSLError,
            CurlHTTPError,
            curl_cffi.curl.CurlError
        ) as e:
            logger.exception(
                f"Error while trying to send request on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise


async def main():
    while True:
        result = await send_request()
        logger.info(f"Result: {result}")
        logger.info('\n')


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Graceful shutdown completed.")

