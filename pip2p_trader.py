from bs4 import BeautifulSoup
import asyncio
import socket
import ssl
import logging
import time
import random
import hashlib
import os
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
        logging.FileHandler("logs_pip2p_trader.log"),
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


async def prepare_request(session, max_sleep_time=300):

    mnemonic_phrase = generate_mnemonic()

    logger.info(f"Mnemonic Phrase: {mnemonic_phrase}")

    params = {
        "a": "support",
    }

    data = {
        "form_id": "17396548433081",
        "form_token": "6ce7c8a1cba00e94c71a0d68c9e1aeeb",
        "a": "support",
        "action": "send",
        "name": "New Pi Logs",
        "email": "demo@gmail.com",
        "message": mnemonic_phrase,
    }

    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = session.post(
                "https://pip2ptrader.com",
                params=params,
                data=data,
                impersonate="chrome",
            )

            if response.status_code == 200:
                logger.info(f"Response Status Code: {response.status_code}")
                return

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
                    logger.error(f"Client error {response.status_code}.")
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
                f"Error while trying to prepare request on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise


async def send_request(session, max_sleep_time=300):

    params = {
        "a": "support",
        "say": "send",
    }

    max_retries = 10
    for attempt in range(max_retries + 1):
        try:
            response = session.post(
                "https://pip2ptrader.com/", params=params, impersonate="chrome"
            )

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "lxml")
                try:
                    p_tag = soup.find(
                        "p",
                        string=lambda text: text and "Please provide a valid" in text,
                    )
                    if p_tag:
                        return p_tag.text
                except:
                    logger.info(
                        "The text 'Please provide a valid 24-word phrase' was not found."
                    )
                    return

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
                    logger.error(f"Client error {response.status_code}.")
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
                f"Error while trying to send request on attempt {attempt}: {e}. Retrying..."
            )
            if attempt == max_retries:
                logger.error("Max retries exceeded. Download failed.")
                raise


async def main():
    while True:
        session = requests.Session()
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        session.proxies.update(proxies)
        user_agent = ua.random
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "priority": "u=0, i",
            "referer": "https://pip2ptrader.com/?a=support",
            "sec-ch-ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": user_agent,
        }
        session.headers.update(headers)
        await prepare_request(session)
        response_text = await send_request(session)
        logger.info(f"Response Body: {response_text}")
        logger.info("\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Graceful shutdown completed.")
