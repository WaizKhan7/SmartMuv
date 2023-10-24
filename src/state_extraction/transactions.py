import requests
from configparser import ConfigParser

config = ConfigParser()
config.read("config.ini")
tx_limit = int(config.get('transactions', 'tx_limit'))


def get_transactions(cont_addr, transactions, endpoint, api_key):
    page = 1
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    while len(transactions) < tx_limit:
        try:
            response = requests.get(endpoint.format(cont_addr, page, api_key), headers=headers).json()
            if response["status"] == "1":
                txs = response["result"]
                if len(txs) == 0:
                    break
                transactions.extend(txs)
                page += 1
            else:
                # print(response["message"])
                break
        except requests.exceptions.RequestException as e:
            print("Error occurred:", e)
            break
    print(f"Total transactions downloaded: {len(transactions)}")
    return transactions


def get_internal_transactions(cont_addr, transactions, endpoint, api_key):
    page = 1
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    while len(transactions) < tx_limit:
        try:
            response = requests.get(endpoint.format(cont_addr, page, api_key), headers=headers).json()
            if response["status"] == "1":
                txs = response["result"]
                if len(txs) == 0:
                    break
                transactions.extend(txs)
                page += 1
            else:
                # print(response["message"])
                break
        except requests.exceptions.RequestException as e:
            print("Error occurred:", e)
            break
    print(f"Total internal txs downloaded: {len(transactions)}")
    return transactions
