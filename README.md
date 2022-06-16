# SmartMuv

[SmartMuv](www.smartmuv.app) is a smart contract analysis and extraction tool written in Python 3. SmartMuv can extract complete state of the smart contract and can help users to analyze, migrate and upgrade their smart contracts. As, Solidity does not keep track of keys of mapping variables, SmartMuv uses static time source code analysis techniques to perform key approximation analysis for mapping variables. Our tool can handle regular variables as well as user-defined variables and can automatically extract their values.

## System Requirements

- Linux Distribution
- Python 3.x

## Clone the project

```
git clone https://github.com/WaizKhan7/SmartMuv.git
```

## Installing Dependencies

### Global dependencies

Smartmuv needs Python version 3 to run, and other Python packages that can be installed with the following commands.

```
sudo apt install -y python3-pip
pip3 install slither-analyzer==0.6.0
pip3 install solidity-parser
pip3 install web3
pip3 install hexbytes
```
SmartMuv uses `solc` to generate smart contract `ABI`, it can be installed with the following commands:

```
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

 The current version of the `solc` compiler should be same as smart contract source code Solidity version. `solc` version can be managed by `solc-select` tool. It can be installed with the following command:

```
pip3 install solc-select
```

## Configuration

SmartMuv uses `infura` archive node to access smart contract storage, and Etherscan `API` to get smart contract transaction. API keys for infura and Etherscan needs to be added on `config.ini` file for the tool to work.

## Running Script

You can run the SmartMuv with the following command on the provided example smart contracts:

```
python3 -m src.smartmuv
```

Select the smart contract from the provided list, and SmartMuv will extract and return the complete state and current block number. 

## Sample Output

```
['owner', 'address', '0x00000000000000000000000020b767115d0e2a23ca52ae3d7b87af61d4af5943', 20]
['newOwner', 'address', '0x0000000000000000000000000000000000000000000000000000000000000000', 20]
['symbol', 'string', '1ai', 32]
['name', 'string', 'Indoaset', 32]
['decimals', 'uint8', 18, 1]
['_totalSupply', 'uint', 20000000000000000000000000000, 32]
['balances:key:0x0358C107D0064d72Aa9040f7B6DAb92250C164F4', 'uint', 19998000000000000000000000000, 32]
['balances:key:0x0358c107d0064d72aa9040f7b6dab92250c164f4', 'uint', 19998000000000000000000000000, 32]
['balances:key:0x07CFcbEC279F57DEC79D0846815E0CCE682F7747', 'uint', 2000000000000000000000000, 32]
```

## Bugs Detection

```
python3 -m tests.ast_parsing_test
python3 -m tests.slot_analysis_test
python3 -m tests.key_approx_analysis_test
python3 -m tests.state_extraction_test
```

## Features and Uses

- Smart Contract Storage Analysis
- Smart Contract Slot Calculation
- Smart Contract State Extraction
- Smart Contract State Packing
- Smart Contract Upgrade
