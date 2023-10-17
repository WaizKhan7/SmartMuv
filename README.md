# SmartMuv
[SmartMuv](https://www.smartmuv.app) is a smart contract analysis and extraction tool written in Python 3. SmartMuv extracts the complete state of the smart contract and enables users to upgrade or migrate their smart contracts across any EVM-compatible blockchain. SmartMuv can also be used for smart contract state tracking or retrieving smart contract's state (i.e. holders list or entries list of any data type like mapping, arrays, etc.) until a specific block number.

As Solidity does not keep track of keys of mapping variables, SmartMuv uses static time source code analysis techniques to perform key approximation analysis on mapping variables. It analyzes the complete layout of a smart contract and can extract not only regular variables but also complex variables (i.e. mappings and multi-dimensional arrays) and user-defined variables.

## System Requirements

- Linux Distribution
- Python 3.x

## Clone the project

```
git clone https://github.com/WaizKhan7/SmartMuv.git
```

## Install

#### Install Dependencies

You can install all the required packages with the following command:

```
python3 setup.py install
```

#### Install Solidity Compilers

You can install all the required Solidity compilers with the following command:

```
python3 install_compilers.py
```

## Configuration

SmartMuv uses EVM-compatible Blockchain `RPC` URL for state extraction, and block explorer `APIs` i.e. EtherScan, PolygonScan, BscScan, etc., to get smart contract transactions. API keys and URLs for RPC and Block explorers need to be added to the `config.ini` file for the tool to work properly.

## Running Script

You can run SmartMuv with the following command on the provided example smart contracts:

```
python3 -m try_smartmuv
```

Select the smart contract from the provided list, and SmartMuv will analyze and extract its complete state. 

```
1   0xc9ae11a393a08e86d46ce683fde7699db01a5f15   AUX1769
2   0x51bb7917efcad03ec8b1d37251a06cd56b0c4a72   DSRCoin
3   0x24dd6e1fe742bd8fd3a1d144fece1680f16296aa   OBK
4   0x143e685dd51d467d77663a3be119217185d81b99   CommunityBankCoin
5   0x145f9bbd9f1ca0923e81e05c2ac04fda2310d774   VACCToken

Select contract no from above to run SmartMuv -> 
```

To run SmartMuv on Solidity smart contract of your choice, add the contract details in the `smartmuv.py` file and run:

```
python3 -m smartmuv
```
**Note:** Add the source code of your project to 'CONTRACT_DIRECTORY' path specified in `config.ini` file. The code file should contain all the code without any `import` statement.
## Sample Outputs

#### Extracted State

**[Name, Type, Value, Size (Bytes), Slot Number]**

```
['owner', 'address', '0xb520de5470c80d57f7005d3b771af675ad311f91', 20, '0x0']
['totalSupply', 'uint256', 100000000000000000, 32, '0x1']
['decimals', 'uint8', 6, 1, '0x2']
['name', 'string', 'Community Decentralized Banking>', 32, '0x3']
['symbol', 'string', 'CMD', 32, '0x4']
['tokenIsFrozen', 'bool', 'False', 1, '0x5']
['tokenMintingEnabled', 'bool', 'False', 1, '0x5']
['contractLaunched', 'bool', 'False', 1, '0x5']
['stakingStatus', 'bool', 'False', 1, '0x5']
['balances:key:0xb520de5470c80d57f7005d3b771af675ad311f91', 'uint256', 99000000000000000, 32, '0x4fa3db652fe4fb0b4583b73847299fbd568219c49826e6778a89ecc882273865']
['balances:key:0x5b7b3ccfc5a89caf6a459627029dc1e1255ee360', 'uint256', 999998994679681, 32, '0xb500fc54d70185966c1ff1538715017b5b6b324727f02becd41481a337bcf77a']
['balances:key:0x642481c0d64f1d8a06da621599b9d64cf41740b8', 'uint256', 2023908, 32, '0xb930fddb7465b82ccbad649c33609aafcf74f4f0763fcd3609a15183bb6e2d8e']
['balances:key:0x4a30f1974Ff2338C4d8f8Eb2f7FE11353FE6f71d', 'uint256', 3296411, 32, '0xffb44d017dc752df1a3231eb81905c9cac26214ade36e0a2a3bc72fcdcbef740']
['balances:key:0x38BC418476D274900167f33e2098A86aB01b96Af', 'uint256', 1000000000, 32, '0x430d203e4eb0ef42503559f8c2f4410eef444da81d0b910d2c40ed75d9c2f34a']
```

#### Slot Layout

```
slot 0 - mapping balances[address] = uint256;
slot 1 - mapping allowed[address][address] = uint256;
slot 2 - uint256 totalSupply;
slot 3 - string name;
slot 4 - uint8 decimals;
slot 5 - string symbol;
```

## Tests

```
python3 -m tests.test_ast_parsing
python3 -m tests.test_slot_analysis
python3 -m tests.test_key_approx_analysis
python3 -m tests.test_state_extraction
```

## Features and Uses

- **Slot Analysis of a smart contract**, to get a complete storage layout of a smart contract.
- Smart contract **storage audit**.
- Smart contract complete **state indexing for blockchain explorer platforms**.
- **State extraction (snapshot)** of smart contracts.
- **Redeployment/upgrade of smart contracts** along their existing state/data.
- **Migration of smart contracts** along with contract data i.e. L1 to L2 or L2 to L2 migrations.
  

## Publications

- [Storage State Analysis and Extraction of Ethereum Blockchain Smart Contracts](https://dl.acm.org/doi/10.1145/3548683), Maha Ayub, Tania Saleem, Muhammad Janjua, Talha Ahmad - TOSEM '23

## Contact Us

In case of any query, you can email us at help@smartmuv.app
