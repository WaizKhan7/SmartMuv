from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="smartmuv",
    description="An EVM-compatible Solidity smart contract state analysis and extraction tool.",
    url="https://github.com/waizkhan7/smartmuv",
    author="NextKore",
    version="0.2.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "packaging",
        "crytic-compile>=0.3.3,<0.4.0",
        "web3>=6.0.0",
        "eth-abi>=4.0.0",
        "eth-typing>=3.0.0",
        "eth-utils>=2.1.0",
        "slither-analyzer>=0.9.0",
        "solc-select>=1.0.4",
        "py-solc-x>=1.1.1",
        "solidity-parser>=0.1.1",
        "hexbytes>=0.2.2",
    ],
    license="GNU-3.0",
    long_description=long_description,
    long_description_content_type="text/markdown"
    )