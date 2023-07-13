# BittensorWallet - v0.0.4

BittensorWallet is a library for managing wallet keypairs, keyfiles, etc. for the [Bittensor Python API](https://github.com/opentensor/bittensor).  

The purpose of this repo is to separate the concern of keyfile management from the https://github.com/opentensor/bittensor repo, to decrease the attack surface of Bittensor related to local keys and wallet functionality.  

# Installation
This package can be installed from [PyPi.org](https://pypi.org/project/bittensor-wallet/):
```bash
pip install bittensor-wallet==0.0.4
```
or via this repo (using [gh-cli](https://cli.github.com/)):  
```bash
gh repo clone opentensor/bittensor-wallet
cd bittensor-wallet
pip install -e .
```


