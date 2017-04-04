## Cryptocompare Melonport Module: Pricefeed

This repository contains the source code of the CryptoCompare price feed smart contract designed to work as a module for the Melonport's Melon protocol.

The contract is now live on Kovan: https://kovan.etherscan.io/address/0x3B8fF409268480c41661a8757b89aAC04d0409dC 

It continuously fetches data from the CryptoCompare WebAPIs through Oraclize to provide on-chain references of the BTC, EUR, REP, MLN exchange rates against ETH. Compared to the existing Oraclize module, you get the benefit of having the data aggregated over all the trading exchanges. It would be a lot more expensive and harder to keep up to date if you had to aggregate the data on-chain. Also, it includes price information for more pairs and is easily extendable to fetch a lot more information if needed.

Prices are being updated every 5 minutes. Our contract leverages the new Oraclize Native Proof, which enables us to sign the data provided through our WebAPIs using the HTTP Signatures specifications. The smart contract can then verify the signature over the data using the data source public key, which is stored in the contract. If the signature verifies, the data can be consumed and the prices are updated. We have done this because it allows us to guarantee the integrity of the data and confidently use it in the smart contract.

The contract was designed by following the template interface proposed by the Melonport team. Compatibility with the Melon protocol is guaranteed.

This module would not have been possible without the amazing support we received from the Oraclize & Melonport teams!
