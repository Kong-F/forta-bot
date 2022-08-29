# Contract Creation Monitor Agent

## Description

The bot will monitor all new contract creations

## Supported Chains

- Ethereum
- Polygon
- Binance Smart Chain
- Avalanche
- Arbitrum
- Optimism
- Fantom

## Alerts

Describe each of the type of alerts fired by this agent

- CONTRACT-CREATION-MONITOR
  - Fired when a new contract is created
  - Type is always set to "info"
  - Metadata will contain creator address, created contract address, network and transaction hash

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed
