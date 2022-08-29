# Potential Malicious Contracts Monitor Agent

## Description

This agent will look for potentially malicious contracts

## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- POTENTIAL-MALICIOUS-CONTRACTS
  - Fired when a new contract is created by an account that was funded by tornado cash
  - - Type is always set to "High"

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed (15,000 USDT)
