import forta_agent
import rlp
from web3 import Web3

from src.constants import (TORNADO_CASH_ADDRESSES,
                           TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE)
from src.findings import SuspiciousContractFindings

TORNADO_CASH_FUNDED_ACCOUNTS = []


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global TORNADO_CASH_FUNDED_ACCOUNTS
    TORNADO_CASH_FUNDED_ACCOUNTS = []


def detect_suspicious_contract_creations(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global TORNADO_CASH_FUNDED_ACCOUNTS

    findings = []

    update_tornado_cash_funded_accounts(transaction_event)

    created_contract_addresses = []
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):

                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1  # for contracts creating other contracts, the nonce would be 1
                created_contract_address = calc_contract_address(trace.action.from_, nonce)

                created_contract_addresses.append(created_contract_address.lower())

                if Web3.toChecksumAddress(trace.action.from_) in TORNADO_CASH_FUNDED_ACCOUNTS:
                    TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(created_contract_address))  # needed in case the contract creates another contract

                    findings.append(SuspiciousContractFindings.suspicious_contract_creation_tornado_cash(trace.action.from_, created_contract_address, transaction_event.transaction.hash))
    return findings


def calc_contract_address(address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def update_tornado_cash_funded_accounts(transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    this function maintains a list of tornado cash funded accounts; holds up to TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE in memory
    :return: None
    """

    global TORNADO_CASH_FUNDED_ACCOUNTS

    for trace in transaction_event.traces:
        if trace.action.value is not None and trace.action.value > 0 and Web3.toChecksumAddress(trace.action.from_) in TORNADO_CASH_ADDRESSES:
            TORNADO_CASH_FUNDED_ACCOUNTS.append(Web3.toChecksumAddress(trace.action.to))
            if len(TORNADO_CASH_FUNDED_ACCOUNTS) > TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
                TORNADO_CASH_FUNDED_ACCOUNTS.pop(0)


def provide_handle_transaction():
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_suspicious_contract_creations(transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction()


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)