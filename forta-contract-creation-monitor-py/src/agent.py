# ref: https://github.com/forta-network/starter-kits/blob/main/suspicious-contract-creation-py
import rlp
import forta_agent
from web3 import Web3
from forta_agent import Finding, FindingType, FindingSeverity


def calc_contract_address(address, nonce) -> str:
    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def detect_contract_creations(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []
    created_contract_addresses = []
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):
                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1
                created_contract_address = calc_contract_address(trace.action.from_, nonce)
                created_contract_addresses.append(created_contract_address.lower())
                findings.append(Finding({
                    'name': 'Contract-Creation',
                    'description': f'{trace.action.from_} created contract {created_contract_address}',
                    'alert_id': 'CONTRACT-CREATION-MONITOR',
                    'type': FindingType.Info,
                    'severity': FindingSeverity.Info,
                    'metadata': {
                        'creator': trace.action.from_,
                        'contract': created_contract_address,
                        'network': transaction_event.network,
                        'tx_hash': transaction_event.transaction.hash
                    }
                }))
    return findings


def provide_handle_transaction():
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_contract_creations(transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction()


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)