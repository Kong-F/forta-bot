import rlp
import forta_agent
from web3 import Web3
from forta_agent import Finding, FindingType, FindingSeverity


def detect_contract_creations(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []
    
    tx = transaction_event.transaction
    if (len(transaction_event.contract_address) > 0):
        findings.append(Finding({
            'name': 'New Contract',
            'description': f'{tx.from_} created contract {transaction_event.contract_address}',
            'alert_id': 'NEW-CREATION-MONITOR',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {
                'creator': tx.from_,
                'contract': transaction_event.contract_address,
                'network': transaction_event.network,
                'tx_hash': tx.hash
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