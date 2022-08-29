from forta_agent import Finding, FindingType, FindingSeverity


class SuspiciousContractFindings:

    @staticmethod
    def suspicious_contract_creation_tornado_cash(from_address: str, contract_address: str, transaction_hash: str) -> Finding:
        return Finding({
            'name': 'Potential Malicious Contracts Monitor',
            'description': f'{from_address} created contract {contract_address}',
            'alert_id': 'POTENTIAL-MALICIOUS-CONTRACTS',
            'type': FindingType.Suspicious,
            'severity': FindingSeverity.High,
            'metadata': {
                'creator': from_address,
                'contract': contract_address,
                'tx_hash': transaction_hash
            }
        })