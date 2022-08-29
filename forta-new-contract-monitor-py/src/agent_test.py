import agent
from forta_agent import create_transaction_event, FindingSeverity


class TestContractCreationAgent:
    def test_new_contract(self):

        tx_event = create_transaction_event({
            'network': 56,
            'contract_address': '0x2320A28f52334d62622cc2EaFa15DE55F9987eD9',
            'transaction': {
                'hash': "0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed",
                'from': "0x81245e489cf1e02e38a83c2b9618826747410c50",
                'to': "0x0000000000000000000000000000000000000000",
                'nonce': 12,
                'data': '0x123'
            },
            'block': {
                'number': 0
            },
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_contract_creations(tx_event)
        assert len(findings) == 1, "this should not have triggered a finding"
        finding = next((x for x in findings if x.alert_id == 'NEW-CREATION-MONITOR'), None)
        print(finding.__dict__)
        assert finding.severity == FindingSeverity.Info