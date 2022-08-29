import agent
from forta_agent import create_transaction_event, FindingSeverity


class TestContractCreationAgent:
    def test_calc_contract_address(self):
        contract_address = agent.calc_contract_address("0x81245e489cf1e02e38a83c2b9618826747410c50", 12)
        assert contract_address == "0x2320A28f52334d62622cc2EaFa15DE55F9987eD9", "should be the same contract address"

    
    def test_contract_creation(self):

        tx_event = create_transaction_event({
            'network': 1,
            'transaction': {
                'hash': "0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed",
                'from': "0x81245e489cf1e02e38a83c2b9618826747410c50",
                'nonce': 12,
            },
            'block': {
                'number': 0
            },
            'traces': [
                 {'type': 'create',
                 'action': {
                     'from': "0x81245e489cf1e02e38a83c2b9618826747410c50",
                     'value': 0,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_contract_creations(tx_event)
        assert len(findings) == 1, "this should not have triggered a finding"
        finding = next((x for x in findings if x.alert_id == 'CONTRACT-CREATION-MONITOR'), None)
        print(finding.__dict__)
        assert finding.severity == FindingSeverity.Info