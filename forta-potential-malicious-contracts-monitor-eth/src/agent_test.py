from forta_agent import create_transaction_event, FindingSeverity
import agent
from findings import SuspiciousContractFindings
from constants import TORNADO_CASH_ADDRESSES, EOA_ADDRESS


class TestSuspiciousContractAgent:
    def test_update_tornado_cash_funded_accounts(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        agent.update_tornado_cash_funded_accounts(tx_event)
        assert EOA_ADDRESS in agent.TORNADO_CASH_FUNDED_ACCOUNTS, "this address was just funded by tornado cash"

    def test_calc_contract_address(self):
        contract_address = agent.calc_contract_address(EOA_ADDRESS, 9)
        assert contract_address == "0x728ad672409DA288cA5B9AA85D1A55b803bA97D7", "should be the same contract address"

    def test_finding_tornado_cash_and_contract_creation(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 },
                 {'type': 'create',
                 'action': {
                     'from': EOA_ADDRESS,
                     'value': 1,
                 }
                 }
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(tx_event)
        assert len(findings) == 1, "this should have triggered a finding"
        finding = next((x for x in findings if x.alert_id == 'POTENTIAL-MALICIOUS-CONTRACTS'), None)
        assert finding.severity == FindingSeverity.High


    def test_finding_tornado_cash_and_no_contract_creation(self):
        agent.initialize()

        tx_event = create_transaction_event({
            'transaction': {
                'hash': "0",
                'from': EOA_ADDRESS,
                'nonce': 10,
            },
            'block': {
                'number': 0
            },
            'traces': [
                {'type': 'call',
                 'action': {
                     'to': EOA_ADDRESS,
                     'from': TORNADO_CASH_ADDRESSES[0],
                     'value': 1,
                 }
                 },
            ],
            'receipt': {
                'logs': []}
        })
        findings = agent.detect_suspicious_contract_creations(tx_event)
        assert len(findings) == 0, "this should not have triggered a finding"


    def test_finding_not_tornado_cash_and_no_contract_creation(self):
        agent.initialize()

        finding = SuspiciousContractFindings.suspicious_contract_creation_tornado_cash("from_address", "contract_address", "0x12345")
        print(finding)
        assert finding.severity == FindingSeverity.High
        assert len(finding.metadata)>0
