import json
from typing import List, Dict, Any


class SarifReporter:
    """
    Exports Model Red-Teaming audit results into standard SARIF (Static Analysis Results Interchange Format) v2.1.0.
    """

    def __init__(self, run_results: List[Dict[str, Any]]):
        self.run_results = run_results

    def generate_sarif(self) -> Dict[str, Any]:
        rules = []
        results = []

        seen_rules = set()
        for res in self.run_results:
            rule_id = res.get("category", "ADVERSARIAL_PROMPT").upper()
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": rule_id.replace("_", " ").title(),
                    "shortDescription": {"text": f"Adversarial safety test: {rule_id}"},
                    "defaultConfiguration": {"level": "error"}
                })

            if not res.get("passed", True):
                results.append({
                    "ruleId": rule_id,
                    "message": {"text": f"Safety boundary failure: {res.get('vector_id', 'TEST')}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"vectors/{rule_id.lower()}.json"}
                        }
                    }]
                })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Model-Redteam-Atlas",
                        "informationUri": "https://github.com/jatinsihag2345/model-redteam-atlas",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
