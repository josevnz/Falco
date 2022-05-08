#!/usr/bin/env python3
"""
Show brief content of default Falco rule YAML files
Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
from argparse import ArgumentParser
from pathlib import Path
from rich.console import Console
import yaml
from falcotutor.ui import create_rules_table, add_rows_to_create_rules_table, RulesDisplayApp


def load_rulez(falco_rulez: Path) -> dict[any, any]:
    rulez = {}
    with open(falco_rulez, 'rt') as falco_file:
        for rule_data in yaml.full_load(falco_file):
            if 'rule' in rule_data:
                rule_name = rule_data['rule']
                del rule_data['rule']
                rulez[rule_name] = rule_data
    return rulez


if __name__ == "__main__":
    CONSOLE = Console()
    AGGREGATED = {}
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument(
        "falco_rules",
        action="store"
    )
    ARGS = PARSER.parse_args()
    try:
        RULES = load_rulez(ARGS.falco_rules)
        RULE_TBL = create_rules_table()
        add_rows_to_create_rules_table(lrules=RULES, rules_tbl=RULE_TBL)
        RulesDisplayApp.run(
            rules_file=ARGS.falco_rules,
            title="Falco brief rule display",
            rules_table=RULE_TBL
        )
    except KeyboardInterrupt:
        CONSOLE.print("[bold]Program interrupted...[/bold]")
