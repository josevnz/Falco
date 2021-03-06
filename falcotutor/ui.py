from pathlib import Path

from rich.traceback import install
from rich import pretty

from rich.table import Table
from textual.app import App
from textual.widgets import ScrollView

pretty.install()
install(show_locals=True)


class EventDisplayApp(App):

    def __init__(
            self,
            *args,
            event_file: Path,
            event_table: Table,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.body = None
        self.event_file = event_file,
        self.event_table = event_table

    async def on_load(self, _) -> None:
        await self.bind("q", "quit", "Quit")

    async def on_mount(self, _) -> None:
        self.body = body = ScrollView(auto_width=True)

        await self.view.dock(body)

        async def add_content():
            await body.update(self.event_table)

        await self.call_later(add_content)


def create_event_table() -> Table:
    """
    :return:
    """
    tbl = Table(
        show_header=True,
        header_style="bold magenta",
        title=f"Falco aggregated events",
        highlight=True
    )
    tbl.add_column("Rule")
    tbl.add_column("Count")
    tbl.add_column("Priority")
    tbl.add_column("Last timestamp")
    tbl.add_column("Last occurrence", style="Blue")
    tbl.show_footer
    return tbl


def add_rows_to_create_event_table(levents: dict[any, any], events_tbl: Table) -> None:
    sorted_events = sorted(levents, key=lambda name: (levents[name]['count']), reverse=True)
    for event in sorted_events:
        event_data = levents[event]
        events_tbl.add_row(
            event,
            str(event_data['count']),
            event_data['priority'],
            event_data['last_timestamp'],
            event_data['last_fields'],
        )


class RulesDisplayApp(App):

    def __init__(
            self,
            *args,
            rules_file: Path,
            rules_table: Table,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.body = None
        self.rules_file = rules_file,
        self.rules_table = rules_table

    async def on_load(self, _) -> None:
        await self.bind("q", "quit", "Quit")

    async def on_mount(self, _) -> None:
        self.body = body = ScrollView(auto_width=True)

        await self.view.dock(body)

        async def add_content():
            await body.update(self.rules_table)

        await self.call_later(add_content)


def create_rules_table() -> Table:
    """
    :return:
    """
    tbl = Table(
        show_header=True,
        header_style="bold magenta",
        title=f"Falco rules",
        highlight=True
    )
    tbl.add_column("Rule")
    tbl.add_column("Description")
    tbl.add_column("Enabled")
    tbl.add_column("Priority", style="Blue")
    tbl.add_column("Tags")
    tbl.show_footer
    return tbl


def add_rows_to_create_rules_table(lrules: dict[any, any], rules_tbl: Table) -> None:
    for rule in lrules:
        rule_data = lrules[rule]
        enabled = "True" if 'enabled' not in rule_data else str(rule_data['enabled'])
        tags = "" if 'tags' not in rule_data else ", ".join(rule_data['tags'])
        rules_tbl.add_row(
            rule,
            rule_data['desc'],
            enabled,
            rule_data['priority'],
            tags
        )
