"""nftables ownership and verdict model; never flushes a global ruleset."""

import re
import subprocess


class NftablesController:
    def __init__(self, table: str = "boundary_audit") -> None:
        if not re.match(r"^[a-z][a-z0-9_]{1,31}$", table):
            raise ValueError("invalid nftables table name")
        self.table = table

    def apply(self, rules_file: str) -> None:
        subprocess.run(["nft", "-f", rules_file], check=True)

    def remove(self) -> None:
        subprocess.run(["nft", "delete", "table", "inet", self.table], check=False)
