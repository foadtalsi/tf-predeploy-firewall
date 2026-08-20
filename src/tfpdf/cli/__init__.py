"""L'interface en ligne de commande. Port de cmd/tf-predeploy-firewall."""

from .main import VERSION, blocked_by, build_parser, main, run

__all__ = ["VERSION", "blocked_by", "build_parser", "main", "run"]
