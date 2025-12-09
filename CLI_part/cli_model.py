from rich.console import Console
from rich.panel import Panel
console = Console()

class RSLogger:

    @staticmethod
    def info(msg):
        console.print(f"[bold cyan][+][/bold cyan] {msg}")

    @staticmethod
    def success(msg):
        console.print(f"[bold green][✔][/bold green] {msg}")

    @staticmethod
    def warn(msg):
        console.print(f"[bold yellow][!][/bold yellow] {msg}")

    @staticmethod
    def error(msg):
        console.print(f"[bold red][✘][/bold red] {msg}")

    @staticmethod
    def debug(msg):
        console.print(f"[dim][~] {msg}[/dim]")

    @staticmethod
    def banner():
        banner_text = """[bold magenta]
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                    ReconSage CLI
            "Observe. Adapt. Overcome."
[/bold magenta]
"""
        console.print(banner_text)

    @staticmethod
    def status_block(target, modules, cc, waf, tls):
        block = Panel.fit(
            f"[cyan]Target[/cyan]       : {target}\n"
            f"[cyan]Modules[/cyan]      : {modules}\n"
            f"[cyan]Concurrency[/cyan]  : {cc}\n"
            f"[cyan]WAF Detected[/cyan] : {waf}\n"
            f"[cyan]TLS Info[/cyan]     : {tls}",
            title="[bold magenta]ReconSage Status[/bold magenta]"
        )
        console.print(block)
