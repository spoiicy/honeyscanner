from math import floor
from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from .dos import DoS
from .fuzzing import Fuzzing
from .tar_bomb import TarBomb


class AttackOrchestrator:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes an AttackOrchestrator object.

        Args:
            honeypot (BaseHoneypot): Honeypot object holding the information
                                     to use in the attacks.
        """
        self.honeypot = honeypot
        self.attacks: list[BaseAttack] = []
        if honeypot.name == "dionaea" or honeypot.name == "conpot":
            self.attacks = [
                DoS(honeypot)
            ]
        else:
            self.attacks = [
                Fuzzing(honeypot),
                TarBomb(honeypot),
                DoS(honeypot)
            ]
        self.total_attacks: int = len(self.attacks)
        self.successful_attacks: int = 0
        self.results: AttackResults

    def run_attacks(self) -> None:
        """
        Runs all attacks that can be ran on the specified honeypot.
        """
        # Then run the attacks
        results = []
        for attack in self.attacks:
            result = attack.run_attack()
            if result[0]:
                self.successful_attacks += 1
            results.append(result)
        self.results = results

    def generate_report(self) -> dict[str, str | int | list]:
        """
        Generates a report of the attack results.

        Returns:
            dict: Report of the attack results to be saved for later.
        """

        details = [] 
        for idx, result in enumerate(self.results):
            attack_details = {}
            attack = self.attacks[idx]
            attack_name = attack.__class__.__name__
            
            attack_details["attack_name"] = attack_name
            attack_details["vulnerability_found"] = result[0]
            attack_details["message"] = result[1]
            attack_details["execution_time_sec"] = floor(result[2])
            
            if attack_name == "DoS" or attack_name == "DoSAllOpenPorts":
                attack_details["details"] = f"Number of threads used: {result[3]}"
            elif attack_name == "Fuzzing":
                attack_details["details"] =  f"Test cases executed: {result[3]}"
            elif attack_name == "TarBomb":
                attack_details["details"] =  f"Number of bombs used: {result[3]}"

            details.append(attack_details)
        
        report = {
            "analysis_type": "Active",
            "target": self.honeypot.ip,
            "details": details,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks
        }
            
        return report
