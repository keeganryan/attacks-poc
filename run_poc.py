
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: entry level executable that can run all PoCs
#

import argparse

issue_descs = {
    "1": "RSA Key Recovery Attack (fast)",
    "1a": "RSA Key Recovery Attack (original)",
    "1b": "RSA Key Recovery Attack (fast)",
    "1c": "RSA Key Recovery Attack (small)",
    "2": "AES-ECB Plaintext Recovery Attack",
    "3": "Framing Attack",
    "4": "Integrity Attack",
    "5": "Guess-and-Purge Variant of Bleichenbacher's Attack on PKCS#1 v1.5 " \
        "adapted for Mega's custom padding"
}

parser = argparse.ArgumentParser(description="Run PoCs")

parser.add_argument("-i", "--issue", type=str, help="Specify which issue to run")
parser.add_argument("-a", "--abstract", action="store_true", help="Only run abstract PoC")
parser.add_argument("-m", "--mitm", action="store_true", help="Only run mitm PoC")

args = parser.parse_args()

if args.mitm and args.abstract:
    print("Invalid arguments, either abstract or MitM PoCs need to be run")
    exit(1)
if not args.issue:
    print("Running all PoCs...")
    issues = ["1", "2", "3", "4", "5"]
else:
    if args.issue not in issue_descs:
        print(f"Issue {args.issue} is not available. Implemented issues are:")
        for i, desc in issue_descs.items():
            print(f"\t- Issue {i}: {desc}")
        exit(1)
    issues = [args.issue]

run_abstract = not args.mitm
run_mitm = not args.abstract

if run_mitm:
    from shared.constants.victim import VICTIM_RSA_Q
    print("In order to run the MitM PoC code, you need to enter the details for the "
          "target user in 'shared/constants/victim.py' (where the TODOs are)")

def print_attack_title(title):
    line_len = 80
    header = "=" * 80
    print(header)
    for i in range(0, len(title), line_len):
        line = title[i:i+line_len]
        center = (line_len - len(line)) // 2
        print(" " * center + line)
    print(header)

for issue in issues:
    print_attack_title(f"Performing {issue_descs[issue]}")

    if "1" in issue:
        if issue == "1a":
            impl = "original"
        elif issue == "1" or issue == "1b":
            impl = "fast"
        elif issue == "1c":
            impl = "small"

        if run_abstract:
            from issue_01.poc_abstract import *
            poc = PoCAbstractRsaKeyRecovery(impl)
            poc.run_sanity_checks()
            poc.run_attack()

        if run_mitm:
            from issue_01.poc_mitm import *
            poc = PoCMitmRsaKeyRecovery(impl)
            poc.run_attack()

    if issue == "2":
        if run_abstract:
            from issue_02.poc_abstract import *
            poc = PoCAbstractAesEcbPlaintextRecovery()
            poc.run_sanity_checks()
            poc.run_attack()

        if run_mitm:
            from issue_02.poc_mitm import *
            poc = PoCMitmAesEcbPlaintextRecovery()
            poc.run_attack()

    if issue == "3":
        if run_abstract:
            from issue_03.poc_abstract import *
            poc = PoCAbstractFramingAttack()
            poc.run_sanity_checks()
            poc.run_attack()

        if run_mitm:
            from issue_03.poc_mitm import *
            poc = PoCMitmFramingAttack()
            poc.run_attack()

    if issue == "4":
        if run_abstract:
            from issue_04.poc_abstract import *
            poc = PoCAbstractIntegrityAttack()
            poc.run_attack()

        if run_mitm:
            from issue_04.poc_mitm import *
            poc = PoCMitmIntegrityAttack()
            poc.run_attack()

    if issue == "5":
        if run_abstract:
            from issue_05.poc_abstract import *
            poc = PoCAbstractGaPBleichenbacherAttack()
            poc.run_sanity_checks()
            poc.run_attack()
