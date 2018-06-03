#!/usr/bin/env python3
###############################################################################
#
#  Classify MSF payload/encoder combos
#
#
#  Python 3.5.2
#
#  Author(s) : Sjors Haanen
#  Date      : 23 May 2018
#  Course    : Offensive Technologies
#  Filename  : interpret-results.py
#
#  This script takes a directory containing MSF payload/encoder combos as input.
#  Each combo is a file containing triggered Snort alerts on that combo. The script
#  also takes a file containing Snort rules to be ignored when classifying. Last
#  argument is the MSF output of when these combos were executed.
#  The script classifies each combo as one of the following:
#  1. combo_new_alerts: combo triggered new alerts; Snort did detect something
#  2. combos_no_alerts: combo triggered no (or no new) alerts
#  3. combos_failed: combo did not execute; Exploit failed
#
#  Input two directories:
#  python interpret-results.py [input-dir] [alerts-to-ignore-file] [msf-output-file]
#
#  Requirements: none
#
###############################################################################

from collections import Counter
import os
import sys
import re


def print_parameter_error():
    print("Usage: {0} {{input-directory}} {{alerts-to-ignore-file}} {{msf-output-file}}".format(os.path.basename(__file__)))
    sys.exit(1)


if len(sys.argv) is not 4:
    print("Wrong amount of parameters given")
    print_parameter_error()

alerts_to_ignore = []
msf_output = []

try:
    with open(sys.argv[2], 'r') as f:
        alerts_to_ignore = [line.rstrip('\n') for line in f]
except OSError as e:
    print("Something wrong with reading alerts-to-ignore file")
    print(e)
    print_parameter_error()

try:
    with open(sys.argv[3], 'r') as f:
        msf_output = f.read().split("-----\n")
except OSError as e:
    print("Something wrong with reading msf-output file")
    print(e)
    print_parameter_error()

directory = os.path.dirname(sys.argv[1])

if not os.path.isdir(directory):
    print("'{0}' is no existing directory.".format(sys.argv[1]))
    print_parameter_error()

os.chdir(directory)

combos = []  # all combos
combos_new_alerts = []  # combos which triggered new alerts; Snort did detect something
combos_no_alerts = []  # combos which triggered no (new) alerts (except optionally alerts to ignore)
combos_failed = []  # combos which failed to execute

total_new_alerts = []  # list to display all the new alerts, and in how many combos they are found. No duplicates per combo)

print("Scanning directory '{0}'...".format(directory))
files = os.listdir('./')
for f in files:
    if re.match(".*---.*", f):
        combos.append(f)
    else:
        print("WARNING: File '{0}' does not match combo regex and is therefore excluded from processing.".format(f))
if len(combos) is 0:
    sys.exit("No combos to process found in directory '{0}'. Is it the right one?".format(directory))
print("Found {0} combos to process".format(len(combos)))


def get_msf_output(c_to_find):
    combo_payload, combo_encoder = c_to_find.split("---")
    combo_payload = combo_payload.replace("-", "/")
    combo_encoder = combo_encoder.replace("-", "/")

    for output in msf_output:
        if combo_payload + "\n" in output and combo_encoder + "\n" in output:
            return output
    sys.exit("Error: Not found in MSF output: {0}   {1}".format(combo_payload, combo_encoder))


for combo in combos:
    new_alerts = []
    with open(combo, 'r') as co:
        combo_text = co.read()
        combo_msf_output = get_msf_output(combo)

        # Did combo fail?
        if re.search('\[-\].* Exploit failed', combo_msf_output):
            combos_failed.append(combo)
            continue
        elif re.search('\[-\]', combo_msf_output):
            sys.exit('"\[-\]" in msf_output, but not appended by "Exploit failed:"? \n {0} \n {1}'.format(combo, combo_msf_output))
        elif 'Exploit failed:' in combo_msf_output:
            sys.exit('"Exploit failed:" in msf_output, but not prepended by "\[-\]"? \n {0} \n {1}'.format(combo, combo_msf_output))

        alerts = re.findall('[[**].+[**]]', combo_text)
        for alert in alerts:
            if alert not in alerts_to_ignore:
                new_alerts.append(alert)
    if new_alerts:
        combos_new_alerts.append(combo)
        # print("\nNew alerts on combo '{0}'".format(combo))
        # for n in new_alerts:
        #     print(n)
        unique_new_alerts = set(new_alerts)
        total_new_alerts.extend(unique_new_alerts)
    else:
        combos_no_alerts.append(combo)

combos_successfully_executed = combos_no_alerts + combos_new_alerts

print("combos_failed: {0} ({1}%)".format(len(combos_failed), round(len(combos_failed) / len(combos) * 100, 2)))

print("\n--------- Combo Statistics All -----------")
print("* Combos successfully executed: {0}".format(len(combos_successfully_executed)))
print("  ->  combos_new_alerts: {0}  ({1}%)".format(len(combos_new_alerts), round(len(combos_new_alerts) / (len(combos_new_alerts) + len(combos_no_alerts)) * 100, 2)))
print("  ->  combos_no_alerts: {0} ({1}%)".format(len(combos_no_alerts), round(len(combos_no_alerts) / (len(combos_new_alerts) + len(combos_no_alerts)) * 100, 2)))


# Statistics for default encoders ##################
print("\n------- Combo Statistics default/no encoders --------")
combos_successfully_executed_default_encoder_count = 0
combos_successfully_executed_without_default_encoder_count = 0
for a in combos_successfully_executed:
    if "---generic-none" in a:
        combos_successfully_executed_default_encoder_count += 1
    else:
        combos_successfully_executed_without_default_encoder_count += 1
print("* Combos successfully executed with default/no encoder: {0}".format(combos_successfully_executed_default_encoder_count))

combos_new_alerts_default_encoder_count = 0
combos_new_alerts_without_default_encoder_count = 0
for a in combos_new_alerts:
    if "---generic-none" in a:
        combos_new_alerts_default_encoder_count += 1
    else:
        combos_new_alerts_without_default_encoder_count +=1
print("  ->  combos_new_alerts with default/no encoder: {0} ({1}%)".format(combos_new_alerts_default_encoder_count,
                                                                 round(combos_new_alerts_default_encoder_count /
                                                                       combos_successfully_executed_default_encoder_count * 100, 2)))

combos_no_new_alerts_default_encoder_count = 0
combos_no_new_alerts_without_default_encoder_count = 0
for a in combos_no_alerts:
    if "---generic-none" in a:
        combos_no_new_alerts_default_encoder_count += 1
    else:
        combos_no_new_alerts_without_default_encoder_count += 1
print("  ->  combos_no_new_alerts with default/no encoder: {0} ({1}%)".format(combos_no_new_alerts_default_encoder_count,
                                                                 round(combos_no_new_alerts_default_encoder_count /
                                                                       combos_successfully_executed_default_encoder_count * 100, 2)))

#############################################

# Statistics without default encoders ##################
print("\n------- Combo Statistics with other encoders --------")
print("* Combos successfully executed with other encoder: {0}".format(combos_successfully_executed_without_default_encoder_count))
print("  ->  combos_new_alerts with other encoder: {0} ({1}%)".format(combos_new_alerts_without_default_encoder_count,
                                                                 round(combos_new_alerts_without_default_encoder_count /
                                                                       combos_successfully_executed_without_default_encoder_count * 100, 2)))
print("  ->  combos_no_new_alerts with other encoder: {0} ({1}%)".format(combos_no_new_alerts_without_default_encoder_count,
                                                                 round(combos_no_new_alerts_without_default_encoder_count /
                                                                       combos_successfully_executed_without_default_encoder_count * 100, 2)))

print("--------------------------------------------------------")
# Check for duplicate counting
length_combos_aggregated = len(combos_new_alerts) + len(combos_no_alerts) + len(combos_failed)
if length_combos_aggregated != len(combos):
    print("WARNING: Total length of all specific combo lists combined ({0}) does not match with length of "
          "overall combo lists ({1})".format(length_combos_aggregated, len(combos)))
else:
    print("\nTotal combos: {0}".format(len(combos)))


if total_new_alerts:
    print("\n---------------- New alerts Statistics -----------------")
    print("Top triggered new alerts (found in nr of combos):")
    counter = Counter(total_new_alerts).most_common()
    for c in counter:
        print("{0}   {1}".format(c[1], c[0]))
    print("-------------------------------------------------------")



