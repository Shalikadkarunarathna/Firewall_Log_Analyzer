import sys
import re
import pandas as pd
import argparse

def parse_iptables_log(log_file_path, action_filter):

    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (ALLOW|BLOCK) (\w+) (\S+) (\S+) (\d+) (\d+) (\d+) (\S+) -(.+)$')

    columns = ["Date", "Time", "Action", "Protocol", "Src IP", "Dst IP", "Src Port", "Dst Port", "Size", "TCP Flags", "Info"]
    df = pd.DataFrame(columns = columns)
    
    with open(log_file_path, 'r') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                action = match.group(3)
                if action.lower() == action_filter:
                    df.loc[len(df)] = match.groups()

                if action_filter == "all":
                    df.loc[len(df)] = match.groups()
    
    print(df)
            



def main():
    parser = argparse.ArgumentParser(description="Firewall Log Analyzer")
    parser.add_argument("action", choices=['block', 'allow', 'all'], default='all', help="Specify the action type: 'block', 'allow', or 'all' (default)")
    parser.add_argument("file_path", help="Path to the firewall log file")

    args = parser.parse_args()
    log_file_path = args.file_path
    action_filter = args.action

    parse_iptables_log(log_file_path, action_filter)

if __name__ == "__main__":
    main()