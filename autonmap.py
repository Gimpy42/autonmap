# pip requirements
# nmap: pip install python-nmap
# nclib: pip install nclib

import nmap
import logging
import nclib

# Set up logging
logging.basicConfig(filename='nmap_scan.log', level=logging.INFO)

def run_nmap_scan(target):
    """
    Run various nmap scans on a target.
    """
    # Create an instance of PortScanner
    nm = nmap.PortScanner()

    # Run the scans
    logging.info(f"Running nmap scans on {target}")

    # Syn-scan
    logging.info("Running Syn-scan")
    nm.scan(target, arguments='-sS')

    # Scan all ports
    logging.info("Scanning all ports")
    nm.scan(target, arguments='-p-')

    # Service-version, default scripts, OS
    logging.info("Running service-version, default scripts, OS scan")
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                nm.scan(target, arguments=f'-sV -sC -O -p {port}')

    # Scan for UDP
    logging.info("Scanning for UDP")
    nm.scan(target, arguments='-sU')

    # Monster scan
    logging.info("Running monster scan")
    nm.scan(target, arguments='-p- -A -T4 -sC')

    # Return the result
    return nm

def parse_nmap_results(nm):
    """
    Parse the results of an nmap scan.
    """
    # Parse the results
    for host in nm.all_hosts():
        logging.info(f"Host : {host} ({nm[host].hostname()})")
        logging.info(f"State : {nm[host].state()}")

        # Iterate over all protocols
        for proto in nm[host].all_protocols():
            logging.info(f"Protocol : {proto}")

            lport = nm[host][proto].keys()
            for port in lport:
                logging.info(f"port : {port}, state : {nm[host][proto][port]['state']}")

def connect_to_udp(target, port):
    """
    Connect to an open UDP port on a target using nclib.
    """
    # Connect to the port
    logging.info(f"Connecting to UDP port {port} on {target}")
    nc = nclib.Netcat((target, port), udp=True)
    response = nc.recv()
    
    # Log the result
    logging.info(response)

def main():
    """
    Main function to run the script.
    """
    target = '127.0.0.1'  # Replace with your target

    # Run the nmap scan
    nm = run_nmap_scan(target)

    # Parse the results
    parse_nmap_results(nm)

    # Connect to open UDP ports
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if proto == 'udp':
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        connect_to_udp(target, port)

if __name__ == "__main__":
    main()
