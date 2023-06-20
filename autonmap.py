import logging
from nmap3 import Nmap, NmapScanTechniques
import nclib
import sys

# Set up logging
logging.basicConfig(filename='nmap_scan.log', level=logging.INFO)

def run_nmap_scan(target):
    """
    Run various nmap scans on a target.
    """
    # Create an instance of Nmap
    nmap = Nmap()

    # Create an instance of NmapScanTechniques
    nmap_scan_techniques = NmapScanTechniques()

    # Run the scans
    logging.info(f"Running nmap scans on {target}")

    # Syn-scan
    logging.info("Running Syn-scan")
    result = nmap_scan_techniques.nmap_syn_scan(target)
    check_host_down(result, target, nmap_scan_techniques.nmap_syn_scan)

    # Scan all ports
    logging.info("Scanning all ports")
    result = nmap_scan_techniques.nmap_syn_scan(target, args="-p-")
    check_host_down(result, target, nmap_scan_techniques.nmap_syn_scan)

    # Service-version, default scripts, OS
    logging.info("Running service-version, default scripts, OS scan")
    result = nmap.nmap_version_detection(target)
    check_host_down(result, target, nmap.nmap_version_detection)

    # Scan for UDP
    logging.info("Scanning for UDP")
    result = nmap_scan_techniques.nmap_udp_scan(target)
    check_host_down(result, target, nmap_scan_techniques.nmap_udp_scan)

    # Monster scan
    logging.info("Running monster scan")
    result = nmap_scan_techniques.nmap_syn_scan(target, args="-A -T4 -sC")
    check_host_down(result, target, nmap_scan_techniques.nmap_syn_scan)

    # Return the result
    return result

def check_host_down(result, target, scan_function):
    """
    Check if the host is down and if so, rerun the scan with -Pn flag.
    """
    if 'error' in result[target] and 'Host seems down' in result[target]['error']:
        logging.info("Host seems down, running scan with -Pn flag")
        result = scan_function(target, args="-Pn")

def parse_nmap_results(result):
    """
    Parse the results of an nmap scan.
    """
    # Parse the results
    for host, info in result.items():
        logging.info(f"Host : {host}")
        logging.info(f"State : {info['state']}")

        # Iterate over all protocols
        for proto, details in info['ports'].items():
            logging.info(f"Protocol : {proto}")

            for port, port_info in details.items():
                logging.info(f"port : {port}, state : {port_info['state']}")

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

def main(target):
    """
    Main function to run the script.
    """
    # Run the nmap scan
    result = run_nmap_scan(target)

    # Parse the results
    parse_nmap_results(result)

    # Connect to open UDP ports
    for host, info in result.items():
        if 'ports' in info:
            for proto, details in info['ports'].items():
                if proto == 'udp':
                    for port, port_info in details.items():
                        if port_info['state'] == 'open':
                            connect_to_udp(target, port)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    main(target)