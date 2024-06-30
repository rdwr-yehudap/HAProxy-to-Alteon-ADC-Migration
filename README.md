# Alteon from HAProxy Migration Tool
## Introduction

This **Command Line Interface (CLI) tool** is engineered to streamline the management of Alteon configurations by intelligently generating and applying configuration changes derived from existing HAProxy configuration files. It meticulously extracts settings from HAProxy configurations, transforms them into Alteon-specific commands, and facilitates the deployment of these configurations to an Alteon device through its REST API.

### Key Features and Capabilities

The script is adept at creating a comprehensive array of both **Layer 4 (L4) and Layer 7 (L7) configurations**, tailored to enhance network efficiency and security. Specifically, it generates:

- **Virtual Servers**: Sets up virtual server configurations that define the IP addresses on which they listen for incoming traffic.
- **Virtual Services**: Configures services within the virtual servers, detailing ports and protocols used.
- **SSL Policies**: Manages SSL policies that dictate the security parameters for HTTPS traffic.
- **Health Checks**: Implements health checks to ensure servers are operational and capable of handling requests.
- **HTTP Modification Lists**: Generates lists of modifications for HTTP traffic to dynamically manipulate headers and other HTTP properties.
- **Real Servers**: Defines the actual servers in the network that handle routed requests.
- **Server Groups and Backup**: Organizes servers into groups for efficient load balancing and specifies backup servers for redundancy.
- **Content Classes**: Creates rules for content classification to help in advanced traffic management decisions.

### Logging and Error Handling

In the pursuit of providing **transparent operations**, the tool is equipped with robust logging mechanisms. It meticulously logs into the `action.log` file any configurations it could not handle or apply. This logging provides detailed insights into areas that may require manual intervention or further investigation.

## Requirements
- Python 3.8 or higher
- Required Python packages:
  - `requests` for HTTP requests to Alteon's REST API.
  - `argparse` for command-line argument parsing.
  - `logging` for outputting logs.
  - `socket` for validating IP addresses or FQDNs.
  - `ipaddress` for calculating IPs in CIDR subnets.

To install the required Python packages, run:
```bash
pip install requests
```

## Installation
Clone this repository to your local machine using the following command:
```bash
git clone <repository-url>
```
Navigate into the cloned directory:
```bash
cd <repository-name>
```

## Usage
To use this tool, run the `app.py` script with the required and optional arguments:

```bash
python app.py <input_file> [-o OUTPUT_FILE] [-a ADDRESS] [-u USERNAME] [-p PASSWORD] [-pass PASSPHRASE]
```

### Arguments
- `input_file`: Path to the input HAProxy configuration file.
- `-o, --output_file`: Optional. Path to save the generated Alteon configuration. Defaults to `alteon_config.txt`.
- `-a, --address`: Optional. IP address or FQDN of the Alteon device.
- `-u, --username`: Optional. Username for the Alteon device. Default is 'admin'.
- `-p, --password`: Optional. Password for the Alteon device. Default is 'admin'.
- `-pass, --passphrase`: Optional. Passphrase for additional security during REST API communication.
- `-c, --cidr_networks`: Optional. Comma-separated list of CIDR IP networks to log servers that match them.
- `--always-add-port`: Optional. Always add port to real server configurations.

### Example
```bash
python app.py haproxy_config.txt -o alteon_config.txt -a 192.168.1.1 -u admin -p password -pass passphrase -c 192.168.1.0/24,192.168.2.0/24
```

## Logging
Logs are generated and saved in a `logs` directory within the script's running directory. Each run creates a new log directory timestamped to the run's start time, containing detailed logs of the operations performed.

## Note
Ensure you have proper network permissions and the correct IP/FQDN for the Alteon device when attempting to push configurations.

