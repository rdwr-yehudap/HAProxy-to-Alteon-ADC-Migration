import re
import logging
import random
import string
import requests
import base64
import os
from datetime import datetime
import argparse
import socket

# Constant Definitions
ACTION_LOG_NAME = 'action_logger'

https_url_prefix = "https://"
content_type = "application/json;charset=UTF-8"
accept_encoding = "gzip, deflate, br"
log_file_path = 'application.log'

####################
# Helper functions #
####################

def is_valid_address(value):
    """ Validate if the value is an IP address or FQDN """
    try:
        socket.gethostbyname(value)
        return value
    except socket.error:
        raise argparse.ArgumentTypeError(f"{value} is not a valid IP address or FQDN")

def setup_logging():
    # Generate timestamp for the folder name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_directory = os.path.join('logs', timestamp)
    os.makedirs(log_directory, exist_ok=True)  # Create the directory

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler for the root logger
    root_log_path = os.path.join(log_directory, 'application.log')
    file_handler = logging.FileHandler(root_log_path)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Action logger configuration
    action_logger = logging.getLogger(ACTION_LOG_NAME)
    action_logger.setLevel(logging.INFO)

    # File handler for the action logger
    action_log_path = os.path.join(log_directory, 'action.log')
    action_file_handler = logging.FileHandler(action_log_path)
    action_file_handler.setLevel(logging.INFO)
    action_file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    action_file_handler.setFormatter(action_file_formatter)
    action_logger.addHandler(action_file_handler)

def log_action(message, level='info'):
    """
    Log a message to the action log with the specified level.

    Args:
    message (str): The message to log.
    level (str): The logging level ('info', 'error', 'warning', 'debug', 'critical').
    """
    action_logger = logging.getLogger(ACTION_LOG_NAME)
    if level.lower() == 'info':
        action_logger.info(message)
    elif level.lower() == 'error':
        action_logger.error(message)
    elif level.lower() == 'warning':
        action_logger.warning(message)
    elif level.lower() == 'debug':
        action_logger.debug(message)
    elif level.lower() == 'critical':
        action_logger.critical(message)
    else:
        raise ValueError(f"Unsupported logging level: {level}")

###############################
# Config Generation functions #
###############################

def generate_virtual_service_base(name, vip_ip):
    base_config = (
        f"/c/slb/virt {name}\n"
        f" \t ena\n"
        f" \t ipver v4\n"
        f" \t vip {vip_ip}\n"
    )
    return base_config

def generate_virtual_service_configs(data, cert="WebManagementCert", ssl_pol="Outbound_FE_SSL_Inspection"):
    # List to hold all configurations for each bind
    all_configs = []

    # Extract mode from data, default to None if not provided
    mode = data.get('mode')
    # Normalize mode to uppercase to handle different case inputs like 'tcp', 'TCP', etc.
    if mode:
        mode = mode.upper()

    for bind in data['bind']:
        service_config = ''
        if mode == 'TCP':
            service_type = 'basic-slb'
            if (bind['port'] == '443' or bind['port'] == '80'):
                log_action(f"Handle unsupported service: virt {data['name']} was defined as a TCP service but uses an application port {bind['port']}. No Virtual Service will be created.")
        elif 'ssl' in bind['bind_options']:
            service_type = 'https'
            custom_ssl_pol_name, generated_ssl_pol_config = generate_ssl_policy_config(data['name'], bind)
            if custom_ssl_pol_name:
                service_config += generated_ssl_pol_config
                ssl_pol = custom_ssl_pol_name

            service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}/ssl\n"
            service_config += f" \t srvrcert cert {cert}\n"
            service_config += f" \t sslpol {ssl_pol}\n"
            
            log_action(f"Check certificate: configured certificate {cert} for virt {data['name']}, original bind options are {bind['bind_options']}")
        else:
            service_type = 'http'

        service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}\n"
        server_ports = [server['port'] for server in data.get('servers', [])]
        unique_ports = set(server_ports)
        rport = unique_ports.pop() if len(unique_ports) == 1 else 0
        service_config += f" \t rport {rport}\n"

        if 'default_backend' in data and data['default_backend'] != None:
            service_config += f" \tgroup {data['default_backend']}\n"
        elif 'servers' in data and len(data['servers']) > 0:
            service_config += f" \tgroup {data['name']}\n"
            if len(data['acls']) > 0:
                backend_info, acls_list = prepare_backend_config_for_acls(data)
                if backend_info is not None and acls_list is not None:
                    service_config += generate_backend_service_configs(data['name'], bind['port'], service_type, [backend_info])
        elif 'use_backends' in data and len(data['use_backends']) > 0:
            service_config += generate_backend_service_configs(data['name'], bind['port'], service_type, data['use_backends'])

        # Generate a random 8-character prefix
        random_prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        # Create the HTTP modifications name with prefix and ensuring it's within the 31 character limit
        mod_name = f"{random_prefix}_{data['name']}_{bind['port']}"[:31]

        http_mods_config = ''
        if service_type in ['https', 'http']:
            http_mods_config = generate_http_mods(mod_name, data.get('http_requests'), data.get('http_responses'), dst_port=bind.get('port'), ssl='ssl' in bind['bind_options'])

        if http_mods_config != '':
            service_config += http_mods_config
            service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}/http\n"
            service_config += f" \t httpmod {mod_name}\n"
        
        if 'options' in data and 'forwardfor' in data['options']:
            service_config += f" \t xforward ena\n"

        if 'cookies' in data:
            for cookie in data['cookies']:
                if cookie['action'] == 'insert':
                    service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}/pbind cookie insert \"{cookie['value']}\"\n"
                elif cookie['action'] == 'passive':
                    service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}/pbind cookie passive \"{cookie['value']}\" 1 16 disable\n"
                elif cookie['action'] == 'rewrite':
                    service_config += f"/c/slb/virt {data['name']}/service {bind['port']} {service_type}/pbind cookie rewrite \"{cookie['value']}\" disable\n"
             
        # Append the configuration for this bind to the list
        all_configs.append(service_config)

    return all_configs

def generate_ssl_policy_config(name, bind):
    # Extract the ciphers from the bind options
    bind_options = bind['bind_options']
    ciphers_match = re.search(r'ciphers\s([^\s]+)', bind_options)
    
    if ciphers_match:
        ciphers = ciphers_match.group(1)
    else:
        return None, None

    # Extract the interface name from the bind options
    interface_match = re.search(r'interface\s(\w+)', bind_options)
    
    if interface_match:
        interface = interface_match.group(1)
        # Create a composite name with the interface name
        composite_name = f"{name}_{interface}_pol"
    else:
        # Create a composite name without the interface name
        composite_name = f"{name}_pol"
    
    # Generate the Alteon SSL policy configuration
    ssl_policy_config = (
        f"/c/slb/ssl/sslpol {composite_name}\n"
        f" \t cipher user-defined-expert \"{ciphers}\"\n"
        f" \t ena\n"
    )
    
    return composite_name, ssl_policy_config

def generate_content_class_config(backend, acls):
    class_config = f"/c/slb/layer7/slb/cntclss {backend['backend']} http\n"
    header_count = 1
    path_count = 1
    for acl in acls:
        if acl['name'] in backend['conditions']:
            condition = acl['condition']
            if 'host' in condition and condition['host'] != None:
                class_config += f"/c/slb/layer7/slb/cntclss {backend['backend']} http/header {header_count}\n"
                class_config += f" \t header NAME=host \"VALUE={condition['host']}\"\n"
                class_config += f" \t match NAME=include \"VALUE=equal\"\n"
                header_count += 1
            if 'path' in condition and condition['path'] != None:
                match_type = "equal"
                if condition['type'] == 'path_beg':
                    match_type = "prefx"
                elif condition['type'] == 'path_end':
                    match_type = "sufx"

                class_config += f"/c/slb/layer7/slb/cntclss {backend['backend']} http/path {path_count}\n"
                class_config += f" \t path \"{condition['path']}\"\n"
                class_config += f" \t match {match_type}\n"
                path_count += 1
    if path_count == 1 and header_count == 1:
        log_action(f"add content class for: {str(backend)}, couldn't determine L7 config from the following: {str(acls)}")
        return ''
    
    return class_config

def generate_http_mods(name, http_requests, http_responses, dst_port=None, ssl=None):
    mod_name = f"{name}"  # Suffix _mod added to the name
    mod_config = f"/c/slb/layer7/httpmod {mod_name}\n"
    mod_config += f" \tena\n"
    rule_count = 1

    # Define allowed headers
    allowed_headers = [
        {'action': 'set-header', 'header_key': 'X-Forwarded-Port', 'header_value': '%[dst_port]'},
        {'action': 'add-header', 'header_key': 'X-Forwarded-Proto', 'header_value': 'https if { ssl_fc }'},
        {'action': 'set-header', 'header_key': 'Strict-Transport-Security', 'header_value': 'max-age=16000000; includeSubDomains; preload;'}
    ]

    # Function to process a single mod dictionary or string
    def process_mod(mod, direction):
        nonlocal rule_count, mod_config
        if isinstance(mod, dict):
            action = mod.get('action')
            header_key = mod.get('header_key', '')
            header_value = mod.get('header_value', '')
        elif isinstance(mod, str):
            parts = mod.split(maxsplit=2)  # Use maxsplit=2 to ensure the header value remains intact
            if len(parts) < 3:
                logging.warning(f"Malformed HTTP modification string: {mod}")
                return
            action = parts[0]
            header_key = parts[1]
            header_value = parts[2].strip('"')  # Assume the entire remainder is the value, strip quotes if any
        else:
            logging.warning(f"Unsupported type for HTTP modification: {type(mod)}")
            return ""

        # Check if the header is allowed and perform replacements
        for hdr in allowed_headers:
            if hdr['action'] == action and hdr['header_key'] == header_key:
                if '%[dst_port]' in hdr['header_value'] and dst_port:
                    header_value = header_value.replace('%[dst_port]', str(dst_port))
                if '{ ssl_fc }' in hdr['header_value'] and ssl is not None:
                    header_value = 'https' if ssl else 'http'
                break
        else:
            logging.warning(f"Header modification not allowed or recognized: {mod}")
            return ""

        # Define action based on the original HTTP action
        # Treat 'set-header' and 'add-header' as 'insert' in Alteon configuration
        alteon_action = "insert" if action in ['set-header', 'add-header'] else "remove" if action == 'del-header' else "replace"
        mod_config += f"/c/slb/layer7/httpmod {mod_name}/rule {rule_count} header\n"
        mod_config += f" \tena\n"
        mod_config += f" \tdirectn {direction}\n"
        mod_config += f" \taction {alteon_action} \"HEADERNAME={header_key}\" \"VALUE={header_value}\"\n"
        rule_count += 1

    # Process all request rules
    for request in http_requests:
        process_mod(request, 'req')

    # Process all response rules
    for response in http_responses:
        process_mod(response, 'resp')

    if rule_count == 1:  # No rules were added
        return ""
    
    return mod_config

def generate_server_config(server, default_port=None):
    """Generate the configuration for a single server, adjusting the name based on port presence."""
    # Determine if the port should be added to the server's real name
    add_port_to_real = 'port' in server and (default_port is None or server['port'] != default_port)
    server_name = server['name']
    if not add_port_to_real:
        server_name = server['address']

    server_lines = []
    
    # Server block start
    server_lines.append(f"/c/slb/real {server_name}")
    
    # Server status (disabled/enabled)
    status = 'dis' if server.get('disabled', False) else 'ena'
    server_lines.append(f" \t {status}")
    
    # IP version and real IP
    server_lines.append(" \t ipver v4")
    server_lines.append(f" \t rip {server['address']}")
    
    # Port
    if add_port_to_real:
        server_lines.append(f" \t addport {server['port']}")
    
    return server_lines

def generate_healthcheck(group_name, server_options):
    """Generate health check based on server options."""
    healthcheck_lines = [
        f"/c/slb/advhc/health {group_name}_hc TCP"
    ]
    
    # Only 'inter' is supported for interval
    if 'inter' in server_options:
        healthcheck_lines.append(f" \t inter {server_options['inter'].rstrip('s')}")
    
    # Log unsupported options
    for option in ['rise', 'fall', 'cookie']:
        if option in server_options:
            logging.warning(f"Unsupported server option '{option}' for health checks")

    return healthcheck_lines

def generate_group_config(group_name, servers, is_backup=False, balance='default'):
    """Generate configuration for a group of servers including health checks and optional balance settings."""
    group_config_lines = []
    health_check_configured = False

    # Start configuration for the group
    group_config_lines.append(f"/c/slb/group {group_name}")
    group_config_lines.append(f" \t ipver v4")

    # Handle balance configuration
    if balance == 'roundrobin':
        group_config_lines.append(f" \t metric roundrobin")
    elif balance == 'source':
        group_config_lines.append(f" \t metric phash 255.255.255.255")
    elif balance != 'default':
        logging.warning(f"Balance method '{balance}' is specified but not supported. No balance configuration applied.")

    # Link health check to the group
    group_config_lines.append(f" \t health {group_name}_hc")

    # Specify the group as a backup group if it's a backup
    if is_backup:
        backup_group_name = f"backup_{group_name}"
        group_config_lines.append(f" \t backup {backup_group_name}")

    # Check for uniform port across all servers
    unique_ports = set(server.get('port') for server in servers if 'port' in server)
    common_port = unique_ports.pop() if len(unique_ports) == 1 else None

    # Add servers to the group
    for server in servers:
        server_name = server['name']

        # if there is a common port we won't add port to the real, and will configure it on the service
        if common_port != None:
            server_name = server['address']
            
        group_config_lines.append(f" \t add {server_name}")
        # Generate server configuration considering common port
    
    for server in servers:
        server_config = generate_server_config(server, default_port=common_port)
        group_config_lines.extend(server_config)

    # Generate health check only once based on the first server's options
    if servers and 'server_options' in servers[0] and not health_check_configured:
        health_check_lines = generate_healthcheck(group_name, servers[0]['server_options'])
        group_config_lines.extend(health_check_lines)
        health_check_configured = True

    return group_config_lines

def generate_alteon_backend(data):
    logging.info(f"Received data (generate_alteon_backend): {data}")
    config_lines = []
    logging.info("Starting generation of Alteon backend config")
    
    group_name = data['name']
    primary_servers = [s for s in data['servers'] if 'backup' not in s.get('server_options', {})]
    backup_servers = [s for s in data['servers'] if 'backup' in s.get('server_options', {})]
    
    # Generate configurations for primary and backup groups
    primary_group_config = generate_group_config(group_name, primary_servers, is_backup=False)
    config_lines.extend(primary_group_config)
    
    if backup_servers:
        backup_group_name = f"backup_{group_name}"
        backup_group_config = generate_group_config(backup_group_name, backup_servers, is_backup=True)
        config_lines.extend(backup_group_config)
    
    logging.info("Completed generation of Alteon backend config")
    return '\n'.join(config_lines)

def generate_alteon_listen(data):
    logging.info(f"Received data (generate_alteon_listen): {data}")

    listen_config = []

    # Set up the virtual service base with the first bind IP and the listen name
    if data['bind']:
        vip_ip = data['bind'][0]['ip']
    else:
        logging.error("No bind IP provided in data.")
        return ""
    virt_name = data['name']
    listen_config.append(generate_virtual_service_base(virt_name, vip_ip))
    listen_config.extend(generate_virtual_service_configs(data))

    # Determine the balance strategy to use for the server groups
    balance = data.get('balance', 'default')  # Use 'default' if balance is not specified

    # Process server configurations
    if data['servers']:
        group_name = virt_name
        primary_servers = [s for s in data['servers'] if 'backup' not in s.get('server_options', {})]
        backup_servers = [s for s in data['servers'] if 'backup' in s.get('server_options', {})]

        if primary_servers:
            primary_group_config = generate_group_config(group_name, primary_servers, is_backup=False, balance=balance)
            listen_config.extend(primary_group_config)

        if backup_servers:
            backup_group_name = f"backup_{group_name}"
            backup_group_config = generate_group_config(backup_group_name, backup_servers, is_backup=True, balance=balance)
            listen_config.extend(backup_group_config)

    # Handle unsupported configurations and log them
    if data.get('maxconn'):
        logging.warning(f"Maxconn '{data['maxconn']}' specified but not handled directly in Alteon config.")
    if data['redirects']:
        logging.warning(f"Redirects specified but not handled. skipping redirect for {str(data['redirects'])} virt {virt_name} ")
        log_action(f"Add redirect: virt {virt_name} has unhandled redirect rule {str(data['redirects'])}")
    if data['compression']:
        logging.warning(f"Compression settings specified but not handled: {data['compression']}")
        log_action(f"Add compression: virt {virt_name} has unhandled compression setting {data['compression']}")
    if data['stick_tables']:
        logging.warning("Stick tables specified but not handled.")
        log_action(f"Add persistency: virt {virt_name} has unhandled stick_table setting {data['stick_tables']}")
    
    if data['acls']:
        backend_info, acls_list = prepare_backend_config_for_acls(data)
        if backend_info is not None and acls_list is not None:
            listen_config.append(str(generate_content_class_config(backend_info, acls_list)))
    
    # Logging completion of listen configuration generation
    logging.info(f"Completed generation of Alteon listen configuration for {virt_name}")
    logging.info(f"Generated data (generate_alteon_listen): \n {listen_config}")
    return '\n'.join(listen_config)

def generate_alteon_frontend(data):
    logging.info(f"Received data (generate_alteon_frontend): {data}")

    vip_ip = data['bind'][0]['ip'] if data['bind'] else None  # Assumes all binds are on the same IP
    if not vip_ip:
        logging.error("No bind IP provided in data.")
        return ""

    virt_name = data['name']
    config = generate_virtual_service_base(virt_name, vip_ip)
    config += '\n'.join(generate_virtual_service_configs(data))

    for backend in data['use_backends']:
        config += generate_content_class_config(backend, data['acls'])

    logging.info(f"Generated data (generate_alteon_frontend): \n{config}")
    return config

def generate_backend_service_configs(virt_name, virt_port, service_type, backends):
    """
    Generate backend service configurations for virtual services.

    Args:
        virt_name (str): Name of the virtual service.
        virt_port (int): Port number for the virtual service.
        service_type (str): Type of service, such as HTTP or HTTPS.
        backends (list): List of backend dictionaries, each containing 'backend', 'conditions', and 'associated_acls'.

    Returns:
        str: A string containing all the backend service configuration commands.
    """
    service_config = ''
    for i, backend in enumerate(backends, 1):
        service_config += f" /c/slb/virt {virt_name}/service {virt_port} {service_type}/cntrules {i}\n"
        service_config += f" \tena\n"
        service_config += f" \tcntclss \"{backend['backend']}\"\n"
        service_config += f" \tgroup {backend['backend']}\n"

    return service_config

def prepare_backend_config_for_acls(data):
    # Extract the backend name
    backend_name = data['default_backend'] if data.get('default_backend') is not None else data.get('name', None)
    if backend_name is None:
        return None, None
    
    # Extract ACLs directly from the data
    acls_list = data['acls']

    # Prepare the backend info
    backend_info = {
        'backend': backend_name,
        'conditions': ' '.join(acl['name'] for acl in acls_list)  # All ACL names concatenated with spaces
    }

    return backend_info, acls_list

################################
# Config Extractions functions #
################################

def parse_server_directive(server_string):
    # Parse a single server directive string to extract all relevant data
    server_pattern = re.compile(r"(#)?\s*server\s+(\S+)\s+(\S+)(.*)")
    match = server_pattern.match(server_string)
    
    if not match:
        return None

    disabled = True if match.group(1) else False
    name = match.group(2)
    address_port = match.group(3)
    options_string = match.group(4).strip()

    # Split address and port
    if ':' in address_port:
        address, port = address_port.split(':')
    else:
        address, port = address_port, ''

    # Combine name and port to form a new name_port identifier
    if port:
        # Ensure the combined name and port is within 127 characters
        max_name_length = 120  # Allocating 120 chars for name, rest for port and underscore
        if len(name) > max_name_length:
            name = name[:max_name_length]
        name_port = f"{name}_{port}"
    else:
        name_port = name  # If no port is specified, use the name as is

    # Parse server options
    options = parse_server_options(options_string)

    server_info = {
        'disabled': disabled,
        'name': name_port,
        'address': address,
        'port': port,
        'server_options': options
    }

    return server_info

def parse_server_options(option_string):
    options = {}
    tokens = option_string.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Check if this token is followed by a value or is the last token
        if i + 1 < len(tokens):
            next_token = tokens[i + 1]

            # Handling for 'ssl verify none' as a special case
            if token == 'ssl' and next_token == 'verify':
                options[token + ' ' + next_token] = tokens[i + 2] if i + 2 < len(tokens) else True
                i += 3
            # Handling for 'cookie' followed by its value
            elif token == 'cookie':
                options[token] = next_token
                i += 2
            # Handling options with values, checking for numeric or time format like '10s'
            elif token in ['inter', 'rise', 'fall'] and (next_token.isnumeric() or next_token[-1] == 's'):
                options[token] = next_token
                i += 2
            # Default case, treat the option as a boolean if no value follows
            else:
                options[token] = True
                i += 1
        else:
            # Last token is just set to True, as it has no following parameters
            options[token] = True
            i += 1

    return options

def parse_cookie_directive(line):
    parts = line.split()
    cookie_data = {
        'value': parts[1],
        'action': parts[2],
        'options': " ".join(parts[3:])  # Join any remaining parts as options
    }
    return cookie_data

def parse_acl(line):
    acl_match = re.search(r"acl\s+(\S+)\s+(.+)", line)
    if acl_match:
        acl_name = acl_match.group(1)
        acl_condition = acl_match.group(2)
        
        # Match for various conditions
        path_match = re.search(r"path\s+-i\s+(.+)", acl_condition)
        path_beg_match = re.search(r"path_beg\s+(.+)", acl_condition)
        path_end_match = re.search(r"path_end\s+(.+)", acl_condition)
        host_match = re.search(r"hdr\(host\)\s+-i\s+(\S+)", acl_condition)

        acl_entries = []
        condition_type = None
        path = None

        # Determine the type of path match and extract path
        if path_match:
            path = path_match.group(1)
            condition_type = 'path'
        elif path_beg_match:
            path = path_beg_match.group(1)
            condition_type = 'path_beg'
        elif path_end_match:
            path = path_end_match.group(1)
            condition_type = 'path_end'

        # Handle path conditions
        if path:
            for segment in path.split():
                clean_segment = segment.strip('/')
                if clean_segment:
                    acl_entries.append({
                        'name': acl_name,
                        'condition': {
                            'type': condition_type,
                            'path': clean_segment,
                            'host': None
                        }
                    })
                elif segment == '/':  # Log root path usage
                    log_action(f"Root path '/' used in ACL named {acl_name}.", level='info')
                    acl_entries.append({
                        'name': acl_name,
                        'condition': {
                            'type': condition_type,
                            'path': '/',
                            'host': None
                        }
                    })

        # Handle host conditions
        if host_match:
            hosts = host_match.group(1).split()
            for host in hosts:
                acl_entries.append({
                    'name': acl_name,
                    'condition': {
                        'type': 'host',
                        'path': None,
                        'host': host
                    }
                })

        if not acl_entries:
            logging.warning(f"ACL configuration not supported or empty: '{line}'")
            return None

        return acl_entries if acl_entries else None

def extract_frontend(section_content):
    logging.info("Processing 'frontend' directive")
    data = {
        'name': "Unnamed listen section",  # Default name if not found
        'bind': [],
        'use_backends': [],
        'timeouts': [],
        'options': [],
        'servers': [],
        'cookies': [], 
        'http_requests': [],
        'http_responses': [],
        'redirects': [],
        'compression': [],
        'stick_tables': [],
        'acls': [],
        'mode': None,
        'balance': None,
        'maxconn': None
    }

    # Regex to extract the name of the frontend, stopping at any whitespace or invalid characters like #
    name_pattern = re.compile(r"^frontend\s+([^\s#]+)")
    name_match = name_pattern.search(section_content)
    data['name'] = name_match.group(1) if name_match else "Unnamed frontend"

    # Split the section content into lines for processing
    lines = section_content.split('\n')
    acl_dict = {}

    for line in lines:
        original_line = line
        line = line.strip()
        if line.startswith('#') or not line:
            logging.info(f"Skipping line: '{original_line}'")  # Log skipped lines
            continue  # Skip comments and empty lines

        if line.startswith('bind'):
            bind_match = re.search(r"bind\s+(\S+)(.*)", line)
            if bind_match:
                bind_address = bind_match.group(1)
                bind_options = bind_match.group(2).strip()
                
                # Split address and port
                if ':' in bind_address:
                    ip, port = bind_address.split(':')
                else:
                    ip, port = bind_address, ''
                
                data['bind'].append({'ip': ip, 'port': port, 'bind_options': bind_options})

        elif line.startswith('option'):
            option_match = re.search(r"option\s+(.+)", line)
            if option_match:
                data['options'].append(option_match.group(1))
        
        elif line.startswith('cookie'):
            cookie_data = parse_cookie_directive(line)
            data['cookies'].append(cookie_data)

        elif line.startswith('timeout'):
            timeout_match = re.search(r"timeout\s+(\S+)\s+(.+)", line)
            if timeout_match:
                data['timeouts'].append({'type': timeout_match.group(1), 'value': timeout_match.group(2)})

        elif line.startswith('http-request') or line.startswith('http-response'):
            http_directive_match = re.search(r"(http-[a-z]+)\s+(set-header|add-header)\s+(\S+)\s+(.+)", line)
            if http_directive_match:
                data['http_requests'].append({
                    'type': http_directive_match.group(1),
                    'action': http_directive_match.group(2),
                    'header_key': http_directive_match.group(3),
                    'header_value': http_directive_match.group(4)
                })
        elif line.startswith('default_backend'):
            backend_match = re.search(r"default_backend\s+(\S+)", line)
            if backend_match:
                data['default_backend'] = backend_match.group(1)
        # elif line.startswith('acl'):
        #     acl_data = parse_acl(line)
        #     if acl_data:
        #         data['acls'].append(acl_data)
        elif line.startswith('acl'):
            acl_entries = parse_acl(line)
            if acl_entries:  # acl_entries is a list of dictionaries
                for entry in acl_entries:  # Iterate through the list
                    data['acls'].append(entry)  # Append each dictionary to the 'acls' list in data
                    acl_dict[entry['name']] = {'path': entry['condition']['path'], 'host': entry['condition']['host']}
        elif line.startswith('use_backend'):
            use_backend_match = re.search(r"use_backend\s+(\S+)\s+if\s+(.+)", line)
            if use_backend_match:
                backend_name = use_backend_match.group(1)
                conditions = use_backend_match.group(2).split()
                associated_acls = [{'name': cond, 'details': acl_dict[cond]} for cond in conditions if cond in acl_dict]
                data['use_backends'].append({
                    'backend': backend_name,
                    'conditions': ' '.join(conditions),
                    'associated_acls': associated_acls
                })
        else:
            logging.warning(f"(extract_frontend) no match for line: '{original_line}'")  # Log non-matched lines

    logging.info(f"Extracted frontend configuration: {str(data)}")
    return data

def extract_listen(section_content):
    logging.info("Processing 'listen' directive")
    data = {
        'name': "Unnamed listen section",  # Default name if not found
        'bind': [],
        'use_backends': [],
        'timeouts': [],
        'options': [],
        'servers': [],
        'http_requests': [],
        'http_responses': [],
        'redirects': [],
        'compression': [],
        'stick_tables': [],
        'cookies': [], 
        'acls': [],
        'default_backend': None,
        'mode': None,
        'balance': None,
        'maxconn': None
    }

    lines = section_content.split('\n')
    for line in lines:
        original_line = line.strip()  # Strip whitespace for consistent processing
        line = original_line.lstrip()  # Remove leading spaces for command detection
        
        # Continue processing comments that are not '#server' with relevant configurations
        if line.startswith('#'):
            if not line.startswith('#server'):
                logging.info(f"Skipping comment line: '{original_line}'")
                continue  # Skip all other comments

        # Extract the name of the listen section
        if line.startswith('listen'):
            name_match = re.search(r"listen\s+(\S+)", line)
            if name_match:
                data['name'] = name_match.group(1)
        
        # Binding information
        elif line.startswith('bind'):
            bind_match = re.search(r"bind\s+(\S+)\s*(.*)", line)
            if bind_match:
                bind_address, bind_options = bind_match.groups()
                ip, port = bind_address.split(':') if ':' in bind_address else (bind_address, '')
                data['bind'].append({'ip': ip, 'port': port, 'bind_options': bind_options})

        # Options, modes, balance, maxconn, and more
        elif line.startswith('option'):
            option = re.search(r"option\s+(.+)", line).group(1)
            data['options'].append(option)
        elif line.startswith('mode'):
            mode = re.search(r"mode\s+(\S+)", line).group(1)
            data['mode'] = mode
        elif line.startswith('balance'):
            balance = re.search(r"balance\s+(\S+)", line).group(1)
            data['balance'] = balance
        elif line.startswith('cookie'):
            cookie_data = parse_cookie_directive(line)
            data['cookies'].append(cookie_data)
        elif line.startswith('maxconn'):
            maxconn = re.search(r"maxconn\s+(\d+)", line).group(1)
            data['maxconn'] = int(maxconn)
        elif line.startswith('compression'):
            compression_match = re.search(r"compression\s+(algo|type)\s+(.+)", line)
            if compression_match:
                data['compression'].append({compression_match.group(1): compression_match.group(2)})
        elif line.startswith('stick-table'):
            stick_table = re.search(r"stick-table\s+(.+)", line).group(1)
            data['stick_tables'].append(stick_table)
        elif line.startswith('http-request'):
            http_request = re.search(r"http-request\s+(.+)", line).group(1)
            data['http_requests'].append(http_request)
        elif line.startswith('http-response'):
            http_response = re.search(r"http-response\s+(.+)", line).group(1)
            data['http_responses'].append(http_response)
        elif line.startswith('redirect'):
            redirect = re.search(r"redirect\s+(.+)", line).group(1)
            data['redirects'].append(redirect)
        elif line.startswith('default_backend'):
            backend_match = re.search(r"default_backend\s+(\S+)", line)
            if backend_match:
                data['default_backend'] = backend_match.group(1)
        elif line.startswith('acl'):
            acl_entries = parse_acl(line)
            if acl_entries:  # acl_entries is a list of dictionaries
                for entry in acl_entries:  # Iterate through the list
                    data['acls'].append(entry)  # Append each dictionary to the 'acls' list in data


        elif line.startswith('server') or line.startswith('#server'):
            server_info = parse_server_directive(line)
            if server_info:
                data['servers'].append(server_info)
            else:
                logging.warning(f"couldn't parse server config: '{original_line}'")  # Log non-matched lines    
        else:
            logging.warning(f"(extract_listen) No match for line: '{original_line}'")  # Log non-matched lines

    logging.info(f"Extracted listen configuration: {data}")
    return data

def extract_backend(section_content):
    logging.info("Processing 'backend' directive")
    data = {}

    # Regex to extract the name of the backend
    name_pattern = re.compile(r"^backend\s+(\S+)")
    name_match = name_pattern.search(section_content)
    data['name'] = name_match.group(1) if name_match else "Unnamed backend"

    # Iterate over server lines
    server_lines = section_content.splitlines()
    servers = [parse_server_directive(line) for line in server_lines if line.strip().startswith("server") or line.startswith('#server')]

    data['servers'] = [server for server in servers if server is not None]

    # Extract balance method
    balance_pattern = re.compile(r"balance\s+(\S+)")
    balance_match = balance_pattern.search(section_content)
    data['balance'] = balance_match.group(1) if balance_match else "default"

    logging.info(f"Extracted backend configuration: {data}")
    return data

def extract_config(input_file_path, output_file_path):
    new_line = 'listen dummy_radware_do_not_remove'

    # Read the file and check if the line already exists
    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        if new_line not in lines:
            # If the line is not in the file, append it
            with open(input_file_path, 'a') as file_to_write:
                file_to_write.write('\n' + new_line)

    with open(input_file_path, 'r') as file:
        config_data = file.read()

    # Pattern to match the blocks
    pattern = re.compile(
        r"(#?\s*(listen|frontend|backend)\s+[\w\-.#]+.*?)(?=\n\s*(#?\s*(listen|frontend|backend)\s+[\w\-.#]+|$))",
        re.DOTALL | re.IGNORECASE)

    matches = pattern.findall(config_data)

    cleaned_data = []
    for match in matches:
        block = match[0]
        # Check if the block starts with a commented directive
        if not block.strip().startswith('#'):
            cleaned_data.append(block)

    cleaned_data = '\n'.join(cleaned_data)

    config_sections = {}

    #Apply the regex to the cleaned data to find active sections
    active_pattern = re.compile(
        r"(listen|frontend|backend)\s+([\w\-.#]+)((?:\n|.)+?)(?=\n\s*(listen|frontend|backend)\s+[\w\-.#]*|\Z)",
    re.IGNORECASE | re.DOTALL)

    active_matches = active_pattern.finditer(cleaned_data)

    handler_functions = {
        'listen': extract_listen,
        'frontend': extract_frontend,
        'backend': extract_backend
    }

    alteon_config_generators = {
        'listen': generate_alteon_listen,
        'frontend': generate_alteon_frontend,
        'backend': generate_alteon_backend
    }

    directive_counters = {'listen': 0, 'frontend': 0, 'backend': 0}
    
    for match in active_matches:
        directive = match.group(1).lower()
        directive_counters[directive] += 1  # Increment the respective directive counter

        key = f"{directive} {match.group(2)}"
        section_content = match.group(0).strip()

        # Apply the handler function based on the directive
        if directive in handler_functions:
            processed_content = handler_functions[directive](section_content)
            # Generate Alteon config for the processed content
            alteon_config = alteon_config_generators[directive](processed_content)
            config_sections[key] = alteon_config

    # Write processed content to the output file
    with open(output_file_path, 'w') as outfile:
        for key, value in config_sections.items():
            outfile.write(f"{value}\n\n")
    
    logging.info(f'SUMMARY: found and created config for the following sections in file - {directive_counters}')
    return directive_counters, config_sections # Return the results

def get_alteon_config(alteon_address, auth, passphrase):
    '''
    Fetch the configuration from an Alteon device using its REST API.
    '''
    headers = {
        'Passphrase': passphrase,
        'Authorization': auth,
        'Content-Type': content_type,
        'Accept-Encoding': accept_encoding
    }

    url = https_url_prefix + alteon_address + "/config/getcfg?pkey=yes&src=txt"
    logging.debug("Attempting to fetch config from Alteon at URL: " + url)
    
    try:
        response = requests.get(url,verify=False, headers=headers, stream=True)
        response.raise_for_status()  # Raises stored HTTPError, if one occurred
        #logging.debug("Received response from Alteon: " + response.text)
    except requests.exceptions.HTTPError as errh:
        logging.error("HTTP Error:", errh)
        raise
    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting:", errc)
        raise
    except requests.exceptions.Timeout as errt:
        logging.error("Timeout Error:", errt)
        raise
    except requests.exceptions.RequestException as err:
        logging.error("OOps: Something Else", err)
        raise

    return response.text

def put_alteon_config(alteon_address, auth, config_to_put, passphrase):
    '''
    Push configuration to an Alteon device using its REST API.
    '''
    url = https_url_prefix + alteon_address + "/config/configimport?pkey=yes"
    headers = {
        'Passphrase': passphrase,
        'Authorization': auth,
        'Content-Type': content_type,
        'Accept-Encoding': accept_encoding
    }
    payload = config_to_put

    #logging.info("Attempting to upload config to Alteon: \n%s", str(payload))
    
    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)  # Be cautious with verify=False
        response.raise_for_status()
        logging.debug("Received response from Alteon: " + response.text)
    except requests.exceptions.HTTPError as errh:
        logging.error("HTTP Error:", errh)
        raise
    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting:", errc)
        raise
    except requests.exceptions.Timeout as errt:
        logging.error("Timeout Error:", errt)
        raise
    except requests.exceptions.RequestException as err:
        logging.error("OOps: Something Else", err)
        raise

    return response.text

def manage_alteon_configuration(alteon_address, user, password, passphrase, added_config =''):
    '''
    Manage the configuration of an Alteon device by fetching and updating its configuration.
    
    Parameters:
    alteon_address (str): IP address of the Alteon device.
    user (str): Username for authentication.
    password (str): Password for authentication.
    passphrase (str): Passphrase used for additional security measures.
    '''

    # Encode credentials in base64 to use in the Authorization header
    credentials = f"{user}:{password}"
    auth = "Basic " + base64.b64encode(credentials.encode()).decode()

    # Fetch configuration
    try:
        current_config = get_alteon_config(alteon_address, auth, passphrase)
        print("Current Configuration:")
        print(current_config)
    except Exception as e:
        print("Failed to fetch configuration:", e)
        return

    ## end of alteon script must always look like this
    eof = '''
    /
    script end  /**** DO NOT EDIT THIS LINE!
    '''
    # Example modification - this is where you would make changes to the configuration
    modified_config = current_config + "\n" + added_config + eof

    # Push modified configuration
    try:
        update_response = put_alteon_config(alteon_address, auth, modified_config, passphrase)
        print("Update Response:")
        print(update_response)
    except Exception as e:
        print("Failed to update configuration:", e)
        return

def main():
    parser = argparse.ArgumentParser(description="CLI tool to manage Alteon configurations.")
    parser.add_argument('input_file', type=str, help='Input file path for HAProxy configuration.')
    parser.add_argument('-o', '--output_file', type=str, default='alteon_config.txt', help='Output file path for Alteon configuration.')
    parser.add_argument('-a', '--address', type=is_valid_address, default='', help='Alteon device address (IP or FQDN).')
    parser.add_argument('-u', '--username', type=str, default='admin', help='Username for the Alteon device.')
    parser.add_argument('-p', '--password', type=str, default='admin', help='Password for the Alteon device.')
    parser.add_argument('-pass', '--passphrase', type=str, default='passphrase', help='Passphrase for additional security measures.')
    
    args = parser.parse_args()

    # Set up logging
    setup_logging()

    # Extract and process configuration
    try:
        result_counters, result_config = extract_config(args.input_file, args.output_file)
        result_string = '\n'.join(result_config.values())
    except Exception as e:
        print(f"Failed to process configuration: {e}")
        return

    # Manage Alteon configuration if an address is provided
    if args.address:
        try:
            manage_alteon_configuration(args.address, args.username, args.password, args.passphrase, result_string)
        except Exception as e:
            print(f"Failed to manage Alteon configuration: {e}")
    else:
        print("No Alteon address provided; skipping device configuration.")

if __name__ == '__main__':
    main()