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
import ipaddress

# Constant Definitions
ACTION_LOG_NAME = 'action_logger'
HAP_PREFIX = 'HAP-'
MAX_ID_LENGTH = 32
SHARED_SSL_POLICY_NAME = 'HAP-shared-fe-be-ssl'

https_url_prefix = "https://"
content_type = "application/json;charset=UTF-8"
accept_encoding = "gzip, deflate, br"
log_file_path = 'application.log'
always_add_port_to_real = False

# Global variable to track SSL verify servers for backend SSL configuration
ssl_verify_backends = set()
# Global variable to track if shared SSL policy has been generated
shared_ssl_policy_generated = False

####################
# Helper functions #
####################

def log_server_by_network(server_ip, virt_name, cidr_networks):
    for network in cidr_networks:
        if ipaddress.ip_address(server_ip) in network:
            log_action(f"IP Found: Server IP {server_ip} in virt {virt_name} is within the CIDR network {network}.", level='info')
            return

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

def ensure_hap_prefix_length(name, prefix=HAP_PREFIX):
    """
    Ensure the name has HAP- prefix and doesn't exceed MAX_ID_LENGTH characters.
    If the prefixed name is too long, truncate the original name.
    """
    if name.startswith(prefix):
        # Already has prefix, check length
        if len(name) <= MAX_ID_LENGTH:
            return name
        # Truncate to fit within limit
        return name[:MAX_ID_LENGTH]
    
    # Add prefix
    prefixed_name = prefix + name
    if len(prefixed_name) <= MAX_ID_LENGTH:
        return prefixed_name
    
    # Truncate original name to fit with prefix
    max_name_length = MAX_ID_LENGTH - len(prefix)
    return prefix + name[:max_name_length]

def generate_shared_ssl_policy_config():
    """
    Generate the shared SSL policy configuration for frontend and backend SSL 
    without custom ciphers. This policy is used when:
    1. Frontend has SSL (crt directive in bind)
    2. Backend has SSL verify (ssl verify in server line)
    3. No custom ciphers are specified
    """
    global shared_ssl_policy_generated
    
    if shared_ssl_policy_generated:
        return ""
    
    shared_ssl_policy_generated = True
    
    ssl_policy_config = (
        f"/c/slb/ssl/sslpol {SHARED_SSL_POLICY_NAME}\n"
        f" \t cipher high\n"
        f" \t ena\n"
        f"/c/slb/ssl/sslpol {SHARED_SSL_POLICY_NAME}/backend\n"
        f" \t ssl enabled\n"
    )
    
    log_action(f"Generated shared SSL policy {SHARED_SSL_POLICY_NAME} for frontend and backend SSL without custom ciphers", level='info')
    
    return ssl_policy_config

def should_use_shared_ssl_policy(data):
    """
    Check if the data configuration should use the shared SSL policy.
    Returns True if:
    1. Has frontend SSL (ssl in bind options)
    2. Has backend SSL verify servers
    3. No custom ciphers specified
    """
    global ssl_verify_backends
    
    # Check if any bind has SSL without custom ciphers
    has_frontend_ssl_without_custom_ciphers = False
    if data.get('bind'):
        for bind in data['bind']:
            if 'ssl' in bind.get('bind_options', ''):
                # Check for custom ciphers
                ciphers_match = re.search(r'ciphers\s([^\s]+)', bind['bind_options'])
                if not ciphers_match:
                    has_frontend_ssl_without_custom_ciphers = True
                    break
    
    if not has_frontend_ssl_without_custom_ciphers:
        return False
    
    # Check if any servers have SSL verify (backend SSL)
    has_ssl_verify_servers = False
    if data:
        # Check direct servers (for listen sections) - only check enabled servers
        if data.get('servers'):
            for server in data['servers']:
                # Only check enabled servers (skip disabled ones)
                if not server.get('disabled', False) and 'server_options' in server:
                    for option_key in server['server_options']:
                        if 'ssl verify' in option_key:
                            has_ssl_verify_servers = True
                            break
                    if has_ssl_verify_servers:
                        break
        
        # Check default backend
        if not has_ssl_verify_servers and data.get('default_backend') and data['default_backend'] in ssl_verify_backends:
            has_ssl_verify_servers = True
        
        # Check use_backends
        if not has_ssl_verify_servers and data.get('use_backends'):
            for backend_info in data['use_backends']:
                if backend_info['backend'] in ssl_verify_backends:
                    has_ssl_verify_servers = True
                    break
    
    return has_ssl_verify_servers

def generate_virtual_service_base(name, vip_ip):
    # Add HAP- prefix to virtual service name
    virt_name = ensure_hap_prefix_length(name)
    base_config = (
        f"/c/slb/virt {virt_name}\n"
        f" \t ena\n"
        f" \t ipver v4\n"
        f" \t vip {vip_ip}\n"
    )
    return base_config

def generate_virtual_service_configs(data, cert="WebManagementCert", ssl_pol="Outbound_FE_SSL_Inspection", proxy_ip=None):
    # List to hold all configurations for each bind
    all_configs = []

    # Add HAP- prefix to virtual service name
    virt_name = ensure_hap_prefix_length(data['name'])

    # Extract mode from data, default to None if not provided
    mode = data.get('mode')
    # Normalize mode to uppercase to handle different case inputs like 'tcp', 'TCP', etc.
    if mode:
        mode = mode.upper()

    for bind in data['bind']:
        service_config = ''
        if mode == 'TCP':
            service_type = 'basic-slb'
            if (bind['port'] == '443'):
                service_type = 'https'
            elif (bind['port'] == '80'):
                service_type = 'http'
            #else:
                #log_action(f"Handle unsupported service: virt {data['name']} was defined as a TCP service but uses port {bind['port']}. No Virtual Service will be created.")
        elif 'ssl' in bind['bind_options']:
            service_type = 'https'
            custom_ssl_pol_name, generated_ssl_pol_config = generate_ssl_policy_config(data['name'], bind, data)
            if custom_ssl_pol_name:
                service_config += generated_ssl_pol_config
                ssl_pol = custom_ssl_pol_name

            service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/ssl\n"
            service_config += f" \t srvrcert cert {cert}\n"
            service_config += f" \t sslpol {ssl_pol}\n"
            
            log_action(f"Check certificate: configured certificate {cert} for virt {virt_name}, original bind options are {bind['bind_options']}")
        else:
            service_type = 'http'

        service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}\n"
        server_ports = [server['port'] for server in data.get('servers', [])]
        unique_ports = set(server_ports)
        rport = unique_ports.pop() if len(unique_ports) == 1 else 0
        service_config += f" \t rport {rport}\n"

        if 'default_backend' in data and data['default_backend'] != None:
            group_name = ensure_hap_prefix_length(data['default_backend'])
            service_config += f" \tgroup {group_name}\n"
        elif 'servers' in data and len(data['servers']) > 0:
            group_name = ensure_hap_prefix_length(data['name'])
            service_config += f" \tgroup {group_name}\n"
            if len(data['acls']) > 0:
                backend_info, acls_list = prepare_backend_config_for_acls(data)
                if backend_info is not None and acls_list is not None:
                    service_config += generate_backend_service_configs(virt_name, bind['port'], service_type, [backend_info])
        elif 'use_backends' in data and len(data['use_backends']) > 0:
            service_config += f" \taction discard\n"
            service_config += generate_backend_service_configs(virt_name, bind['port'], service_type, data['use_backends'])
        else:
            service_config += f" \taction discard\n"

        # Generate a random 8-character prefix
        random_prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        # Create the HTTP modifications name with prefix and ensuring it's within the 31 character limit
        mod_name = f"{random_prefix}_{data['name']}_{bind['port']}"[:31]

        http_mods_config = ''
        if service_type in ['https', 'http']:
            http_mods_config = generate_http_mods(mod_name, data.get('http_requests'), data.get('http_responses'), dst_port=bind.get('port'), ssl='ssl' in bind['bind_options'])

        if http_mods_config != '':
            service_config += http_mods_config
            service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/http\n"
            service_config += f" \t httpmod {mod_name}\n"
        
        if 'options' in data and 'forwardfor' in data['options']:
            service_config += f" \t xforward ena\n"

        if 'cookies' in data:
            for cookie in data['cookies']:
                if cookie['action'] == 'insert':
                    service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/pbind cookie insert \"{cookie['value']}\"\n"
                elif cookie['action'] == 'passive':
                    service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/pbind cookie passive \"{cookie['value']}\" 1 16 disable\n"
                elif cookie['action'] == 'rewrite':
                    service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/pbind cookie rewrite \"{cookie['value']}\" disable\n"
        
        # Add proxy IP configuration if provided
        if proxy_ip and service_type in ['http', 'https', 'basic-slb']:
            service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}\n"
            service_config += f" \t dbind forceproxy\n"
            # Parse proxy IP to get IP and subnet mask
            if '/' in proxy_ip:
                ip, cidr = proxy_ip.split('/')
                # Convert CIDR to subnet mask
                cidr_int = int(cidr)
                mask = (0xffffffff >> (32 - cidr_int)) << (32 - cidr_int)
                subnet_mask = f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
            else:
                ip = proxy_ip
                subnet_mask = "255.255.255.255"
            
            service_config += f"/c/slb/virt {virt_name}/service {bind['port']} {service_type}/pip\n"
            service_config += f" \t mode address\n"
            service_config += f" \t addr v4 {ip} {subnet_mask} persist disable\n"
             
        # Append the configuration for this bind to the list
        all_configs.append(service_config)

    return all_configs

def generate_ssl_policy_config(name, bind, data=None):
    global ssl_verify_backends
    
    # Extract the ciphers from the bind options
    bind_options = bind['bind_options']
    ciphers_match = re.search(r'ciphers\s([^\s]+)', bind_options)
    
    # Check if any servers have SSL verify (to determine if we need backend SSL)
    has_ssl_verify_servers = False
    if data:
        # Check direct servers (for listen sections) - only check enabled servers
        if data.get('servers'):
            for server in data['servers']:
                # Only check enabled servers (skip disabled ones)
                if not server.get('disabled', False) and 'server_options' in server:
                    for option_key in server['server_options']:
                        if 'ssl verify' in option_key:
                            has_ssl_verify_servers = True
                            break
                    if has_ssl_verify_servers:
                        break
        
        # Check default backend
        if not has_ssl_verify_servers and data.get('default_backend') and data['default_backend'] in ssl_verify_backends:
            has_ssl_verify_servers = True
        
        # Check use_backends
        if not has_ssl_verify_servers and data.get('use_backends'):
            for backend_info in data['use_backends']:
                if backend_info['backend'] in ssl_verify_backends:
                    has_ssl_verify_servers = True
                    break
    
    # Only create SSL policy if we have custom ciphers OR need backend SSL
    if not ciphers_match and not has_ssl_verify_servers:
        return None, None
    
    # Use shared policy if no custom ciphers and has SSL verify servers
    if not ciphers_match and has_ssl_verify_servers:
        shared_policy_config = generate_shared_ssl_policy_config()
        log_action(f"Using shared SSL policy {SHARED_SSL_POLICY_NAME} for {name} (frontend SSL + backend SSL verify, no custom ciphers)", level='info')
        return SHARED_SSL_POLICY_NAME, shared_policy_config
    
    # Use custom ciphers if specified, otherwise use default
    if ciphers_match:
        ciphers = ciphers_match.group(1)
    else:
        ciphers = "DEFAULT"  # Default cipher suite

    # Create a safe base name by removing any problematic characters
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    
    # Create SSL policy name without interface (interface not relevant for Alteon)
    composite_name = f"{safe_name}_pol"
    
    # Ensure HAP- prefix and length limits - but preserve the _pol suffix
    # First calculate available space for the name part
    prefix_length = len(HAP_PREFIX)
    suffix_length = len("_pol")
    available_length = MAX_ID_LENGTH - prefix_length - suffix_length
    
    # If the safe name part is too long, truncate it but keep the _pol suffix
    if len(safe_name) > available_length:
        truncated_name = safe_name[:available_length]
        composite_name = f"{truncated_name}_pol"
    
    # Now apply the HAP- prefix
    final_name = f"{HAP_PREFIX}{composite_name}"
    
    # Final safety check
    if len(final_name) > MAX_ID_LENGTH:
        # Emergency fallback - create a simple name
        final_name = f"{HAP_PREFIX}ssl_pol_{hash(name) % 10000}"
    
    # Generate the Alteon SSL policy configuration
    ssl_policy_config = (
        f"/c/slb/ssl/sslpol {final_name}\n"
        f" \t cipher user-defined-expert \"{ciphers}\"\n"
        f" \t ena\n"
    )
    
    # Add backend SSL if any referenced backend has SSL verify servers
    if has_ssl_verify_servers:
        ssl_policy_config += f"/c/slb/ssl/sslpol {final_name}/backend\n"
        ssl_policy_config += f" \t ssl enabled\n"
        logging.info(f"Added backend SSL to SSL policy {final_name} due to SSL verify servers in referenced backends")
    
    return final_name, ssl_policy_config

def generate_content_class_config(backend, acls):
    # Add HAP- prefix to content class name
    class_name = ensure_hap_prefix_length(backend['backend'])
    class_config = f"/c/slb/layer7/slb/cntclss {class_name} http\n"
    header_count = 1
    path_count = 1
    for acl in acls:
        if acl['name'] in backend['conditions']:
            condition = acl['condition']
            if 'host' in condition and condition['host'] != None:
                class_config += f"/c/slb/layer7/slb/cntclss {class_name} http/header {header_count}\n"
                class_config += f" \t header NAME=host \"VALUE={condition['host']}\"\n"
                class_config += f" \t match NAME=include \"VALUE=equal\"\n"
                header_count += 1
            if 'path' in condition and condition['path'] != None:
                match_type = "equal"
                if condition['type'] == 'path_beg':
                    match_type = "prefx"
                elif condition['type'] == 'path_end':
                    match_type = "sufx"

                class_config += f"/c/slb/layer7/slb/cntclss {class_name} http/path {path_count}\n"
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
    if always_add_port_to_real:
        add_port_to_real = True
    server_name = server['name']
    if not add_port_to_real:
        server_name = server['address']

    # Add HAP- prefix to server name
    server_name = ensure_hap_prefix_length(server_name)

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
    # Add HAP- prefix to healthcheck name
    hc_name = ensure_hap_prefix_length(f"{group_name}_hc")
    healthcheck_lines = [
        f"/c/slb/advhc/health {hc_name} TCP"
    ]
    
    # Only 'inter' is supported for interval
    if 'inter' in server_options:
        healthcheck_lines.append(f" \t inter {server_options['inter'].rstrip('s')}")
    
    # Log unsupported options
    for option in ['rise', 'fall', 'cookie']:
        if option in server_options:
            logging.warning(f"Unsupported server option '{option}' for health checks")

    return healthcheck_lines

def generate_group_config(group_name, servers, backup_group_name=None, balance='default'):
    """Generate configuration for a group of servers including health checks and optional balance settings."""
    group_config_lines = []
    health_check_configured = False

    # Add HAP- prefix to group name
    group_name = ensure_hap_prefix_length(group_name)

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

    # Link health check to the group - ensure HAP- prefix for healthcheck name
    hc_name = ensure_hap_prefix_length(f"{group_name.replace(HAP_PREFIX, '')}_hc")
    group_config_lines.append(f" \t health {hc_name}")

    # Specify the group as a backup group if backup_group_name is provided
    if backup_group_name:
        backup_group_name = ensure_hap_prefix_length(backup_group_name)
        group_config_lines.append(f" \t backup g{backup_group_name}")

    # Check for uniform port across all servers
    unique_ports = set(server.get('port') for server in servers if 'port' in server)
    common_port = unique_ports.pop() if len(unique_ports) == 1 else None

    # Add servers to the group
    for server in servers:
        server_name = server['name']

        # if there is a common port we won't add port to the real, and will configure it on the service
        if common_port != None and not always_add_port_to_real:
            server_name = server['address']
        
        # Add HAP- prefix to server name
        server_name = ensure_hap_prefix_length(server_name)
        group_config_lines.append(f" \t add {server_name}")
        # Generate server configuration considering common port
    
    for server in servers:
        server_config = generate_server_config(server, default_port=common_port)
        group_config_lines.extend(server_config)

    # Generate health check only once based on the first server's options
    if servers and 'server_options' in servers[0] and not health_check_configured:
        health_check_lines = generate_healthcheck(group_name.replace(HAP_PREFIX, ''), servers[0]['server_options'])
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
    
    backup_group_name = None
    if backup_servers:
        backup_group_name = f"backup_{group_name}"
        backup_group_config = generate_group_config(backup_group_name, backup_servers)
        config_lines.extend(backup_group_config)
        

    primary_group_config = generate_group_config(group_name, primary_servers, backup_group_name)
    config_lines.extend(primary_group_config)
    
    logging.info("Completed generation of Alteon backend config")
    return '\n'.join(config_lines)

def generate_alteon_listen(data, proxy_ip=None):
    logging.info(f"Received data (generate_alteon_listen): {data}")

    listen_config = []
    
    # Generate shared SSL policy if needed (frontend SSL + backend SSL verify, no custom ciphers)
    if should_use_shared_ssl_policy(data):
        shared_ssl_config = generate_shared_ssl_policy_config()
        if shared_ssl_config:
            listen_config.append(shared_ssl_config)

    # Set up the virtual service base with the first bind IP and the listen name
    if data['bind']:
        vip_ip = data['bind'][0]['ip']
    else:
        logging.error("No bind IP provided in data.")
        return ""
    virt_name = data['name']
    listen_config.append(generate_virtual_service_base(virt_name, vip_ip))
    listen_config.extend(generate_virtual_service_configs(data, proxy_ip=proxy_ip))

    # Determine the balance strategy to use for the server groups
    balance = data.get('balance', 'default')  # Use 'default' if balance is not specified

    # Process server configurations
    if data['servers']:
        group_name = virt_name
        primary_servers = [s for s in data['servers'] if 'backup' not in s.get('server_options', {})]
        backup_servers = [s for s in data['servers'] if 'backup' in s.get('server_options', {})]

        backup_group_name = None
        if backup_servers:
            backup_group_name = f"backup_{group_name}"
            backup_group_config = generate_group_config(backup_group_name, backup_servers, balance=balance)
            listen_config.extend(backup_group_config)

        primary_group_config = generate_group_config(group_name, primary_servers, backup_group_name=backup_group_name, balance=balance)
        listen_config.extend(primary_group_config)

    # Handle unsupported configurations and log them
    virt_name_with_prefix = ensure_hap_prefix_length(virt_name)
    if data.get('maxconn'):
        logging.warning(f"Maxconn '{data['maxconn']}' specified but not handled directly in Alteon config.")
    if data['redirects']:
        logging.warning(f"Redirects specified but not handled. skipping redirect for {str(data['redirects'])} virt {virt_name_with_prefix} ")
        log_action(f"Add redirect: virt {virt_name_with_prefix} has unhandled redirect rule {str(data['redirects'])}")
    if data['compression']:
        logging.warning(f"Compression settings specified but not handled: {data['compression']}")
        log_action(f"Add compression: virt {virt_name_with_prefix} has unhandled compression setting {data['compression']}")
    if data['stick_tables']:
        logging.warning("Stick tables specified but not handled.")
        log_action(f"Add persistency: virt {virt_name_with_prefix} has unhandled stick_table setting {data['stick_tables']}")
    
    if data['acls']:
        backend_info, acls_list = prepare_backend_config_for_acls(data)
        if backend_info is not None and acls_list is not None:
            listen_config.append(str(generate_content_class_config(backend_info, acls_list)))
    
    # Logging completion of listen configuration generation
    logging.info(f"Completed generation of Alteon listen configuration for {virt_name_with_prefix}")
    logging.info(f"Generated data (generate_alteon_listen): \n {listen_config}")
    return '\n'.join(listen_config)

def generate_alteon_frontend(data, proxy_ip=None):
    logging.info(f"Received data (generate_alteon_frontend): {data}")
    
    # Generate shared SSL policy if needed (frontend SSL + backend SSL verify, no custom ciphers)
    config = ""
    if should_use_shared_ssl_policy(data):
        shared_ssl_config = generate_shared_ssl_policy_config()
        if shared_ssl_config:
            config += shared_ssl_config + "\n"

    vip_ip = data['bind'][0]['ip'] if data['bind'] else None  # Assumes all binds are on the same IP
    if not vip_ip:
        logging.error("No bind IP provided in data.")
        return config

    virt_name = data['name']
    config += generate_virtual_service_base(virt_name, vip_ip)
    config += '\n'.join(generate_virtual_service_configs(data, proxy_ip=proxy_ip))

    for backend in data['use_backends']:
        config += generate_content_class_config(backend, data['acls'])
    
    # Generate content rules for use_backends
    if data['use_backends']:
        for bind in data['bind']:
            service_type = 'https' if 'ssl' in bind['bind_options'] else 'http'
            config += generate_backend_service_configs(virt_name, bind['port'], service_type, data['use_backends'])

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
    for i, backend in enumerate(backends):
        rule_id = (i + 1) * 5  # Start from 5, increment by 5 (5, 10, 15, etc.)
        # Add HAP- prefix to backend group name
        backend_group = ensure_hap_prefix_length(backend['backend'])
        # Ensure virt_name has HAP- prefix
        virt_name_prefixed = ensure_hap_prefix_length(virt_name)
        service_config += f" /c/slb/virt {virt_name_prefixed}/service {virt_port} {service_type}/cntrules {rule_id}\n"
        service_config += f" \tena\n"
        service_config += f" \tcntclss \"{backend_group}\"\n"
        service_config += f" \tgroup {backend_group}\n"

    return service_config

def prepare_backend_config_for_acls(data):
    # Extract the backend name
    backend_name = data['default_backend'] if data.get('default_backend') is not None else data.get('name', None)
    if backend_name is None:
        return None, None
    
    # Extract ACLs directly from the data
    acls_list = data['acls']

    # Prepare the backend info with HAP- prefix
    backend_info = {
        'backend': backend_name,  # Will be prefixed in generate_content_class_config
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
        path_match = re.search(r"path\s+-?i?\s+(.+)", acl_condition)
        path_beg_match = re.search(r"path_beg\s+-?i?\s+(.+)", acl_condition)
        path_end_match = re.search(r"path_end\s+-?i?\s+(.+)", acl_condition)
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
                    logging.warning(f"unhandled root path: '/' used in ACL named {acl_name}. ignoring..")
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

def extract_frontend(section_content, cidr_networks=[]):
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
        
        # Skip empty lines
        if not line:
            continue
            
        # Skip general comments - if line has leading whitespace before #, treat as general comment
        if original_line.lstrip() != original_line and original_line.lstrip().startswith('#'):
            logging.info(f"Skipping comment line: '{original_line}'")
            continue
            
        # Skip direct comments (lines that start with # without leading whitespace)
        if line.startswith('#'):
            logging.info(f"Skipping comment line: '{original_line}'")
            continue

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

def extract_listen(section_content, cidr_networks=[]):
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
        original_line = line
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
            
        # Skip general comments - if line has leading whitespace before #, treat as general comment
        if original_line.lstrip() != original_line and original_line.lstrip().startswith('#'):
            logging.info(f"Skipping comment line: '{original_line}'")
            continue
            
        # Skip direct comments (lines that start with # without leading whitespace)
        if line.startswith('#'):
            logging.info(f"Skipping comment line: '{original_line}'")
            continue

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
                log_server_by_network(server_info['address'], data['name'], cidr_networks)
                data['servers'].append(server_info)
            else:
                logging.warning(f"couldn't parse server config: '{original_line}'")  # Log non-matched lines    
        else:
            logging.warning(f"(extract_listen) No match for line: '{original_line}'")  # Log non-matched lines

    logging.info(f"Extracted listen configuration: {data}")
    return data

def extract_backend(section_content, cidr_networks=[]):
    global ssl_verify_backends
    logging.info("Processing 'backend' directive")
    data = {
        'name': "Unnamed backend",
        'servers': [],
    }

    # Regex to extract the name of the backend
    name_pattern = re.compile(r"^backend\s+(\S+)")
    name_match = name_pattern.search(section_content)
    data['name'] = name_match.group(1) if name_match else "Unnamed backend"

    # Iterate over server lines
    server_lines = section_content.splitlines()
    
    # Filter out general comments (any line starting with # after whitespace)
    valid_server_lines = []
    for line in server_lines:
        stripped = line.strip()
        
        # Skip empty lines
        if not stripped:
            continue
            
        # Skip general comments - if line has leading whitespace before #, treat as general comment
        if line.lstrip() != line and line.lstrip().startswith('#'):
            # This line has leading whitespace before #, so it's a general comment - skip it
            continue
            
        # Skip direct comments (lines that start with # without leading whitespace)
        if line.startswith('#'):
            continue
        
        # Only process server lines
        if stripped.startswith("server"):
            valid_server_lines.append(line)
    
    servers = [parse_server_directive(line.strip()) for line in valid_server_lines]

    # Check for SSL verify servers and add backend to global set - only check enabled servers
    has_ssl_verify = False
    for server in servers:
        if server:
            log_server_by_network(server['address'], data['name'], cidr_networks)
            data['servers'].append(server)
            # Check if this server has SSL verify - only for enabled servers
            if not server.get('disabled', False) and 'server_options' in server:
                for option_key in server['server_options']:
                    if 'ssl verify' in option_key:
                        has_ssl_verify = True
                        break
    
    if has_ssl_verify:
        ssl_verify_backends.add(data['name'])
        logging.info(f"Backend {data['name']} has SSL verify servers, added to SSL verify backends list")

    #data['servers'] = [server for server in servers if server is not None]

    # Extract balance method
    balance_pattern = re.compile(r"balance\s+(\S+)")
    balance_match = balance_pattern.search(section_content)
    data['balance'] = balance_match.group(1) if balance_match else "default"

    logging.info(f"Extracted backend configuration: {data}")
    return data

def extract_config(input_file_path, output_file_path, cidr_networks, proxy_ip=None):
    global ssl_verify_backends
    ssl_verify_backends.clear()  # Clear global SSL verify backends list for new configuration
    
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
    all_matches = list(active_matches)
    
    # First pass: Process backends to collect SSL verify information
    for match in all_matches:
        directive = match.group(1).lower()
        if directive == 'backend':
            directive_counters[directive] += 1
            key = f"{directive} {match.group(2)}"
            section_content = match.group(0).strip()
            processed_content = handler_functions[directive](section_content, cidr_networks)
            alteon_config = alteon_config_generators[directive](processed_content)
            config_sections[key] = alteon_config
    
    # Second pass: Process frontends and listens (now SSL verify info is available)
    for match in all_matches:
        directive = match.group(1).lower()
        if directive in ['listen', 'frontend']:
            directive_counters[directive] += 1
            key = f"{directive} {match.group(2)}"
            section_content = match.group(0).strip()
            processed_content = handler_functions[directive](section_content, cidr_networks)
            alteon_config = alteon_config_generators[directive](processed_content, proxy_ip)
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
    parser.add_argument('--always-add-port', dest='always_add_port', action='store_true', help='Always add port to real server configurations.')
    parser.add_argument('-c', '--cidr_networks', type=str, help='Comma-separated list of CIDR IP networks to log servers that match them.')
    parser.add_argument('--proxy-ip', type=str, help='Proxy IP address to add to all services (format: IP/subnet, e.g., 1.1.1.1/32).')

    args = parser.parse_args()

    global always_add_port_to_real
    always_add_port_to_real = args.always_add_port

    # Set up logging
    setup_logging()

    # Convert CIDR networks to list
    cidr_networks = []
    if args.cidr_networks:
        cidr_list = args.cidr_networks.split(',')
        for cidr in cidr_list:
            try:
                network = ipaddress.ip_network(cidr)
                cidr_networks.append(network)
            except ValueError as e:
                logging.error(f"Invalid CIDR network '{cidr}': {e}")

    # Extract and process configuration
    try:
        result_counters, result_config = extract_config(args.input_file, args.output_file, cidr_networks, args.proxy_ip)
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