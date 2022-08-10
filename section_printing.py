import sys

from api_calls import getEndpointXQLReply
from aux_funcs import printListHorizontal, formatTimestamp, printKeyIfNotNone, printNonEmptyProcess, sortByTimestamp

# Dep.: printListHorizontal, formatTimestamp {datetime}, printKeyIfNotNone
def printEndpointXQLResults(endpoint_xql, ostream=sys.stdout):
    
    print("name: '", endpoint_xql['endpoint_name'], sep='', end="'", file=ostream)
    if endpoint_xql['endpoint_alias'] != None:
        print(" aka '", endpoint_xql['endpoint_alias'], sep='', end="'", file=ostream)
    print("\n", endpoint_xql['endpoint_status'], " ", endpoint_xql['endpoint_type'], ", ",
         endpoint_xql['endpoint_id'], sep='', end='  \n', file=ostream)
    
    print("user: ", endpoint_xql['user'], ", ", sep='', end='  \n', file=ostream)
    
    # Print IP-information
    printListHorizontal("ip", endpoint_xql['ip_address'], end='', ostream=ostream)
    if endpoint_xql['last_origin_ip'] != None:
        print(", last origin: ", endpoint_xql['last_origin_ip'], sep='', end='', file=ostream)
    print("  ", file=ostream)
        
    printListHorizontal("mac", endpoint_xql['mac_address'], end='  \n', ostream=ostream)
    
    # Print time-information
    print("seen from ", formatTimestamp(endpoint_xql['first_seen'], format_string="%Y-%m-%d"),
          " to ", formatTimestamp(endpoint_xql['last_seen'], format_string="%Y-%m-%d"), sep='', end='  \n', file=ostream)
    
    # Print os information
    print(endpoint_xql['bit_version'], " ", endpoint_xql['operating_system'], " (", endpoint_xql['os_version'],
          ") ", endpoint_xql['endpoint_type'], sep='', end='  \n', file=ostream)
    
    if endpoint_xql['cloud_id'] != None:
        print("cloud id: ", endpoint_xql['cloud_id'], ", cloud info: ", endpoint_xql['cloud_info'], sep='', end='  \n', file=ostream)
    printKeyIfNotNone('kernel_version', endpoint_xql, end='  \n', ostream=ostream)
    printKeyIfNotNone('android_id', endpoint_xql, end='  \n', ostream=ostream)
    if endpoint_xql['last_used_proxy'] != None:
        print("last proxy: ", endpoint_xql['last_used_proxy'], ":", endpoint_xql['last_used_proxy_port'],
              sep='', end=', ', file=ostream)
        printListHorizontal("proxy", endpoint_xql['proxy'], end='  \n', ostream=ostream)
    
    return None

# Dep.: sortByTimestamp, 
#       getEndpointXQLReply {checkResponseStatus {eprint}, requests, startEndpointXQL {requests}},
#       printEndpointXQLResults {printListHorizontal, formatTimestamp {datetime}, printKeyIfNotNone}
def printWho(alerts, tenant_code = '1c1', ostream=sys.stdout):
    
    # Sort alerts chronologically
    sorted_alerts = sortByTimestamp(alerts)
    endpoint_ids = []
    
    # Print Hosts
    for alert in sorted_alerts:
        host_ip = alert['host_ip']
        hostname = alert['host_name']
        endpoint_id = alert['endpoint_id']
        
        if host_ip != None and endpoint_id != None and endpoint_id not in endpoint_ids:
            endpoint_ids.append(endpoint_id)
            print("#### Host: '", hostname, "' ", host_ip, sep='', file=ostream)
                        
            # Get more information by performing an xql query on the endpoint_id
            xql_reply = getEndpointXQLReply(endpoint_id, tenant_code=tenant_code)
            if (xql_reply['status'] == "SUCCESS" and xql_reply['number_of_results'] == 1 and
                xql_reply['number_of_results'] == len(xql_reply['results']['data'])):
                
                endpoint_xql = xql_reply['results']['data'][0]
                printEndpointXQLResults(endpoint_xql, ostream=ostream)
            else:
                print(alert['agent_os_type'], " ", alert['agent_os_sub_type'], ", ",
                  endpoint_id, sep='', end='  \n', file=ostream)
            print("", file=ostream)
            
    usernames = []
    
    # Print User-information
    for alert in sorted_alerts:
        username = alert['user_name']
        
        if username != None and username not in usernames:
            usernames.append(username)
            print("#### User: '", username, "' on ", alert['host_ip'], sep='', end='\n\n', file=ostream)
        
        os_username = alert['os_actor_effective_username']
        if os_username != None and os_username not in usernames:
            usernames.append(username)
            print("#### User: '", os_username, "' on ", alert['host_ip'], sep='', end='\n\n', file=ostream)

    
# Print information on all alerts in the input-list as nicely formatted paragraphs.
# Dep.: formatTimestamp {datetime}, printNonEmptyProcess
def printAlertList(alerts, ostream=sys.stdout):
    
    # Sort alerts chronologically
    sorted_alerts = sortByTimestamp(alerts)
    
    for alert in sorted_alerts:
        print("#### ", formatTimestamp(alert['detection_timestamp']), ", '", alert['event_type'], sep='', end='', file=ostream)
        if alert['event_sub_type'] != None:
            print(": ", alert['event_sub_type'], sep='', end='', file=ostream)
        print("' from ", alert['source'], sep='', end='  \n', file=ostream)
        print(alert['category'], ". ", alert['description'], ".", sep='', end='  \n', file=ostream)
        
        # Print host-information
        print("Host: ", alert['host_name'], " (", alert['host_ip'], ", ID: ", alert['endpoint_id'], sep='', end='', file=ostream)
        if alert['agent_os_type'] != None and alert['agent_os_type'] != "NO_HOST":
            print(", ", alert['agent_os_type'], " ", alert['agent_os_sub_type'], sep='', end='', file=ostream)
        print(")  ", file=ostream)
        
        # If it is an email
        if (alert['fw_email_subject'] != None or alert['fw_email_sender'] != None or 
            alert['fw_email_recipient'] != None):
            print("Email subject:", alert['fw_email_subject'], "\nSender:", alert['fw_email_sender'],
                  "\nRecipient:", alert['fw_email_recipient'], "\nIs Phishing:", alert['fw_is_phishing'],
                  end='  \n', file=ostream)
        
        # If the alert has connection information
        if (alert['action_local_ip'] != None and alert['action_local_port'] != None and
            alert['action_remote_ip'] != None and alert['action_remote_port'] != None):
            print("Connection: ", alert['action_local_ip'], ":", alert['action_local_port'], " --> ",
                 alert['action_remote_ip'], ":", alert['action_remote_port'], sep='', end='  \n', file=ostream)
        if alert['dns_query_name'] != None:
            print("Dns query name:", alert['dns_query_name'], end='  \n', file=ostream)
        if alert['dst_action_external_hostname'] != None:
            print("Dst action external hostname: ", alert['dst_action_external_hostname'], ":",
                  alert['dst_action_external_port'], sep='', end='  \n', file=ostream)
        
        # If the alert has a process execution
        # Print Actor process
        printNonEmptyProcess("Actor process", alert['actor_process_command_line'], 
                             alert['actor_process_signature_status'],
                             alert['actor_process_signature_vendor'], alert['actor_process_image_sha256'],
                             ostream=ostream)
        # Print CGO Process
        printNonEmptyProcess("Causality actor process", alert['causality_actor_process_command_line'],
                             alert['causality_actor_process_signature_status'],
                             alert['causality_actor_process_signature_vendor'], 
                             alert['causality_actor_process_image_sha256'],
                             ostream=ostream)
        
        # Print file-information
        if (alert['action_file_path'] != None or alert['action_file_sha256'] != None):
            print("Action file: '", alert['action_file_path'], "' (", alert['action_file_sha256'], ")",
            end='  \n', file=ostream)
            
        # Print registry-information
        if (alert['action_registry_data'] != None or alert['action_registry_full_key'] != None 
            or alert['action_registry_value_name'] != None):
            print("Registry key: ", alert['action_registry_full_key'], " : ", alert['action_registry_value_name'],
                 " <- ", alert['action_registry_data'], end='  \n', file=ostream)
        
    
        
        print("", file=ostream)


# Dep.: printKeyIfNotNone
def printWhere(network_artifacts, ostream=sys.stdout):
    for artifact in network_artifacts:
        if artifact['network_remote_ip'] != None:
            
            print("#### ", artifact['type'], " ",
                  artifact['network_remote_ip'], ":", artifact['network_remote_port'], sep='', file=ostream)
            country = artifact['network_country']
            
            printKeyIfNotNone("network_domain", artifact, ostream=ostream, end='  \n')
            
            if country != None and country != "UNKNOWN":
                print("country:", country, end='  \n', file=ostream)
            print("", file=ostream)

def printWhy(alerts, ostream=sys.stdout):
    
    for alert in alerts:
        if alert['causality_actor_process_command_line'] != None:
            printNonEmptyProcess("Causality actor process", alert['causality_actor_process_command_line'],
                 alert['causality_actor_process_signature_status'],
                 alert['causality_actor_process_signature_vendor'], 
                 alert['causality_actor_process_image_sha256'],
                 ostream=ostream)
    
    return