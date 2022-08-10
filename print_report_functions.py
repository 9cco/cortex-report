import pprint
import sys

from aux_funcs import eprint, checkIncidentStatus, formatTimestamp, printListHorizontal, printKeyIfNotNone
from api_calls import getSingleIncident, getExtraIncInfo

from section_printing import printWho, printWhere, printAlertList, printWhy


# Print functions
# ------------------------------------------------------------------------------------

# Dep.: eprint, getSingleIncident {requests}, checkIncidentStatus {eprint, formatTimestamp {datetime}},
#       getExtraIncInfo {requests}, requests,
#       printTemplate {
#          printListHorizontal, formatTimestamp
#          printWho {sortByTimestamp, 
#             getEndpointXQLReply {checkResponseStatus {eprint}, requests, startEndpointXQL {requests}},
#             printEndpointXQLResults {printListHorizontal, formatTimestamp {datetime}, printKeyIfNotNone}},
#          printWhere {printKeyIfNotNone}, printAlertList {formatTimestamp {datetime}, printNonEmptyProcess}
#       }
def printIncidentData(incident_id, tenant_code='1c1', ostream=sys.stdout):
    try:
        res = getSingleIncident(incident_id, tenant_code=tenant_code)
        reply = res.json()['reply']
        
        # Check return code
        if res.status_code != 200:
            eprint("API Error: returned code ", res.status_code)
            eprint(res.text)
            return
        
        # Check return-count
        if reply['result_count'] != 1:
            eprint("ERROR: API returned", reply['result_count'], "results.")
            return
        
        incident = reply['incidents'][0]
        # Variables for checking
        checkIncidentStatus(incident)
        
        res = getExtraIncInfo(incident_id, tenant_code=tenant_code)
        incident_extra = res.json()['reply']
        
        printTemplate(incident, incident_extra, tenant_code=tenant_code, ostream=ostream)
                
    except Exception as err:
        eprint(f"Unknown exception caught in printIncidentData while processing incident id {incident_id}.\nError: {err}")
        raise
    return




# Dep.: formatTimestamp, printListHorizontal, 
#       printWho {sortByTimestamp, 
#          getEndpointXQLReply {checkResponseStatus {eprint}, requests, startEndpointXQL {requests}},
#          printEndpointXQLResults {printListHorizontal, formatTimestamp {datetime}, printKeyIfNotNone}},
#       printWhere {printKeyIfNotNone}, printAlertList {formatTimestamp {datetime}, printNonEmptyProcess}
def printTemplate(incident, incident_extra, tenant_code = '1c1', ostream=sys.stdout):
    # Variables for printing
    incident_id = incident['incident_id']
    description = incident['description']
    # Note: timestamps from the Cortex API are in ms, not seconds.
    creation_time = incident['creation_time']
    usernames = incident['users']
    hosts = incident['hosts']
    
    alerts = incident_extra['alerts']['data']
    network_artifacts = incident_extra['network_artifacts']['data']
    
    # Separate the hostnames and host IDs.
    hostnames = []
    host_IDs = []
    for host in hosts:
        hostname, host_ID = host.split(':', 1)
        hostnames.append(hostname)
        host_IDs.append(host_ID)

    print(f"ID-{incident_id}", file=ostream)
    print("================================================\n", file=ostream)
    print("________________________________________________", file=ostream)
    print("# CASE DESCRIPTION: \n", file=ostream)
    
    # Printing time
    time_str = formatTimestamp(creation_time, format_string="%Y-%m-%d %H:%M:%S UTC")
    print("Timestamp:", time_str, end='  \n', file=ostream)
    # Printing hosts
    printListHorizontal("Host", hosts, end='  \n', ostream=ostream)
    # Printing users
    printListHorizontal("User", usernames, end='  \n', ostream=ostream)
    # Priting various information
    printKeyIfNotNone('alert_count', incident_extra['incident'], end='  \n', alias='Alert count', ostream=ostream)
    printListHorizontal('Category', incident_extra['incident']['alert_categories'], end='  \n', ostream=ostream)
    printKeyIfNotNone('incident_id', incident_extra['incident'], end='  \n', alias='Cortex-ID', ostream=ostream)
    printListHorizontal('Source', incident_extra['incident']['incident_sources'], end='  \n', ostream=ostream)
    printKeyIfNotNone('description', incident_extra['incident'], end='  \n', alias='Incident description', ostream=ostream)
    
    
    print("\n\n\n# RECOMMENDED ACTION:  \n\n\n________________________________________________\n# W5s\n## Who:\n", file=ostream)
    printWho(alerts, tenant_code=tenant_code, ostream=ostream)
    
    print("\n\n\n## Where:", file=ostream)
    printWhere(network_artifacts, ostream=ostream)
    
    print("\n\n\n## What / When:\n", file=ostream)
    print(description, "\n", file=ostream)
    printAlertList(alerts, ostream=ostream)
    
    print("\n\n\n## Why:", file=ostream)
    printWhy(alerts, ostream=ostream)
    
    print("\n\n\n## Impact / Risk:", file=ostream)
    
    print("\n\n\n________________________________________________\n# Other notes", file=ostream)
    return
