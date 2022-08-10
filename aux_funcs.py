import sys
from datetime import *

# Utility functions
# ------------------------------------------------------------------------------------

# Function for printing to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    
# Take a list of alert dictionaries that all include the key 'detection_timestamp'.
# Sort the list on the value of this key.
def sortByTimestamp(alerts):
    
    # Extract timestamps
    timestamps = [alert['detection_timestamp'] for alert in alerts]
    
    # Create pair-iterable with zip and sort this on the first element in each pair.
    tmp_pairs = zip(timestamps, alerts)
    alerts = [alert for timestamp, alert in sorted(tmp_pairs)]
    
    return alerts

# Take an integer of unix epoch in miliseconds and format it as conventional date string.
# Dep.: datetime
def formatTimestamp(timestamp, format_string="%Y-%m-%d %H:%M:%S.%f UTC"):
    dt = datetime.fromtimestamp(timestamp/1e3, tz=timezone.utc)
    time_str = dt.strftime(format_string)
    
    return time_str

# Dep.: eprint, formatTimestamp {datetime}
def checkIncidentStatus(incident):
    severity = incident['severity']
    status = incident['status']
    audit_email = incident['assigned_user_mail']
    audit_name = incident['assigned_user_pretty_name']
    resolved_timestamp = incident['resolved_timestamp']
    
    if severity != "high" and severity != "critical" and severity != "medium":
        eprint("Warning: incident severity is", severity)
        
    if status != "new":
        eprint("Warning: incident has status '", status, "'\n  Assigned email: ", audit_email,
            "\n  Assigned name: ", audit_name, "\n  Resolved: ", formatTimestamp(resolved_timestamp), sep='')
    return

# Dep.: eprint
def checkResponseStatus(web_response):
    
    if web_response.status_code != 200:
        eprint("ERROR: status code =", web_response.status_code)
        eprint(response.json()['reply'])
        return False
    return True


# Print functions
# ------------------------------------------------------------------------------------
    
def printListHorizontal(keyword, elements, end='\n', ostream=sys.stdout):
    num = len(elements)
    if num > 0:
        printed_keyword = keyword + ": "
        if num > 1:
            if keyword[-1] == 'y':
                printed_keyword = keyword[:-1] + "ies: "
            else:
                printed_keyword = keyword + "s: "
        print(printed_keyword, end='', file=ostream)
        
        for element in elements[:-1]:
            print(element, ", ", end='', sep='', file=ostream)
        print(elements[-1], end=end, file=ostream)
    return None
    
def printNonEmptyProcess(keyword, command_line, sign_status, sign_vendor, sha256, ostream=sys.stdout):
    if command_line != None or sha256 != None:
            print(keyword, " CMD: ", command_line, "  \n Signature: ",
                 sign_status, " by ", sign_vendor, "  \n SHA256: ", sha256, sep='', file=ostream)
    return

def printKeyIfNotNone(key, dictionary, ostream=sys.stdout, end='', alias=None):
    if alias == None:
        alias = key
    if dictionary[key] != None:
        print(alias, ": ", dictionary[key], sep='', end=end, file=ostream)
    return None
