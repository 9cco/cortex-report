import sys
import getopt
import datetime as dt
import os

from print_report_functions import printIncidentData
from aux_funcs import eprint

def genFilename(incident_id, tenant_code, ext='md'):
    now = dt.datetime.now(tz=dt.timezone(dt.timedelta(hours=2)))
    day = now.strftime("%d")
    return day + "_" + tenant_code + "_" + str(incident_id) + "." + ext

# Parse command-line arguments
def main(argv):
    tenant_code = '0c1'
    incident_id = 56
    filename=None
    
    try:
        opts, args = getopt.getopt(argv, "ht:i:f:", ["tenant-code=", "incident-id=", "filename="])
    except getopt.GetoptError:
        eprint("py cortex_incident_report.py -t <tenant code> -i <incident id>")
        eprint(argv)
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-t", "--tenant-code"):
            tenant_code = arg
        elif opt in ("-i", "--incident-id"):
            incident_id = int(arg)
        elif opt in ("-f", "--filename"):
            filename = arg
    
    # Default filename is "<day>_<tenant_code>_<incident_id>.md"
    if filename==None:
        filename = genFilename(incident_id, tenant_code)
    
    with open(filename, 'w') as f:
        printIncidentData(incident_id, tenant_code=tenant_code, ostream=f)
    
    # Print output-path
    print("Filepath: ", os.getcwd(), '\\', filename, sep='')
    
if __name__ == "__main__":
   main(sys.argv[1:])
   
