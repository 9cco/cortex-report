from api_conf import getAPIData
from aux_funcs import checkResponseStatus
import requests
import time

# API call functions
# ------------------------------------------------------------------------------------

# Dep.: checkResponseStatus {eprint}, requests, startEndpointXQL {requests}
def getEndpointXQLReply(endpoint_id, wait_max=10, tenant_code='1c1'):
    start_res = startEndpointXQL(endpoint_id, tenant_code=tenant_code)
    start_res_json = start_res.json()
    
    if not checkResponseStatus(start_res):
        return None
    
    execution_id = start_res_json['reply']
    
    for i in range(wait_max):
        xql_res = getXQLResults(execution_id, tenant_code=tenant_code)
        if not checkResponseStatus(xql_res):
            return None
        xql_reply = xql_res.json()['reply']
        
        if xql_reply['status'] != "PENDING":
            break
            
        time.sleep(1)
            
    return xql_reply

# Return HTTP response from Cortex XDR API for a single incident.
# Dep.: requests
def getSingleIncident(incident_id, tenant_code='1c1'):
    api_key_id, api_key, api_fqdn, _ = getAPIData(tenant_code)
    incident_ids = [str(incident_id)]
    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key
    }
    filters = [{'field': 'incident_id_list',
                'operator': 'in',
                'value': incident_ids}]
    json_body = {"request_data": {'filters': filters}}
    res = requests.post(url=f"https://{api_fqdn}/public_api/v1/incidents/get_incidents/",
                        headers=headers,
                        json=json_body)
    return res
    
# Return HTTP response from Cortex XDR API for extra information on a single incident.
# Dep.: requests
def getExtraIncInfo(incident_id, tenant_code='1c1'):
    api_key_id, api_key, api_fqdn, _ = getAPIData(tenant_code)
    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key
    }
    json_body = {'request_data': {'incident_id': str(incident_id), 'alerts_limit': 15}}
    res = requests.post(url=f"https://{api_fqdn}/public_api/v1/incidents/get_incident_extra_data/",
                        headers=headers,
                        json=json_body)
    return res

# Dep.: requests
def startEndpointXQL(endpoint_id, tenant_code='1c1'):
    api_key_id, api_key, api_fqdn, _ = getAPIData(tenant_code)
    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key
    }
    query_str = f"dataset = endpoints | filter endpoint_id = \"{endpoint_id}\" | limit 1"
    json_body = {'request_data': {'query': query_str,
                                  'tenants': None,
                                  'timeframe': {'relativeTime': 86400000}}}
    res = requests.post(url=f"https://{api_fqdn}/public_api/v1/xql/start_xql_query/",
                        headers=headers,
                        json=json_body)
    return res

# Dep: requests
def getXQLResults(execution_id, tenant_code='1c1'):
    api_key_id, api_key, api_fqdn, _ = getAPIData(tenant_code)
    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key
    }
    json_body = {'request_data': {'query_id': execution_id,
                                  'pending_flag': True,
                                  'limit': 100,
                                  'format': "json"}}
    res = requests.post(url=f"https://{api_fqdn}/public_api/v1/xql/get_query_results/",
                        headers=headers,
                        json=json_body)
    return res

