#!/usr/bin/env python3

## Original script source: https://forums.anandtech.com/threads/folding-home-fahclient-config-control-manual-page.2574018/#post-40108202

import requests
import os
import time
import logging
import sys
import json
import random
import re
import time
import calendar

import telnetlib
# vars and configs
bearertoken = ""
vropsUser = "admin"
vropsPassword = "VMware1!"
vropsHost = "vrops.virtualiseme.com.au"
vropsAuthsource = "Local"
teamId = "52737"
foldingUserName = "<enter folding user name>"

verify = False
if not verify:
    requests.packages.urllib3.disable_warnings()
clientChildren = []
# Enter one or more hosts here.
# Can be 'localhost', or IP addresses like '192.168.0.5', or hostnames.
# Enclose in '' and separate by comma.
hosts = [
 #['IP or hostname', port , "DisplayName in output"],
  ['10.0.0.144', 36330 , "fah02"],
  ['192.168.0.194', 36330, "FoldingServer"],
  ['10.0.0.146', 36330, "fah01"],
  ['192.168.0.161', 36330, "Samuels-PC"],
  ['192.168.0.127', 36330, "Ahleighs-PC"]
]

# The intervals in which to check, in minutes:
loopdelay = 5

# Enable/Disable continuous looping
loop = True

# Enable debug output
debug = True

# Used to format ETA metric
def get_sec(time_str):
    #"""Get Seconds from time."""
    #print(time_str)
    if "d" in time_str:
        return (int(time_str[:2]) * 24) * 3600
    else:
        h, m, s = time_str.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)

#vROps bearer token function
def vropsGetToken(user=vropsUser, passwd=vropsPassword, authSource=vropsAuthsource, host=vropsHost):
    if not bearertoken:
        url = "https://" + host + "/suite-api/api/auth/token/acquire"
        payload = "{\r\n  \"username\" : \"" + user + "\",\r\n  \"authSource\" : \"" + authSource + "\",\r\n  \"password\" : \"" + passwd + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
        response = requests.request("POST", url, data=payload, headers=headers, verify=verify)
        return response.text
    elif int(bearertoken["validity"])/1000 < int(round(time.time()*1000)):
        url = "https://" + host + "/suite-api/api/versions"
        headers = {
            'authorization': "vRealizeOpsToken " + bearertoken["token"],
            'accept': "application/json"
        }
        response = requests.request("GET", url, headers=headers, verify=verify)
        if response.status_code == 401:
            url = "https://" + host + "/suite-api/api/auth/token/acquire"
            payload = "{\r\n  \"username\" : \"" + vropsUser + "\",\r\n  \"authSource\" : \"" + vropsAuthsource + "\",\r\n  \"password\" : \"" + vropsPassword + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
            headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
            response = requests.request("POST", url, data=payload, headers=headers, verify=verify)
            return response.text
        else:
            return json.dumps(bearertoken)
    else:
        return json.dumps(bearertoken)

#vROps vROps Request Function
def vropsRequest(request,method,querystring="",payload="",log=True):
    global bearertoken
    print(payload)
    bearertoken = json.loads(vropsGetToken())
    url = "https://" + vropsHost + "/suite-api/" + request
    querystring = querystring
    headers = {
        'authorization': "vRealizeOpsToken " + bearertoken["token"],
        'accept': "application/json",
        'content-type': "application/json"
    }
    if (querystring != "") and (payload != ""):
        response = requests.request(method, url, headers=headers, params=querystring, json=payload, verify=verify)
    elif (querystring != ""):
        response = requests.request(method, url, headers=headers, params=querystring, verify=verify)
    elif (payload != ""):
        response = requests.request(method, url, headers=headers, json=payload, verify=verify)
    else:
        response = requests.request(method, url, headers=headers, verify=verify)
    if log == True:
        print ("Request " + response.url + " returned status " + str(response.status_code))
        #print (response.text)
    if response.text:
        return response.json()

#FaH API for team and user metrics
def foldRequest(request,method,querystring="",payload=""):
    url = "https://api.foldingathome.org" + request
    headers = {
        'content-type' : "application/json"
    }
    retry = True
    tryCount = 0
    while retry:
        response = requests.request(method, url, headers=headers)
        #print ("Request " + response.url + " returned status " + str(response.status_code))
        if response.status_code == 200:
            return response.json()
        else:
            if tryCount > 15:
                retry = False
            else:
                tryCount += 1
                time.sleep(5)

def format_ppd(ppd):
  if ppd >= 1e6:
    return "%.2fM ppd" % (ppd / 1e6)
  if ppd >= 1e4:
    return "%.0fk ppd" % (ppd / 1e3)
  return "%d ppd" % (ppd)

def format_duration(dur):
  d = dur // (24*3600)
  dur -= d*24*3600
  h = dur // 3600
  dur -= h*3600
  m = dur // 60
  dur -= m*60
  s = dur
  if d > 0:
    return "%02.0fd%02.0fh" % (d, h)
  else:
    return "%02.0f:%02.0f:%02.0f" % (h, m, s)

def parse_duration(dur):
  d = 0.
  for t in dur.split():
    if t == 'days':
      return d*24.*3600.
    elif t == 'hours':
      d *= 60.
    elif t == 'mins':
      d *= 60.
    elif t == 'secs':
      pass
    else:
      d += float(t)
  return d

# Class to handle client information and connections
class FAHClients:
  def __init__(self, name, ip, port):
    self.name = name
    self.ip = ip
    self.port = port
    self.host_ppd = 0

  #Class function to gather queue information and handle connection to servers
  def connect_to_server(self):
    try:
      x = 0
      while x < 2:
        self.tn = telnetlib.Telnet(self.ip, self.port, 10)
        if debug:
          print("\nConnecting...")
          self.tn.set_debuglevel(200)

        buftest = self.tn.read_until(b'Welcome to the Folding@home Client command\n> ', 10).decode('utf-8')
        if "Client" not in buftest:
          self.tn.write(b'exit\n')
          self.tn.close()
          x += 1
          continue

        self.tn.write(b'slot-info\n')
        slotbuf = self.tn.read_until(b'---\n', 10).decode('utf-8')
        slots = eval(slotbuf.split('PyON 1 slots\n')[1].split('\n---\n')[0])
        trip = True
        for x in slots:
          if x["status"] == "RUNNING":
            trip = False

        if trip:
          self.queue = []
          return("Information retrieved")

        self.tn.write(b'queue-info\n')
        bufdec = self.tn.read_until(b'---\n>', 10).decode('utf-8')
        self.tn.write(b'exit\n')
        self.tn.close()

        if len(bufdec.split('PyON 1 units\n')) > 1:
          self.queue = eval(bufdec.split('PyON 1 units\n')[1].split('\n---\n')[0])
          if len(self.queue) > 0:
            break

        x += 1

      else:
        if not hasattr(self, "queue"):
          raise(TimeoutError)

    except TimeoutError as err:
      return("Cannot retrieve info")

    except:
      if debug:
        print(sys.exc_info())
      return("Cannot connect")
    return("Information Retrieved")

  #Parses the information for each host
  def parse_info(self):
    self.slots = {}
    for i in self.queue:
      if debug:
        print(i)

      indx = i['slot']
      x = 1

      #Adjusts slot index to handle multiple instances of slots (when downloading and working at the same time).
      while indx in self.slots:
        if x < 10:
          indx = i['slot'] + "_0" + str(x)
        else:
          indx = i['slot'] + "_" + str(x)

        x += 1

      self.slots[indx] = {"state": i['state'], "unit": i["id"], "waiting": i["waitingon"]}

      #Store targeted information from queue based on state
      if i['state'] == 'DOWNLOAD':
        self.slots[indx]['attempts'] = i['attempts']
        if self.slots[indx]['attempts'] > 0:
          self.slots[indx]["download_duration"] = parse_duration(i['nextattempt'])
          self.slots[indx]["formatted_duration"] = format_duration(self.slots[indx]["download_duration"])
        else:
          self.slots[indx]["download_duration"] = ""
          self.slots[indx]["formatted_duration"] = ""

      elif i['state'] == 'RUNNING':
        self.host_ppd += int(i['ppd'])
        self.slots[indx]["ppd"] = int(i['ppd'])
        self.slots[indx]["pctdone"] = i['percentdone']
        self.slots[indx]["duration"] = format_duration(parse_duration(i['eta']))

      elif i['state'] == 'SEND':
        self.slots[indx]["cs"] = i["cs"]
        self.slots[indx]["ws"] = i["ws"]
        self.slots[indx]["sunit"] = i["unit"]


def main():
  print(time.ctime(), end="\n\n")
  total_ppd = 0

  for h in hosts:
    if len(h) > 2:
      host = FAHClients(h[2], h[0], h[1])
    else:
      host = FAHClients(h[0], h[0], h[1])
    print(host.name, end="")

    
    # Load client objects
    # First find if the client has been added to vROps
    vropsObjects = vropsRequest("api/resources","GET","adapterKind=FoldingAtHome")
    fahClients = vropsObjects["resourceList"]
    fahClientRes = ""
    for fahClient in fahClients:
        if fahClient["resourceKey"]["name"] == host.name:
            fahClientRes = fahClient
            break
    # If no client found create it
    if fahClientRes == "":
        payload = {
        'description' : 'Folding@Home Client',
        'resourceKey' : {
            'name' : host.name,
            'adapterKindKey' : 'FoldingAtHome',
            'resourceKindKey' : 'Folding Client'
            }
        }
        fahClientRes = vropsRequest("api/resources/adapterkinds/foldingathome","POST","",payload,False)
    clientChildren.append(fahClientRes["identifier"])
    #print("client")
    #print(fahClientRes)
    conn = host.connect_to_server()

    #Skip parsing information if no information to parse.
    if "cannot" in conn.lower():
      print("\n" + conn, end="\n\n")
      continue

    host.parse_info()

    total_ppd += host.host_ppd
    print(': {0!s}'.format(format_ppd(host.host_ppd)))

    #Loop through hosts and output queue info based on state
    for slot, info in host.slots.items():
      timestamp = int(round(time.time()*1000))
      print("Slot: {slot!s} - Unit: {id!s}: {state!s}".format(slot=slot, id=info["unit"], state=info["state"]), end="")
      slotName = "slot"+slot
      if info["state"] == "DOWNLOAD":
        if info['attempts'] > 0:
          print(', {attempts!s} attempts, next in {duration}'.format(attempts=info['attempts'], duration=info['formatted_duration']))
        else:
          print(', 0 attempts')

      elif info["state"] == "RUNNING":
        print(", {pctdone} done, ETA: {eta}, Points: {ppd}".format(pctdone=info["pctdone"], eta=info["duration"], ppd = info["ppd"]))
        
        metricPayload = {
            "stat-content" : [ {
                "statKey" : slotName+"|percent_done",
                "timestamps" : [ timestamp ],
                "data" : [ float(info["pctdone"][:-1]) ]
            },
            {
                "statKey" : slotName+"|eta",
                "timestamps" : [ timestamp ],
                "data" : [ get_sec(info["duration"]) ]
            },
            {
                "statKey" : slotName+"|ppd",
                "timestamps" : [ timestamp ],
                "data" : [ info["ppd"] ]
            } ]
        }
        propPayload = {
            "property-content" : [{
                "statKey" : slotName+"|status",
                "timestamps" : [ timestamp ],
                "values" : [info["state"]]

            }]
        }
      elif info['state'] == 'SEND':
        print(' ~{unit} to ws {ws}, cs {cs}'.format(unit=info["sunit"][-8:], ws=info["ws"], cs=info["cs"]))

      elif info['state'] == 'READY':
        propPayload = {
            "property-content" : [{
                "statKey" : slotName+"|status",
                "timestamps" : [ timestamp ],
                "values" : [info["state"]]

            }]
        }
        if info["waiting"] == "":
            print(", PAUSED")
            propPayload = {
                "property-content" : [{
                    "statKey" : slotName+"|status",
                    "timestamps" : [ timestamp ],
                    "values" : ["PAUSED"]

                }]
            }
      else:
        print(', waiting on: {0}'.format(info["waiting"]))

      resourceId = fahClientRes["identifier"]
      #print(metricPayload)
      metricResponse = vropsRequest("api/resources/"+resourceId+"/stats","POST","",metricPayload,False)
      propResponse = vropsRequest("api/resources/"+resourceId+"/properties","POST","",propPayload,False)
    if host.slots.__len__() < 1:
      print("No active work units")

    print("")

  if len(hosts) >= 1:
    print('\nTotal ppd= {total}'.format(total=format_ppd(total_ppd)), end="\n\n")
    metricPayload = {
    "stat-content" : [ {
        "statKey" : "total_ppd",
        "timestamps" : [ timestamp ],
        "data" : [ float(total_ppd) ]
    }]}
    metricResponse = vropsRequest("api/resources/"+resourceId+"/stats","POST","",metricPayload,False)

if __name__ == "__main__":
  main()
  while loop:
    time.sleep(loopdelay*60)
    teamStats = foldRequest("/team/"+teamId,"GET")
    # Load team objects
    # First find if the team has been added to vROps
    vropsObjects = vropsRequest("api/resources","GET","adapterKind=FoldingAtHome")
    teams = vropsObjects["resourceList"]
    teamRes = ""
    for team in teams:
        if team["resourceKey"]["name"] == teamStats['name']:
            teamRes = team
            break

    # If no team found create it
    if teamRes == "":
        payload = {
        'description' : 'Folding@Home Team',
        'resourceKey' : {
            'name' : teamStats['name'],
            'adapterKindKey' : 'FoldingAtHome',
            'resourceKindKey' : 'Folding Team'
            }
        }
        teamRes = vropsRequest("api/resources/adapterkinds/foldingathome","POST","",payload,False)

    # Push team stats
    timestamp = int(round(time.time()*1000))
    payload = {
    "stat-content" : [ {
        "statKey" : "WUs",
        "timestamps" : [ timestamp ],
        "data" : [ teamStats['wus'] ]
    },{
        "statKey" : "rank",
        "timestamps" : [ timestamp ],
        "data" : [ teamStats['rank'] ]
    },{
        "statKey" : "credit",
        "timestamps" : [timestamp],
        "data" : [ teamStats['score'] ]
    },{
        "statKey" : "id",
        "timestamps" : [ timestamp ],
        "data" : [ teamStats['id'] ]
    } ]
    }
    propPayload = {
    "property-content" : [{
        "statKey" : "name",
        "timestamps" : [ timestamp ],
         "values" : [teamStats['name']]
        }]
    }

    resourceId = teamRes["identifier"]

    response = vropsRequest("api/resources/"+resourceId+"/stats","POST","",payload,True)
    propResponse = vropsRequest("api/resources/"+resourceId+"/properties","POST","",propPayload,True)

    userStats = foldRequest("/user/"+foldingUserName,"GET")
    print(userStats['name'])
    fahObjs = vropsObjects["resourceList"]
    userRes = ""
    for fahObj in fahObjs:
        if fahObj["resourceKey"]["name"] == userStats['name']:
            userRes = fahObj
            break
    if userRes == "":
        payload = {
        'description' : 'Folding@Home User',
        'resourceKey' : {
            'name' : userStats['name'],
            'adapterKindKey' : 'FoldingAtHome',
            'resourceKindKey' : 'Folding User'
            }
        }
        userRes = vropsRequest("api/resources/adapterkinds/foldingathome","POST","",payload,True)
    payload = {
    "stat-content" : [ {
        "statKey" : "general|total_score",
        "timestamps" : [ timestamp ],
        "data" : [ userStats['score'] ]
    },{
        "statKey" : "general|total_wus",
        "timestamps" : [ timestamp ],
        "data" : [ userStats['wus'] ]
    },{
        "statKey" : "general|rank",
        "timestamps" : [timestamp],
        "data" : [ userStats['rank'] ]
    } ]
    }
    propPayload = {
        "property-content" : [{
            "statKey" : "name",
            "timestamps" : [ timestamp ],
            "values" : [userStats['name']]

        }]
    }
    resourceId = userRes["identifier"]

    response = vropsRequest("api/resources/"+resourceId+"/stats","POST","",payload,True)
    propResponse = vropsRequest("api/resources/"+resourceId+"/properties","POST","",propPayload,True)

    payload = {"uuids" : clientChildren}
    response = vropsRequest("api/resources/"+userRes["identifier"]+"/relationships/CHILD","POST","",payload,True)
    clientChildren = []

    print("------------------------------------------", end="\n\n\n")
    main()









