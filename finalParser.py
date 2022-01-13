#!/usr/bin/env python


#Open snort file and read it's contents
snort_file = open("snort-outfile.txt","r")

#for each line in the snort out file write into the connections list variable
connections=[]
for line in snort_file:
	connections.append(line)
snort_file.close()


#creating lists to be filled with logs later by the logSeperator function
cnc_logs = []
infection_logs= []
other_logs= []

c = 'cnc'
i = 'infection'
o = 'other'


#The following 3 lists are to store tuples of label connections i.e. |192.168.0.1|81|11.10.9.9|766|cnc|

parsedAll = {}

hosts = {}

#the following function will read each line in connections and check to see if the it contains 1 of 3 labels: cnc, infection, other the places each log type into an associated list
def logSeperator(connections):
	for connection in connections:
		if c in connection:
			cnc_logs.append(connection)
		elif i in connection:
			infection_logs.append(connection)
		elif o in connection:
			other_logs.append(connection)
		else:
			print "What the heck, this log doesn't contain a title see connectionParser method in code and fix"


#counts items in a list
def connectionsCounter(logs):
	return len(logs)


#Pulls out connection values of interest, checks dict keys with connection info, if connection not accounted for it is added to the dict
def logSpliter(log, logType):
	for each in log:
		#splitting the full text log into smaller parts
		break_log = each.split(" ")		
		
		#taking length of the now split log and storing it in var l
		l = len(break_log)

		#grabbing the last value from the split log which should be an IP:PORT
		ip1_and_port1 = break_log[l-1]
	        
		         
		#Now that we have the IP:PORT, we split it  at the colon so that we have list of 2 values
		break_ip1_from_port1 = ip1_and_port1.split(":")
	
		#Now are list of 2 values should be index0 = ip and index1 = port
		ip1 = break_ip1_from_port1[0]
		ip1 = ip1.strip()
		try:
			port1 = break_ip1_from_port1[1]
			port1 = port1.strip()	
		except:
			port1 = "EMPTY"

		#grabbing the 3rd to last value in orignal log that we split on blank space which should be an IP:PORT combo	
		ip2_and_port2 = break_log[l-3]

		#breaking apart the IP:PORT string into a list of "IP","PORT" values
		break_ip2_from_port2 = ip2_and_port2.split(":")
	
		#grabbing the first value of list containing IP,PORT
		ip2 = break_ip2_from_port2[0]
		ip2 = ip2.strip()

		#grabbing the second value of list containing IP,PORT if port value is out of range, we mark it as EMPTY
		try:
			port2 = break_ip2_from_port2[1]
			port2 = port2.strip()
		except:
			port2 = "EMPTY"

		if (str(ip1),str(port1),str(ip2),str(port2)) in parsedAll: # or ((str(ip2),str(port2),str(ip1),str(port1))) in parsedAll:
			if  parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] == 'cnc':
				pass

			elif parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] == 'infection' and logType == 'cnc':
				print "[PROBLEM]The following connection is reporting both CNC & INFECTION!!!!![PROBLEM] : "
				print ">>>",(str(ip1),str(port1),str(ip2),str(port2))
				parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] = str(logType)

			elif parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] == 'other' and logType != 'other':
				parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] = str(logType)

			else:
				pass		
		
		elif (str(ip2),str(port2),str(ip1),str(port1)) in parsedAll:
			if parsedAll[(str(ip2),str(port2),str(ip1),str(port1))] == 'cnc':
				pass

			elif parsedAll[(str(ip2),str(port2),str(ip1),str(port1))] == 'infection' and logType == 'cnc':
				print "[PROBLEM]The following connection is reporting both CNC & INFECTION!!!!![PROBLEM] : "
				print ">>>",(str(ip1),str(port1),str(ip2),str(port2))
				parsedAll[(str(ip2),str(port2),str(ip1),str(port1))] = str(logType)

			elif parsedAll[(str(ip2),str(port2),str(ip1),str(port1))] == 'other' and logType != 'other':
				parsedAll[(str(ip2),str(port2),str(ip1),str(port1))] = str(logType)
			else:
				pass
		else:
                       	parsedAll[(str(ip1),str(port1),str(ip2),str(port2))] = str(logType)

logSeperator(connections)
logSpliter(cnc_logs,c)
logSpliter(infection_logs,i)
logSpliter(other_logs,o)


#print "ALL CONNECTIONS ACCOUNTED FOR BELOW : "
#print ""
#for key, value in parsedAll.iteritems():
#	print "|"+ key[0] +"|" + key[1] +"|" + key[2] +"|" +  key[3] +"|" + value + "|"+ "\n\n"


#Open new file and write the contents of the parsedAll dict in the format requested by the assignment :
f = open("connections.txt","w")
#for each connection in parsedAll dict, write the connection in the proper format to connections.txt file:
for key, value in parsedAll.iteritems():
   f.write("|"+ key[0] +"|" + key[1] +"|" + key[2] +"|" +  key[3] +"|" + value + "|"+ "\n")
f.close()


for key,value in parsedAll.iteritems():
	if value == 'cnc':
		if key[0][0:7] == '192.168' and key[0] not in hosts.keys():
			#f2.write( "|"+ key[0] + "|" + "Bot"+ "|"+"\n"  )
			hosts[key[0]] = 'Bot' 
		elif key[2][0:7] == '192.168'and key[2] not in hosts.keys():
			#f2.write("|"+ key[2] + "|" + "Bot"+ "|"+"\n" )
			hosts[key[2]] = 'Bot'
		else:
			pass

for key,value in parsedAll.iteritems():
	if value == 'infection':
                if key[0][0:7] == '192.168'and key[0] not in hosts.keys():
                        #f2.write( "|"+ key[0] + "|" + "IsolatedInfection"+ "|"+"\n"  )
			hosts[key[0]] = 'IsolatedInfection'
                elif key[2][0:7] == '192.168' and key[2] not in hosts.keys():
                        #f2.write("|"+ key[2] + "|" + "IsoloatedInfection"+ "|" +"\n")
			hosts[key[2]] = 'IsolatedInfection'
		else: 
			pass

for key,value in parsedAll.iteritems():
        if value == 'other':
                if key[0][0:7] == '192.168'and key[0] not in hosts.keys():
                        #f2.write( "|"+ key[0] + "|" + "Benign" + "|" +"\n")
			hosts[key[0]] = 'Benign'
                elif key[2][0:7] == '192.168' and key[2] not in hosts.keys():
                        #f2.write("|"+ key[2] + "|" + "Benign"+ "|" +"\n")
			hosts[key[2]] = 'Benign'
		else:
			pass


print "Total # of CNC connections : " + str(connectionsCounter(cnc_logs))
print "Total # of Infection connections : " + str(connectionsCounter(infection_logs))
print "Total # of other connections : " + str(connectionsCounter(other_logs))
print ''

countUniqueCNC = 0
countUniqueInfections=0
countUniqueOthers=0
for key,value in parsedAll.iteritems():
	if value == 'cnc':
		countUniqueCNC+=1
	elif value =='infection':
		countUniqueInfections+=1
	else:
		countUniqueOthers+=1

		
print "Total Number of Unique Connections :\t\t", "Actual: ",len(parsedAll), "\tExpected: 30543"
print "Total Number of Unique CNC Connections:\t\t", "Actual: ", countUniqueCNC, "\tExpected: 80"
print "Total Number of Unique Infection Connections:\t", "Actual: ", countUniqueInfections, "\tExpected: 14189"
print "Total Number of Unique Other Connections:\t", "Actual: ",countUniqueOthers,"\tExpected: 16274"  

#print "The following is from the hosts dict : "

f2 = open("hosts.txt","w")
for key,value in hosts.iteritems():
	f2.write("|" + key + "|" + value + "|" + "\n")
f2.close()
