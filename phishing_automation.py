#! /usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from email.mime.application import MIMEApplication
from Levenshtein import distance as levenshtein
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from subprocess import Popen, PIPE
from Levenshtein import hamming
from jira import JIRA
import traceback
import requests
import json
import time
import co3
import sys
import re

requests.packages.urllib3.disable_warnings()

#True to stop ticket creation; email will be sent to Mark
DEBUG = True

'''print error messages to stderr'''
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

'''remove all attachment local copies'''
#this way local copies will be removed even if on fail
def cleanup():
	Popen("./cleanup.sh")
	print("cleaning up")

def find_shift():
	date = time.asctime()[0:11]
	hour = int(time.asctime()[11:13])
	if hour == 23: 
		return (date, 'Swing', 65)
	elif hour == 15: 
		return (date, 'Morning', 65)
	else: 
		return (date, 'Night', 102)


'''
uses the Python API wrappers in the Resilient co3 module to get all phishing cases made during
the current shift, parses the data, sets the case to review and creates and assigns a task to a
Senior Analyst
'''
class Osiris():
	def __init__(self):
		self.phishing_data = []
		self.attachments = []

		try:
			self.client = co3.SimpleClient(org_name=org, proxies=None, base_url=url.com, verify=False)
			self.client.connect(username, password)
		except:
			eprint("ERROR: Cannot create co3 SimpleClient")
			traceback.print_exc()

	def get_incidents(self):
		print("getting incidents")
		inc = self.client.get('/incidents/open')
		incidents = self.check_incidents(inc)

		#exit if no phishing cases open
		if len(incidents) < 1:
			sys.exit(0)
		else:
			for incident in incidents: 
				print('found phishing case: ' + incident['name'])
				self.get_incident_data(incident)
				self.get_attachments(incident)
#				if not DEBUG:
#					self.set_incident_review(incident)
#					self.post_task(incident)
				print('\n')

	def check_incidents(self, incidents):
		ret = []
		for incident in incidents:
			#we only want the pure phishing cases
			#keep incident if phishing and not in review
			if 22 in incident['incident_type_ids']: 
				if str(103) not in str(incident['properties']['stage']):
					#TODO: won't need the time check below after all previous phishing emails have been closed
					if int(incident['create_date']) > int(time.time() * 1000) - 8*60*60*1000: #8 hours * minutes * seconds * milliseconds
						if len(incident['incident_type_ids']) > 1:
							continue
						ret.append(incident)
		return ret

	def get_incident_data(self, incident):
		print('\tretrieving data')
		ret = {'subject':'', 'sender':'', 'date received':'', 'domain':'', 'indicators of compromise':''}
		incident_data = []

		if incident['properties']['source'] != None:
			incident_data.append(incident['properties']['source'].split('\n'))
		if incident['properties']['destination'] != None:
			incident_data.append(incident['properties']['destination'].split('\n'))
		if incident['description'] != None:
			incident_data.append(incident['description'].split('\n'))

		for pattern in [('sender\(?s?\)?\s?[:=-]', 'sender'), ('subject\(?s?\)?\s?[:=-]', 'subject'), ('domain\(?s?\)?\s?[:=-]', 'domain'), ('date received\(?s?\)?\s?[:=-]', 'date received'), ("indicator'?s? of compromise\s?[:=-]?", 'indicators of compromise')]:
			ret[pattern[1]] = self.match_regex(incident_data, pattern)

		#if regex doesn't match use hamming and levenshtein distances to match
		for datatype in self.is_empty(ret):
			ret[datatype] = self.check_edit_distances(incident_data, datatype)

		self.phishing_data.append(ret)

	def match_regex(self, incident_data, pattern):
		for iList in incident_data:
			for count, line in enumerate(iList):
				if re.search(pattern[0], line, re.I): #re.I ignores upper/lowercase, re.search matches anywhere in the string
					if pattern[1] == 'indicators of compromise':
						return self.ret_indicators_of_compromise(iList[count:])
					else:
						try:
							match = re.match(pattern[0], line, re.I)
							return str(line.split(str(match.group(0)))[1]).strip() #will return none on no match
						except:
							eprint("\tERROR: regex failed on " + pattern[1])
							traceback.print_exc()
		return ''

	#we have to rely solely on user input, this will give us some flexibility for spelling/grammar mistakes
	#2 spelling mistakes are allowable per hamming distance
	#2 extra/missing characters are allowable per levenshtein distance
	def check_edit_distances(self, incident_data, datatype):		
		for iList in incident_data:
			for count in range(0, len(iList)):
				split_line = iList[count].replace('=',':').replace('-',':').split(':')
				d_type = str(split_line[0].lower().strip())

				hamming = self.check_hamming_distance(iList[count:], datatype, d_type, split_line)
				if hamming != '':
					return hamming
					
				levenshtein = self.check_levenshtein_distance(iList[count:], datatype, d_type, split_line)
				if levenshtein != '':
					return levenshtein
	
	#hamming distance will check for misspellings		
	def check_hamming_distance(self, iList, datatype, d_type, split_line):
		MAX_SPELLING_ERRORS = 2

		if len(d_type) == len(datatype):
			if hamming(d_type, datatype) <= MAX_SPELLING_ERRORS: 
				if datatype == 'indicators of compromise':
					print('\tno regex match on %s, using hamming distance' % datatype)
					return self.ret_indicators_of_compromise(iList)
				else:
					print('\tno regex match on %s, using hamming distance' % datatype)
					return ''.join(split_line[1:])
		return ''

	#levenshtein distance will check if there is an extra character inserted, or missing character
	def check_levenshtein_distance(self, iList, datatype, d_type, split_line):
		MAX_SPELLING_ERRORS = 2

		if levenshtein(d_type.lower(), datatype) <= MAX_SPELLING_ERRORS: 
			if datatype == 'indicators of compromise':
				print('\tno regex match on %s, using Levenshtein distance' % datatype)
				return self.ret_indicators_of_compromise(iList)
			else:
				print('\tno regex match on %s, using Levenshtein distance' % datatype)
				return ''.join(split_line[1:])
		return ''

	def ret_indicators_of_compromise(self, iList):
		temp = []
		for num, item in enumerate(iList):
			if num == 0:
				ioc = iList[0].replace('=',':').replace('-',':').split(':')
				if len(ioc) > 1:
					temp.append(ioc[1])
					continue
			if item == '' and num != 0:
				break
			temp.append(item)
		return temp


	def is_empty(self, dictionary):
		empty = []

		for key in dictionary.keys():
			if dictionary[key] == '' or dictionary[key] == None:
				empty.append(key)

		return empty

	#stores all attachments in /{PATH}/temp/
	#removed by cleanup()
	def get_attachments(self, incident):
		attachments = self.client.get('/incidents/'+str(incident['id'])+'/attachments')
		if len(attachments) > 0:
			for attachment in attachments:
				att = self.client.get_content('/incidents/'+str(incident['id'])+'/attachments/'+str(attachment['id'])+'/contents')
				try:
					with open('temp/' + attachment['name'], 'w') as ifile:
						print('\tfound attachment: ' + attachment['name'] + ', writing to file')
						self.attachments.append(attachment['name'])
						ifile.write(att)
				except:
					eprint("ERROR: failed to copy attachments for " + incident['name'])
					traceback.print_exc()

	def set_incident_review(self, incident):
		print('\tsetting case to review')
		incident['properties']['stage'] = 103 #103 == review
		self.client.put('/incidents/' + str(incident['id']), json.loads(json.dumps(incident)))

	def post_task(self, incident):
		print(message)
		incident_id = incident['id']

		owner = find_shift()[2]

		task = { task1: info,
				task2: info, 
				task3: info
		} 

		self.client.post("/incidents/" + str(incident_id) + "/tasks", task)


'''
This class creates a Jira ticket, adds all data gathered from the Osiris class as a comment
to the ticket (one comment per case), and adds all attachments found in Osiris phishing cases
'''
class JiraTicket:
	def __init__(self, attachments):
		jira_options = { 'server': server.com, 'verify': False }	
		try:
			self.jira = JIRA(options=jira_options, basic_auth=(username, password))
			self.jira._session.proxies={'http':'proxy.com', 'https':'proxy.com'}
		except:
			eprint("ERROR: cannot create JIRA object.  Is Jira down?")
			traceback.print_exc()

		self.comments = [] #populated in add_comments(), global needed for email
		self.attachments = attachments
		self.ticket = "" #populated in create_ticket()

	def create_ticket(self):
		date = find_shift()
		summary = date[0] + "phishing indicators and IOC's - " + date[1] 
		description = 	"""
						helpful information
						"""
		jira_payload = {
						'project' : {'key' : team},
						'issuetype' : {'name' : 'Other'},
						'customfield_11802' : 	{ #This is the "Requesting Team"
												'id' : id_num,	#this is needed
												'key' : team,	#this is also needed
												'name' : team_name
												},
						'summary' : summary,
						'description': "Daily phishing indicators and IOC's from " + date[1] + " " + date[0] + description
						}

		try:
			new_ticket = self.jira.create_issue(fields=jira_payload)
			self.ticket = new_ticket.key
			print("created ticket: " + new_ticket.key)			
		except:
			eprint("ERROR: cannot create new Jira ticket")
			traceback.print_exc()

	def add_comments(self, phishing_data):
		for data in phishing_data:
			#this comment_list will be used in the email as well
			#*<text>* is bold in Jira
			comment_list = []
			comment_list.append('*Subject*: ' + data['subject'])
			comment_list.append('*Sender*: ' + data['sender'].replace('@', '(@)')) #unlink emails
			comment_list.append('*Date Received*: ' + data['date received'])
			comment_list.append('*Domain*: ' + data['domain'].replace('http', 'hxxp').replace('[.]', '.').replace('.', '[.]') + '\n') #unlink URL's

			#IOC's are multiline and come as it's own list, must iterate through
			#don't join, it will remove all multiline formatting
			comment_list.append('*Indicators of Compromise*')
			for IOC in data['indicators of compromise']:
				comment_list.append(IOC)

			comment = '\n'.join(comment_list) #This is our comment for Jira
			#this is extra stuff added for the email
			self.comments.append(comment + '<br><br>')
			self.comments.append('-------------------------------------<br><br>')

			try:
				if not DEBUG:
					self.jira.add_comment(self.ticket, comment)
				print('adding comments to ticket')
			except:
				eprint("ERROR: unable to add comments to Jira ticket")
				traceback.print_exc()

	def add_attachment(self):
		for name in self.attachments:
			try:
				with open('temp/' + name, 'rb') as ifile:
					self.jira.add_attachment(self.ticket, ifile)
					print( self.ticket + ': attaching ' + name)
			except:
				eprint("ERROR: unable to add attachment " + name + " to ticket " + self.ticket)
				traceback.print_exc()


'''
This class sends out an email version of the Jira Ticket to to@email.com
and to2@email.com
'''
class Email: #TODO: I should just make this a module...
	def __init__(self, comments, attachments):
		self.comments = comments
		self.attachments = attachments

	def send_email(self):
		message = MIMEMultipart('alternative')
		message['Subject'] = "subject - " + time.asctime()[0:11]
		message['To'] = to@email.com
		if DEGUG:
			message['To'] = developer@email.com
		message['From'] = from@email.com	   

		suffix = '''Required Actions:'''
		
		self.comments.insert(0, prefix<br><br>') 
		self.comments.insert(1, prefix2)
		self.comments.append(suffix)

		#adding phishing information and getting rid of Jira text formatting
		payload = MIMEText('\n\n'.join(comment.replace('*','').replace('\n','<br>') for comment in self.comments), 'html')
		message.attach(payload)

		#adding attachments
		for name in self.attachments:
			try:
				with open('temp/' + name, 'rb') as ifile:
					print('Email: attaching ' + name)
					attachment = MIMEApplication(ifile.read(), Name=name)
					attachment['Content-Disposition'] = 'attachment; filename="%s"' % name
					message.attach(attachment)
			except:
				eprint("ERROR: unable to attach " + name + " to email")

		print("Sending Email")
		try:
			process = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin = PIPE) #-t reads message for recipients. -oi ignores single dots on lines by themselves
			process.communicate(message.as_string())
		except:
			eprint('ERROR: Unable to send email')
			traceback.print_exc()


def main():
	osiris = Osiris()
	osiris.get_incidents()

	jira_ticket = JiraTicket(osiris.attachments)
	if not DEBUG:
		jira_ticket.create_ticket()	
	jira_ticket.add_comments(osiris.phishing_data)
	if not DEBUG:		
		jira_ticket.add_attachment()

	email = Email(jira_ticket.comments, osiris.attachments)
	email.send_email()

	cleanup()

if __name__ == "__main__":
	main()



