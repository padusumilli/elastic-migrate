#! /usr/bin/env python3
import pkgutil
import time
from datetime import datetime

import urllib3
from elasticsearch import Elasticsearch
from elasticsearch5 import Elasticsearch as Elasticsearch5

# disable ssl insecure host warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# old es5 host details
es_old_host = 'abcdef.us-east-1.aws.found.io'
es_old_port = 9243
es_old_user = 'elastic'
es_old_pwd = 'abced'
es_old_scheme = 'https'
es_old_url = es_old_scheme + '://' + es_old_user + ':' + es_old_pwd + '@' + es_old_host + ':' + str(es_old_port)

# old es5 connection
es_old = Elasticsearch5(es_old_url, verify_certs=False, timeout=60)

# new es7 host details
es_new_host = 'qwerty.us-east-1.aws.found.io'
es_new_port = 9243
es_new_user = 'elastic'
es_new_pwd = 'qwerty'
es_new_scheme = 'https'
es_new_url = es_new_scheme + '://' + es_new_user + ':' + es_new_pwd + '@' + es_new_host + ':' + str(es_new_port)

# new es7 connection
es_new = Elasticsearch(es_new_url, verify_certs=False, timeout=60)

# list of indices pattern that are to be migrated to new cluster
indices = ['agent', 'threats*', 'summary*', 'scan*', 'quarantine*', 'incident*', 'site_v1', 'idsrules-vipre*',
		   'exclusions*', 'audit*']
# indices = ['audit*']

# indices that require aliases
aliases = {
	"site_v1": "site"
}

templates = {
	'agent-mapping': 'agent-mapping.json',
	'audit-mapping': 'audit-mapping.json',
	'incident-mapping': 'incident-mapping.json',
	'quarantine-mapping': 'quarantine-mapping.json',
	'scans-mapping': 'scans-mapping.json',
	'site-mapping': 'site-mapping.json',
	'summary-mapping': 'summary-mapping.json',
	'threats-mapping': 'threats-mapping.json',
	'exclusion-vipre-mapping': 'exclusion-vipre-mapping.json',
	'exclusion-custom-mapping': 'exclusion-custom-mapping.json',
	'idsrules-vipre-mapping': 'idsrules-vipre-mapping.json'
}


# Add index templates for the new cluster
def add_index_templates():
	for template in templates:
		print 'Adding template ' + templates[template]
		audit = pkgutil.get_data('resources', templates[template])
		es_new.indices.put_template(template, audit)


def migrate():
	print 'Migrating from ' + es_old_host + ' to ' + es_new_host + '\n'
	total_doc_count = 0
	add_index_templates()
	for index_pattern in indices:
		print '\nMigrating ' + index_pattern + " " + cur_time()
		old_cat_indices = []
		if es_old.indices.exists(index=index_pattern):
			old_cat_indices = es_old.cat.indices(index_pattern, params={"format": "json"})

		new_cat_indices = []
		if es_new.indices.exists(index=index_pattern):
			new_cat_indices = es_new.cat.indices(index_pattern, params={"format": "json"})

		old_index_counts = {}
		for index_stat in old_cat_indices:
			index = trim_index(index_stat['index'])
			old_index_counts[index] = index_stat['docs.count']

		new_index_counts = {}
		for index_stat in new_cat_indices:
			new_index_counts[index_stat['index']] = index_stat['docs.count']

		total_index_type_count = 0
		for index in sorted(es_old.indices.get(index_pattern)):
			index = trim_index(index)
			count = int(old_index_counts[index]) if index in old_index_counts else 0
			total_index_type_count += count
			# if index count match, skip to the next index
			reindexed_count = int(new_index_counts[index]) if index in new_index_counts else 0
			if count is not None and reindexed_count is not None and reindexed_count == count:
				print index + ' counts match in new cluster, skipping...'
			else:
				if es_new.indices.exists(index):
					print "Deleting older index " + index
					es_new.indices.delete(index)

				# migrate index to new cluster
				output = reindex(index)
				task_status = es_new.tasks.get(output['task'], timeout='1m')
				while not task_status['completed']:
					time.sleep(5)
					task_status = es_new.tasks.get(output['task'], timeout='1m')

				if 'error' in task_status:
					print task_status['error']['caused_by']
				else:
					response = task_status['response']
					print cur_time() + " - Migrated " + index + " with " + str(response['total']) + " documents in " + \
						  str(response['took']) + "ms"

		print "Indexed " + str(total_index_type_count) + " docs for " + index_pattern
		total_doc_count += total_index_type_count

	print "Indexed " + str(total_doc_count) + " docs"
	# add index aliases
	add_aliases()
	update_settings()


def trim_index(index):
	index = index.replace('v2-', '')
	return index


def cur_time():
	now = datetime.now()
	current_time = now.strftime("%H:%M:%S")
	return current_time


# Update index settings (replicas and refresh interval)
def update_settings():
	for index_pattern in indices:
		new_index = trim_index(index_pattern)
		print '\nUpdating index settings for ' + new_index
		for index in sorted(es_new.indices.get(new_index)):
			# set refresh interval and replica count on the new index
			es_new.indices.put_settings(index=index, body={
											"number_of_replicas": 1,
											"refresh_interval": "5s"
										})


# Add aliases for indices in the new cluster
def add_aliases():
	print "\nAdding index aliases"
	for alias in aliases:
		print 'Adding alias ' + aliases[alias] + ' to index ' + alias
		es_new.indices.put_alias(alias, aliases[alias])


# method to reindex from old es cluster to new
def reindex(index):
	new_index = trim_index(index)
	print cur_time() + " - Migrating index " + index + " to index " + new_index
	if 'quarantine' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}, "script": {
				"source": "if (ctx._type == 'event') {"
						  "ctx._source.eventType = [:];"
						  "ctx._source.eventType['parent'] = ctx._source.quarantineId;"
						  "ctx._source.eventType['name'] = 'quarantine-event';"
						  "} else {"
						  "ctx._source.eventType = 'quarantine';"
						  "}"
			}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif ('ids' or 'audit' or 'summary') in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}, "script": {"source": "ctx._source.type = ctx._type;"}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif 'exclusions' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}, "script": {"source": "ctx._source.recordType = ctx._type;"}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	else:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}}, wait_for_completion=False, request_timeout=30,
			refresh=True)


if __name__ == '__main__':
	migrate()
