#! /usr/bin/env python3
import argparse
import pkgutil
import time
from datetime import datetime

import urllib3
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from elasticsearch5 import Elasticsearch as Elasticsearch5

# disable ssl insecure host warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Migrate data from elastic 5 to elastic 7')
parser.add_argument('-s', '--source', type=str, metavar='SRC', required=True, help='Host value for elastic 5')
parser.add_argument('-sp', '--source-port', type=int, metavar='', required=False, default=9243, help='Port of elastic 5 host')
parser.add_argument('-su', '--source-user', type=str, metavar='', required=False, default='elastic', help='User for elastic 5 host')
parser.add_argument('-spwd', '--source-pwd', type=str, metavar='pwd', required=True, help='Password for elastic 5')
parser.add_argument('-ss', '--source-scheme', type=str, metavar='', required=False, default='https', help='Scheme for elastic 5')

parser.add_argument('-t', '--target', type=str, metavar='TGT', required=True, help='Host value for elastic 7')
parser.add_argument('-tp', '--target-port', type=int, metavar='', required=False, default=9243, help='Port of elastic 7 host')
parser.add_argument('-tu', '--target-user', type=str, metavar='', required=False, default='elastic', help='User for elastic 7 host')
parser.add_argument('-tpwd', '--target-pwd', type=str, metavar='pwd', required=True, help='Password for elastic 7')
parser.add_argument('-ts', '--target-scheme', type=str, metavar='', required=False, default='https', help='Scheme for elastic 7')

args = parser.parse_args()

# old es5 host details
es_old_host = args.source  # '9ca6245f7ae74d239b6c9040d6997c54.us-east-1.aws.found.io'
es_old_port = args.source_port  # 9243
es_old_user = args.source_user  # 'elastic'
es_old_pwd = args.source_pwd  # 'lONlBpimkkf5tpgzGbBz7aoL'
es_old_scheme = args.source_scheme  # 'https'
es_old_url = es_old_scheme + '://' + es_old_user + ':' + es_old_pwd + '@' + es_old_host + ':' + str(es_old_port)

# old es5 connection
es_old = Elasticsearch5(es_old_url, verify_certs=False, timeout=60)

# new es7 host details
es_new_host = args.target  # 'a62f208a43674c6fb4801e28fa019d12.us-east-1.aws.found.io'
es_new_port = args.target_port  # 9243
es_new_user = args.target_user  # 'elastic'
es_new_pwd = args.target_pwd  # '1MNxU3xauiu8lapBTLIKr5KY'
es_new_scheme = args.target_scheme  # 'https'
es_new_url = es_new_scheme + '://' + es_new_user + ':' + es_new_pwd + '@' + es_new_host + ':' + str(es_new_port)

# new es7 connection
es_new = Elasticsearch(es_new_url, verify_certs=False, timeout=60)

# flag to exclude current index
exclude_current_index = True

# list of indices pattern that are to be migrated to new cluster
# indices = ['agent', 'site_v1', 'idsrules-vipre*', 'exclusions*']  # , 'audit-2017*']
# indices = ['threat-2017*', 'summary-2017*', 'scans-2017*', 'quarantine-2017*', 'incident-2017*']
# indices = ['quarantine-2019*']

indices = {
	"quarantine-2019*": "weekly",
	"threats-2019*": "monthly",
	"summary-2019*": "monthly",
	"scans-2019*": "monthly",
	"incident-2019*": "monthly",
	"agent": "single",
	"site_v1": "single",
	"idsrules-vipre*": "single",
	"exclusions*": "single"
}

# indices that require aliases
aliases = {
	"site_v1": "site",
	"exclusions-vipre-2020.06.12-32851": "exclusions-vipre",
	"idsrules-vipre-2020.06.15-61651": "idsrules-vipre"
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
	for index_pattern in indices.keys():
		print '\nMigrating ' + index_pattern + " " + cur_time()
		old_cat_indices = []
		if es_old.indices.exists(index=index_pattern):
			old_cat_indices = es_old.cat.indices(index_pattern, params={"format": "json"})

		new_cat_indices = []
		index_duration = indices[index_pattern]
		if index_duration == "weekly":
			if es_new.indices.exists(index=index_pattern):
				new_cat_indices = es_new.cat.indices(index_pattern, params={"format": "json"})
		elif index_duration == "monthly":
			res_old = es_old.count(index=index_pattern)
			res_new = es_new.count(index=index_pattern)
			if res_old is not None and res_new is not None and res_old["count"] == res_new["count"]:
				print "Doc count for monthly indices for pattern " + index_pattern + " matched. Skipping to next index"
				continue

		old_index_counts = {}
		for index_stat in old_cat_indices:
			index = trim_index(index_stat['index'])
			old_index_counts[index] = index_stat['docs.count']

		new_index_counts = {}
		for index_stat in new_cat_indices:
			new_index_counts[index_stat['index']] = index_stat['docs.count']

		total_index_type_count = 0
		total_old_index_type_count = 0
		for index in sorted(es_old.indices.get(index_pattern)):

			# Exclude current index from migration
			if exclude_current_index and ((index_duration.lower() in ("weekly", "monthly") and index == target_index(
					index, index_duration)) or (index_duration.lower() == "single")):
				print "Skipping current index " + index
				continue

			index = trim_index(index)
			count = int(old_index_counts[index]) if index in old_index_counts else 0

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
				task_status = retry(check_task_status, output)

				if 'error' in task_status:
					print task_status['error']['caused_by']
				else:
					response = task_status['response']
					total_old_index_type_count += count
					total_index_type_count += response['total']
					print cur_time() + " - Migrated " + index + " with " + str(
						response['total']) + " documents in " + str(
						response['took']) + "ms"

			if total_old_index_type_count == total_index_type_count:
				print "Index pattern " + index_pattern + " successfully migrated. " + str(
					total_index_type_count) + " documents migrated."
			else:
				print "Count mismatched migrating index pattern " + index_pattern + ". " + str(
					total_index_type_count) + " docs migrated while " + str(
					total_old_index_type_count) + " found in old cluster."

		print "Indexed " + str(total_index_type_count) + " docs for " + index_pattern
		total_doc_count += total_index_type_count

	print "Indexed " + str(total_doc_count) + " docs"
	# add index aliases
	add_aliases()
	update_settings()


def retry(fun, task, max_tries=10):
	for i in range(max_tries):
		try:
			return fun(task)
		except Exception as ex:
			print("Error: {0}, Retrying!".format(ex))
			continue


def check_task_status(output):
	task_status = es_new.tasks.get(output['task'], timeout='1m')
	while not task_status['completed']:
		time.sleep(5)
		task_status = es_new.tasks.get(output['task'], timeout='1m')
	return task_status


def target_index(index, index_duration):
	if index_duration.lower() in ("weekly", "monthly"):
		idx = trim_index(index)
		idx = idx[:idx.index("-")]
		ts = int(round(time.time() * 1000))

		if index_duration == "monthly":
			date = datetime.fromtimestamp(ts / 1e3)
			return idx + "-{}-{:02}".format(date.year, date.month)
		else:
			date = datetime.fromtimestamp(ts / 1e3)
			return idx + "-{}-w{:02}".format(date.year, date.isocalendar()[1])
	else:
		return index


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
			es_new.indices.put_settings(index=index,
										body={
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
	print cur_time() + " - Migrating index " + index
	if 'quarantine' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index},
			"script": {
				"source": "if (ctx._type == 'event') {"
						  "ctx._source.eventType = [:];"
						  "ctx._source.eventType['parent'] = ctx._source.quarantineId;"
						  "ctx._source.eventType['name'] = 'quarantine-event';"
						  "} else {"
						  "ctx._source.eventType = 'quarantine';"
						  "}"}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif 'ids' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}, "script": {"source": "ctx._source.type = ctx._type;"}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif index.lower().startswith(('audit', 'summary')):
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index},
			"script": {"source": "ctx._source.type = ctx._type;"
								 "DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM\");"
								 "LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(ctx._source.timestamp), ZoneOffset.UTC);"
								 "int loc = ctx._index.indexOf('v2-');"
								 "if (loc == 0) {"
								 "ctx._index = ctx._index.substring(loc+3);"
								 "}"
								 "ctx._index = ctx._index.substring(0, ctx._index.indexOf('-')) + '-' + dateTime.format(dtf);"
					   }},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif 'exclusions' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}, "script": {"source": "ctx._source.recordType = ctx._type;"}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif index.lower().startswith(('threats', 'incident')):
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index},
			"script": {
				"source": "DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM\");"
						  "LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(ctx._source.timestamp), ZoneOffset.UTC);"
						  "int loc = ctx._index.indexOf('v2-');"
						  "if (loc == 0) {"
						  "ctx._index = ctx._index.substring(loc+3);"
						  "}"
						  "ctx._index = ctx._index.substring(0, ctx._index.indexOf('-')) + '-' + dateTime.format(dtf);"
			}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	elif 'scans' in index:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index},
			"script": {
				"source": "DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy-MM\");"
						  "LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(ctx._source.startTime), ZoneOffset.UTC);"
						  "int loc = ctx._index.indexOf('v2-');"
						  "if (loc == 0) {"
						  "ctx._index = ctx._index.substring(loc+3);"
						  "}"
						  "ctx._index = ctx._index.substring(0, ctx._index.indexOf('-')) + '-' + dateTime.format(dtf);"
			}},
			wait_for_completion=False, request_timeout=30, refresh=True)
	else:
		return es_new.reindex({"source": {
			"remote": {"host": es_old_url, "username": es_old_user, "password": es_old_pwd}, "index": index},
			"dest": {"index": new_index}},
			wait_for_completion=False, request_timeout=30, refresh=True)


# method to reindex quarantine child event to correct index
def reindex_quarantine_events(index):
	print cur_time() + " - Reindexing quarantine events for index " + index
	# JSON body for the Elasticsearch query
	search_body = {}

	# make a search() request to scroll documents
	data = es_old.search(
		index=index,
		doc_type='event',
		body=search_body,
		size=500,
		scroll='1m',  # time value for search
	)
	# Get the scroll ID
	sid = data['_scroll_id']
	scroll_size = len(data['hits']['hits'])

	while scroll_size > 0:
		idx = trim_index(index)
		idx = idx[:idx.index("-")]

		hits = data['hits']['hits']
		ids = []
		for num, doc in enumerate(hits):
			qid = doc["_source"]["quarantineId"]
			routing = doc["_routing"]
			ids.append({"_index": index, "_routing": routing, "_id": qid})

		res = es_old.mget(index=index, doc_type="quarantine",
						  body={'docs': ids}, _source_include=['timestamp'])

		id_ts = {}
		for doc in res["docs"]:
			qid = doc["_id"]
			id_ts[qid] = doc["_source"]["timestamp"]

		bulk_docs = []
		# Before scroll, process current batch of hits
		for num, doc in enumerate(hits):
			qid = doc["_source"]["quarantineId"]
			routing = doc["_routing"]
			if qid not in id_ts.keys():
				print "Quarantine id " + qid + " does not exits!"
				quit()
			ts = id_ts[qid]
			date = datetime.fromtimestamp(ts / 1e3)
			new_idx = idx + "-{}-{:02}".format(date.year, date.month)

			new_doc = doc["_source"]
			new_doc["eventType"] = {"parent": qid, "name": "quarantine-event"}
			new_doc["_index"] = new_idx
			new_doc["_routing"] = routing
			bulk_docs.append(new_doc)

		bulk_res = helpers.bulk(es_new, bulk_docs)
		if len(bulk_docs) != bulk_res[0]:
			print "Bulk index failures! Expected " + str(len(bulk_docs)) + " doc to be indexed but only " + bulk_res[
				0] + " were indexed"
			quit()
		else:
			print cur_time() + " - Reindexed " + str(len(bulk_docs)) + " quarantine events for index " + index

		data = es_old.scroll(scroll_id=sid, scroll='1m')

		# Update the scroll ID
		sid = data['_scroll_id']

		# Get the number of results that returned in the last scroll
		scroll_size = len(data['hits']['hits'])


if __name__ == '__main__':
	migrate()
