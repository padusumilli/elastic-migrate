#! /usr/bin/env python3
import argparse
import calendar
import pkgutil
import re
import time
import datetime

import urllib3
from elasticsearch import Elasticsearch
from elasticsearch5 import Elasticsearch as Elasticsearch5

# disable ssl insecure host warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Migrate data from elastic 5 to elastic 7')
parser.add_argument('-s', '--source', type=str, metavar='SRC', required=True, help='Host value for elastic 5')
parser.add_argument('-sp', '--source-port', type=int, metavar='', required=False, default=9243,
					help='Port of elastic 5 host')
parser.add_argument('-su', '--source-user', type=str, metavar='', required=False, default='elastic',
					help='User for elastic 5 host')
parser.add_argument('-spwd', '--source-pwd', type=str, metavar='pwd', required=True, help='Password for elastic 5')
parser.add_argument('-ss', '--source-scheme', type=str, metavar='', required=False, default='https',
					help='Scheme for elastic 5')

parser.add_argument('-t', '--target', type=str, metavar='TGT', required=True, help='Host value for elastic 7')
parser.add_argument('-tp', '--target-port', type=int, metavar='', required=False, default=9243,
					help='Port of elastic 7 host')
parser.add_argument('-tu', '--target-user', type=str, metavar='', required=False, default='elastic',
					help='User for elastic 7 host')
parser.add_argument('-tpwd', '--target-pwd', type=str, metavar='pwd', required=True, help='Password for elastic 7')
parser.add_argument('-ts', '--target-scheme', type=str, metavar='', required=False, default='https',
					help='Scheme for elastic 7')

group = parser.add_mutually_exclusive_group()
group.add_argument("-m", "--migrate", action='store_true', help='Run migration')
group.add_argument("-v", "--verify", action='store_true', help='Verify migration')

args = parser.parse_args()

# old es5 host details
es_old_host = args.source
es_old_port = args.source_port
es_old_user = args.source_user
es_old_pwd = args.source_pwd
es_old_scheme = args.source_scheme
es_old_url = es_old_scheme + '://' + es_old_user + ':' + es_old_pwd + '@' + es_old_host + ':' + str(es_old_port)

# old es5 connection
es_old = Elasticsearch5(es_old_url, verify_certs=False, timeout=60)

# new es7 host details
es_new_host = args.target
es_new_port = args.target_port
es_new_user = args.target_user
es_new_pwd = args.target_pwd
es_new_scheme = args.target_scheme
es_new_url = es_new_scheme + '://' + es_new_user + ':' + es_new_pwd + '@' + es_new_host + ':' + str(es_new_port)

# new es7 connection
es_new = Elasticsearch(es_new_url, verify_certs=False, timeout=60)

# flag to exclude current index
exclude_current_index = True

# list of indices pattern that are to be migrated to new cluster
indices = {
	"threats-2018*": "monthly",
	"quarantine-2018*": "weekly",
	"summary-2018*": "monthly",
	"scans-2018*": "monthly",
	"incident-2018*": "monthly",
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
		print("Adding template " + templates[template])
		data = pkgutil.get_data('resources', templates[template])
		es_new.indices.put_template(template, data)


def verify():
	print("Verifying migrated data from " + es_old_host + " to " + es_new_host + "\n")
	for index_pattern in indices.keys():
		index_duration = indices[index_pattern]
		verify_index(index_pattern, index_duration)


def verify_index(index_pattern, index_duration):
	valid = True
	print("\n" + cur_time() + " - Verifying " + index_pattern)
	new_cat_indices = []
	if index_duration == "weekly":
		old_cat_indices = []
		if es_old.indices.exists(index=index_pattern):
			old_cat_indices = es_old.cat.indices(index_pattern, params={"format": "json"})

		if es_new.indices.exists(index=index_pattern):
			new_cat_indices = es_new.cat.indices(index_pattern, params={"format": "json"})

		old_index_counts = {}
		for index_stat in old_cat_indices:
			index = trim_index(index_stat['index'])
			old_index_counts[index] = index_stat['docs.count']

		new_index_counts = {}
		for index_stat in new_cat_indices:
			new_index_counts[index_stat['index']] = index_stat['docs.count']

		for index in sorted(es_old.indices.get(index_pattern)):
			index = trim_index(index)
			count = int(old_index_counts[index]) if index in old_index_counts else 0

			reindexed_count = int(new_index_counts[index]) if index in new_index_counts else 0
			if count is not None and reindexed_count is not None and reindexed_count == count:
				print(index + " counts match in new cluster. Found " + str(count) + " docs")
			else:
				print(index + " counts DOES NOT match in new cluster. Found " + str(
					count) + " docs in old cluster and " + str(reindexed_count) + " in new cluster")
				valid = False
	elif index_duration == "monthly":
		years = set(map(lambda x: index_year(x), sorted(es_old.indices.get(index_pattern))))
		"""
		iterate through the each month of the year and validate data by month
		"""
		for year in sorted(years):
			print("Verifying " + index_pattern + " for year " + str(year))
			ret = verify_single_index(index_pattern)
			if valid:
				valid = ret

			for i in range(1, 13):
				date = datetime.datetime(year, i, 1)
				month_range = get_month_day_range(date)
				time_field = "startTime" if "scans" in index_pattern else "timestamp"
				q = {"query": {"range": {time_field: {"gte": month_range[0], "lte": month_range[1]}}}}
				res_old = es_old.count(index=index_pattern, body=q)

				month_index = index_pattern[0:index_pattern.index("-")] + "-" + str(year) + "-" + "{:02d}".format(i)
				res_new = es_new.count(index=month_index) if es_new.indices.exists(month_index) else None
				if res_old is not None and res_new is not None and res_old["count"] == res_new["count"]:
					print(month_index + " counts match in new cluster. Found " + str(res_old["count"]) + " docs")
				elif res_old is not None and res_new is not None:
					print(month_index + " counts DOES NOT match in new cluster. Found " + str(
						res_old["count"]) + " docs in old cluster and " + str(res_new["count"]) + " in new cluster")
					valid = False
				elif res_old is not None and res_old["count"] > 0:
					valid = False
	elif index_duration == "single":
		ret = verify_single_index(index_pattern)
		if valid:
			valid = ret
	return valid


def verify_single_index(index_pattern):
	res_old = es_old.count(index=index_pattern)
	res_new = es_new.count(index=index_pattern) if es_new.indices.exists(index_pattern) else None
	if res_old is not None and res_new is not None and res_old["count"] == res_new["count"]:
		print(index_pattern + " counts match in new cluster. Found " + str(res_old["count"]) + " docs")
		return True
	elif res_old is not None and res_new is not None:
		print(index_pattern + " counts DOES NOT match in new cluster. Found " + str(
			res_old["count"]) + " docs in old cluster and " + str(res_new["count"]) + " in new cluster")
		return False
	else:
		return False


def index_year(index):
	match = re.match('\\w*-([0-9]*)-\\w*', trim_index(index))
	if match:
		return int(match.group(1))
	else:
		return -1


def get_month_day_range(dt):
	"""
	For a date 'date' returns the start and end date for the month of 'date'.

	Month with 31 days:
	>>> date = dt.date(2011, 7, 27)
	>>> get_month_day_range(date)
	(datetime.date(2011, 7, 1), datetime.date(2011, 7, 31))

	Month with 28 days:
	>>> date = dt.date(2011, 2, 15)
	>>> get_month_day_range(date)
	(datetime.date(2011, 2, 1), datetime.date(2011, 2, 28))
	"""
	first_day = dt.replace(tzinfo=datetime.timezone.utc, day=1)
	last_day = dt.replace(tzinfo=datetime.timezone.utc, hour=23, minute=59, second=59, microsecond=999999,
						  day=calendar.monthrange(dt.year, dt.month)[1])
	return int(first_day.timestamp()) * 1000, int(last_day.timestamp() * 1000)


def migrate():
	print("Migrating from " + es_old_host + " to " + es_new_host + "\n")
	total_doc_count = 0
	add_index_templates()
	for index_pattern in indices.keys():
		print("\nMigrating " + index_pattern + " " + cur_time())
		old_cat_indices = []
		if es_old.indices.exists(index=index_pattern):
			old_cat_indices = es_old.cat.indices(index_pattern, params={"format": "json"})

		# validate counts if index exists in target, delete index in target when counts does not match
		new_cat_indices = []
		index_duration = indices[index_pattern]
		if index_duration == "weekly":
			if es_new.indices.exists(index=index_pattern):
				new_cat_indices = es_new.cat.indices(index_pattern, params={"format": "json"})
		elif index_duration == "monthly":
			valid = verify_index(index_pattern, index_duration)
			if not valid:
				user_res = query_yes_no("Do you want to delete count mismatched monthly index " + index_pattern + " and retry?")
				if user_res:
					print("Deleting count mismatched monthly index " + index_pattern)
					es_new.indices.delete(index_pattern)
				else:
					continue
			else:
				continue
		elif index_duration == "single":
			valid = verify_single_index(index_pattern)
			if not valid:
				user_res = query_yes_no(
					"Do you want to delete count mismatched single index " + index_pattern + " and retry?")
				if user_res:
					print("Deleting count mismatched single index " + index_pattern)
					es_new.indices.delete(index_pattern)
				else:
					continue
			else:
				continue

		old_index_counts = {}
		for index_stat in old_cat_indices:
			index = trim_index(index_stat['index'])
			old_index_counts[index] = index_stat['docs.count']

		new_index_counts = {}
		for index_stat in new_cat_indices:
			new_index_counts[index_stat['index']] = index_stat['docs.count']

		total_indexed_count = 0
		total_old_index_count = 0
		for index in sorted(es_old.indices.get(index_pattern)):

			# Exclude current index from migration
			if exclude_current_index and ((index_duration.lower() in ("weekly", "monthly") and index == target_index(
					index, index_duration)) or (index_duration.lower() == "single")):
				print("Skipping current index " + index)
				continue

			index = trim_index(index)
			count = int(old_index_counts[index]) if index in old_index_counts else 0

			# if index count match, skip to the next index
			reindexed_count = int(new_index_counts[index]) if index in new_index_counts else 0
			if count is not None and reindexed_count is not None and reindexed_count == count:
				print(index + " counts match in new cluster, skipping...")
			else:
				if es_new.indices.exists(index):
					print("Deleting older index " + index)
					es_new.indices.delete(index)

				# migrate index to new cluster
				output = reindex(index)
				task_status = retry(get_task_status, output)

				if 'error' in task_status:
					print(task_status['error']['caused_by'])
				else:
					response = task_status['response']
					total_old_index_count += count
					total_indexed_count += response['total']
					print(cur_time() + " - Migrated " + index + " with " + str(
						response['total']) + " documents in " + str(
						response['took']) + "ms")

			if total_old_index_count == total_indexed_count:
				print("Index " + index + " successfully migrated. " + str(
					total_indexed_count) + " documents migrated.")
			else:
				print("Count mismatched migrating index " + index + ". " + str(
					total_indexed_count) + " docs migrated while " + str(
					total_old_index_count) + " found in old cluster.")

		print("Indexed " + str(total_indexed_count) + " docs for " + index_pattern)
		total_doc_count += total_indexed_count

	print("Indexed " + str(total_doc_count) + " docs")

	# add index aliases
	add_aliases()
	update_settings()


def query_yes_no(question, default="yes"):
	"""Ask a yes/no question via raw_input() and return their answer.

	"question" is a string that is presented to the user.
	"default" is the presumed answer if the user just hits <Enter>.
		It must be "yes" (the default), "no" or None (meaning
		an answer is required of the user).

	The "answer" return value is True for "yes" or False for "no".
	"""
	valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
	if default is None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)

	while True:
		print(question + prompt)
		choice = input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			print("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


# Add retry to elastic calls to account for temporary connectivity issues
def retry(fun, task, max_tries=30):
	for i in range(max_tries):
		try:
			return fun(task)
		except Exception as ex:
			print("Error: {0}, Retrying!".format(ex))
			continue


# Method to retrieve the status of reindex job
def get_task_status(output):
	task_status = es_new.tasks.get(output['task'], timeout='1m')
	while not task_status['completed']:
		time.sleep(60)
		task_status = es_new.tasks.get(output['task'], timeout='1m')
	return task_status


# Compute target index name form the source index. This methods converts the weekly/monthly index names to
# monthly index names in target cluster
def target_index(index, index_duration):
	if index_duration.lower() in ("weekly", "monthly"):
		idx = trim_index(index)
		idx = idx[:idx.index("-")]
		ts = int(round(time.time() * 1000))

		if index_duration == "monthly":
			date = datetime.datetime.fromtimestamp(ts / 1e3)
			return idx + "-{}-{:02}".format(date.year, date.month)
		else:
			date = datetime.datetime.fromtimestamp(ts / 1e3)
			return idx + "-{}-w{:02}".format(date.year, date.isocalendar()[1])
	else:
		return index


def trim_index(index):
	index = index.replace('v2-', '')
	return index


def cur_time():
	now = datetime.datetime.now()
	current_time = now.strftime("%H:%M:%S")
	return current_time


# Update index settings (replicas and refresh interval)
def update_settings():
	for index_pattern in indices:
		new_index = trim_index(index_pattern)
		print("\nUpdating index settings for " + new_index)
		for index in sorted(es_new.indices.get(new_index)):
			# set refresh interval and replica count on the new index
			es_new.indices.put_settings(index=index,
										body={
											"number_of_replicas": 1,
											"refresh_interval": "5s"
										})


# Add aliases for indices in the new cluster
def add_aliases():
	print("\nAdding index aliases")
	for alias in aliases:
		print("Adding alias " + aliases[alias] + " to index " + alias)
		es_new.indices.put_alias(alias, aliases[alias])


# method to reindex from old es cluster to new
def reindex(index):
	new_index = trim_index(index)
	print(cur_time() + " - Migrating index " + index)
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


if __name__ == '__main__':
	if args.migrate:
		migrate()
	elif args.verify:
		verify()
	else:
		print("No valid option selected!")
