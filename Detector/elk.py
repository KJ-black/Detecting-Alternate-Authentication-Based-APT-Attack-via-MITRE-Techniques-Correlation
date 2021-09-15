import json
import requests

from elasticsearch.connection import create_ssl_context
from elasticsearch import Elasticsearch
from getpass import getpass


class ElasticSearch:
    """Wrapper of Elasticsearch module.
    This module is designed for using elastic search more friendly.
    """

    def __init__(self, host, credential):
        self._set_condition_func()

        requests.packages.urllib3.disable_warnings()
        self._es = Elasticsearch(
                hosts=[host],
                http_auth=credential,
                verify_certs=False)
        self._index = '*'
        self._query = {
            'query': {'bool': {'must': []}},
            'sort': {'@timestamp': {'order': 'desc'}}
        }

    def index(self, index):
        self._index = index

    def query(self):
        return json.dumps(self._query)

    def column(self, column):
        self._query['_source'] = {'includes': column}

    def sort(self, column, order):
        self._query['sort'] = {column: {'order': order}}

    def time(self, start=None, end=None):
        self._query['query']['bool']['filter'] = {
            'range': {'@timestamp': {'gte': start, 'lt': end }}
        }

    def range(self, column, start=None, end=None):
        self._query['query']['bool']['must'].append({
            'bool': {
                'filter': [{'range': {column: {'gte': start, 'lt': end}}}]
            }
        })

    def clean(self):
        self._query['query']['bool']['must'] = []

    def _set_condition_func(self):
        """Generate functions dynamically for setting conditions.
        This function will generate 6 funcions, including:
            must(conditions):
                All of the conditions must be satisfied.
            must_reg(conditions)
                All of the conditions must be satisfied in regular
                    expression matching.
            must_not(conditions)
                All of the conditions must not be satisfied.
            must_not_reg(conditions)
                All of the conditions must not be satisfied in regular
                    expression matching.
            should(conditions)
                One of the conditions must be satisfied.
            should_reg(conditions)
                One of the conditions must be satisfied in regular
                    expression matching.
        All these funcions have one parameter in `list of dict` type.
        Each element in `list` is a `dict` which have only one
            key-value pair.
        """
        def func(operation, method):
            func_name = operation + ('_reg' if method == 'regexp' else '')
            def func_code(conditions):
                clause = {
                    'bool': {operation: [{method: c} for c in conditions]}
                }
                if operation == 'should':
                    clause['bool']['minimum_should_match'] = 1
                self._query['query']['bool']['must'].append(clause)
            setattr(self, func_name, func_code)

        for operation in ['must', 'must_not', 'should']:
            for method in ['match_phrase', 'regexp']:
                func(operation, method)

    def search(self, size=None, clean=False):
        data = []

        res = self._es.search(
                index=self._index,
                size=10000 if not size else size,
                scroll='2m',
                body=self._query)
        sid = res['_scroll_id']
        count = len(res['hits']['hits'])

        while count > 0:
            data += res['hits']['hits']
            if size and len(data) >= size:
                break

            res = self._es.scroll(scroll_id=sid, scroll='2m')
            sid = res['_scroll_id']
            count = len(res['hits']['hits'])

        if clean:
            self.clean()

        return [datum['_source'] for datum in data][:size]


if __name__ == '__main__':
    es_host = 'https://140.113.194.82:9200'
    es_username = input('username:')
    es_password = getpass('password:')
    es = ElasticSearch(es_host, (es_username, es_password))
    es.index('logstash-router.zeek*')
    # es.column()

    # es.time('now-30s', 'now')
    # es.time('2020-05-14T03:10:00+0800')
    es.time('2021-04-17T15:19:19+0800', '2021-04-17T15:22:40+0800')

    # es.should_reg([{'id_orig_h': '192.168.1.*'}])

    data = es.search(size=10, clean=True)
    print(len(data))
    [print(datum) for datum in data]
    data = es.search()
    print(len(data))
    # print(data)