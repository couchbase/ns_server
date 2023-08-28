# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
import time
import math
from pprint import pprint


class StatsRangeAPITests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return [testlib.ClusterRequirements(num_nodes=2)]

    def setup(self, cluster):
        self.align_timestamps_start = -100
        self.align_timestamps_step = 7
        # wait for all nodes to scrape some stats first
        for node in cluster.connected_nodes:
            print(f'Waiting for stats at {node}')
            testlib.poll_for_condition(lambda: is_sys_stats_reported(node),
                                       1, timeout=120, verbose=True,
                                       msg='waiting for stats')

    def teardown(self, cluster):
        pass

    def basic_range_api_test(self, cluster):
        data = range_api_get(cluster, 'sys_cpu_host_seconds_total')
        self.validate_basic_range_api_res(data, cluster)

    def validate_basic_range_api_res(self, data, cluster):
        assert len(data) >= len(cluster.connected_nodes) * 4, \
               f'supposed to return at least 4 metrics per host but ' \
               f'returned {len(data)} for {len(cluster.connected_nodes)} ' \
               'nodes instead'

    def align_timestamps_test(self, cluster):
        data = range_api_get(cluster, 'sys_cpu_host_seconds_total',
                             params={'start': self.align_timestamps_start,
                                     'step': self.align_timestamps_step,
                                     'alignTimestamps': 'true'})
        self.validate_align_timestamps_res(data)

    def validate_align_timestamps_res(self, data):
        assert len(data) > 0, 'API returned empty result'
        step = self.align_timestamps_step
        for d in data:
            assert len(d['values']) > 0, 'API returned no metrics'
            for dp in d['values']:
                assert dp[0] % step == 0, f'timestamp is not aligned: {dp}'

    def filter_by_label_test(self, cluster):
        data = range_api_get(cluster, 'sys_cpu_host_seconds_total',
                             params={'mode': 'sys'})
        self.validate_filter_by_label_res(data, cluster)

    def validate_filter_by_label_res(self, data, cluster):
        assert len(data) == len(cluster.connected_nodes), \
               'api returned more metrics than expected'

    def apply_function_test(self, cluster):
        data = range_api_get(cluster.connected_nodes[0],
                             'sys_cpu_host_seconds_total/irate/sum')
        self.validate_apply_function_res(data, cluster)

    def validate_apply_function_res(self, data, cluster):
        assert len(data) == len(cluster.connected_nodes), \
               'API returned unexpected number of metrics'
        for d in data:
            assert 'mode' not in d['metric'], \
                   f'unexpected label "mode" in {d["metric"]}'

    def node_stat_test(self, cluster):
        def get_stat_from(nodes):
            return range_api_get(cluster.connected_nodes[0],
                                 'sys_cpu_host_seconds_total',
                                 params={'nodes': nodes})

        data0 = get_stat_from(cluster.connected_nodes[0].hostname())
        data1 = get_stat_from(cluster.connected_nodes[1].hostname())
        all_nodes = ','.join([n.hostname() for n in cluster.connected_nodes])
        data2 = get_stat_from(all_nodes)

        self.validate_node_stat_res(data0, data1, data2, cluster)

    def validate_node_stat_res(self, data0, data1, data_all, cluster):
        assert len(data0) >= 4, f'expected 4 metrics, got {len(data0)}'
        assert len(data1) >= 4, f'expected 4 metrics, got {len(data1)}'
        assert len(data_all) >= 4 * len(cluster.connected_nodes), \
               f'expected 4 metrics per node, got {len(data_all)}'
        assert len(data0[0]['metric']['nodes']) == 1, \
               f'expected 1 node in nodes, got {data0[0]["metric"]}'
        assert len(data1[0]['metric']['nodes']) == 1, \
               f'expected 1 node in nodes, got {data1[0]["metric"]}'
        [node0] = data0[0]['metric']['nodes']
        [node1] = data1[0]['metric']['nodes']
        for d in data0:
            assert [node0] == d['metric']['nodes'], \
                   'all metrics in data0 are expected to come from node ' \
                   f'{node0}, got {d["metric"]}'
        for d in data1:
            assert [node1] == d['metric']['nodes'], \
                   'all metrics in data1 are expected to come from node ' \
                   f'{node1}, got {d["metric"]}'
        for d in data_all:
            assert 1 == len(d['metric']['nodes']), \
                   'all metrics in data_all are supposed have 1 node in ' \
                   f'nodes, got {d["metric"]}'
        nodes_all = [d['metric']['nodes'][0] for d in data_all]
        assert node0 in nodes_all, f'node {node0} is missing in {nodes_all}'
        assert node1 in nodes_all, f'node {node1} is missing in {nodes_all}'

    def nodes_aggregation_test(self, cluster):
        params = node_aggregation_common_params()
        data1 = range_api_get(cluster.connected_nodes[0],
                              'sys_cpu_host_seconds_total',
                              params=dict(params, nodesAggregation='sum'))
        data2 = range_api_get(cluster.connected_nodes[0],
                              'sys_cpu_host_seconds_total',
                              params=params)

        self.validate_nodes_aggregation_res(data1, data2, cluster)

    # data1 is aggregated data, data2 is not aggregated data
    def validate_nodes_aggregation_res(self, data1, data2, cluster):
        timestamp = data1[0]['values'][0][0]
        sys_sum = 0
        received_sys_sum = 0
        for d in data2:
            if d['metric']['mode'] == 'sys':
                got_timestamp = d['values'][0][0]
                assert timestamp == got_timestamp, \
                       'the first datapoint is expected to have timestamp ' \
                       f'{timestamp}, got the following timestamp ' \
                       f'instead: {got_timestamp}'
                val = float(d['values'][0][1])
                print(f'got {val} for node {d["metric"]["nodes"]}')
                sys_sum += val
        print(f'calculated sum: {sys_sum}')
        for d in data2:
            assert len(d['metric']['nodes']) == 1, \
                   'not agregated metric nodes value is greater ' \
                   'than 1: {d["metric"]["nodes"]}'

        for d in data1:
            if d['metric']['mode'] == 'sys':
                got_timestamp = d['values'][0][0]
                assert timestamp == got_timestamp, \
                       'the first datapoint is expected to have timestamp ' \
                       f'{timestamp}, got the following timestamp ' \
                       f'instead: {got_timestamp}'
                received_sys_sum = float(d['values'][0][1])
                break
        for d in data1:
            assert len(d['metric']['nodes']) == len(cluster.connected_nodes), \
                   'aggregated metric nodes field does not contain all ' \
                   'nodes: {d["metric"]["nodes"]}'
        print(f'received sum: {received_sys_sum}')

        # since these are floats we can't expect them to be exactly the same
        assert abs(received_sys_sum - sys_sum) < 0.1, \
               f'actual sum for the metric ({sys_sum}) doesn\'t match ' \
               f'the value aggregated by the server ({received_sys_sum})'

    def post_test(self, cluster):
        node_aggregation_params = node_aggregation_common_params()
        req = [{'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'}]},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'}],
                'start': self.align_timestamps_start,
                'step': self.align_timestamps_step,
                'alignTimestamps': 'true'},
               {'metric': [{'label': 'name',
                            'operator': '=~',
                            'value': 'sys_cpu_host_seconds_.*'}]},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'},
                           {'label': 'mode',
                            'value': 'sys'}]},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'},
                           {'label': 'mode',
                            'value': 'sys'}],
                'applyFunctions': ['irate', 'sum']},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'}],
                'nodes': [cluster.connected_nodes[0].hostname()]},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'}],
                'nodes': [cluster.connected_nodes[1].hostname()]},
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'}],
                'nodes': [n.hostname() for n in cluster.connected_nodes]},
               dict(node_aggregation_params,
                    metric=[{'label': 'name',
                             'value': 'sys_cpu_host_seconds_total'}],
                    nodesAggregation='sum'),
               dict(node_aggregation_params,
                    metric=[{'label': 'name',
                             'value': 'sys_cpu_host_seconds_total'}]),
               {'metric': [{'label': 'name',
                            'value': 'sys_cpu_host_seconds_total'},
                           {'label': 'mode',
                            'value': 'sys'}],
                'applyFunctions': ['irate', 'sum'],
                'alignTimestamps': 'true',
                'nodesAggregation': 'sum',
                'start': -100,
                'end': -1,
                'step': 2,
                'returnRequestParams': 'true'}]
        r = testlib.post_succ(cluster.connected_nodes[0],
                              '/pools/default/stats/range',
                              json=req)
        res = r.json()
        pprint(res)
        assert len(res) == len(req), \
               'the number of results ({len(res)}) doesn\'t match ' \
               'the number of requests ({len(req)})'
        self.validate_basic_range_api_res(res[0]['data'], cluster)
        self.validate_align_timestamps_res(res[1]['data'])
        self.validate_basic_range_api_res(res[2]['data'], cluster)
        self.validate_filter_by_label_res(res[3]['data'], cluster)
        self.validate_apply_function_res(res[4]['data'], cluster)
        self.validate_node_stat_res(res[5]['data'],
                                    res[6]['data'],
                                    res[7]['data'], cluster),
        self.validate_nodes_aggregation_res(res[8]['data'],
                                            res[9]['data'], cluster)
        assert res[10]['requestParams'] == req[10], \
               f'requestParams in result {res[10]["requestParams"]} is ' \
               f'expected to match the request ({req[10]})'


def range_api_get(cluster, stat, params={}):
    r = testlib.get_succ(
          cluster,
          f'/pools/default/stats/range/{stat}',
          params=params)
    r = r.json()
    print('stats res: ')
    pprint(r)
    return r['data']


# the goal of this function is to check if sys stats has already been
# collected by prometheus
def is_sys_stats_reported(node):
    path = '/_prometheus/api/v1/query_range'
    query = 'irate(sys_cpu_host_seconds_total[1m])'
    now = math.floor(time.time())
    start = now - 10
    end = now
    r = testlib.get(node, path, params={'query': query,
                                        'start': start,
                                        'end': end,
                                        'step': 1})
    if r.status_code != 200:
        return False

    r = r.json()

    pprint(r)

    if r['status'] != 'success':
        return False

    # we expect at least 4 metric to come back: mode=idle, user, sys, other
    # macos gives these four, but linux gives us more cpu metrics
    if len(r['data']['result']) < 4:
        return False

    return len(r['data']['result'][0]['values']) >= 10


def node_aggregation_common_params():
    now = math.floor(time.time())
    return {'start': now - 10,
            'end': now,
            'step': 1}
