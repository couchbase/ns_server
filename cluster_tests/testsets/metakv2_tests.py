# @author Couchbase <info@couchbase.com>
# @copyright 2024-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
import json
import requests

METAKV2_ENDPOINT = "/_metakv2"
CONTROLLER_ENDPOINT = METAKV2_ENDPOINT + "/_controller"

def decode_json(resp):
    return testlib.json_response(resp,
                                 testlib.format_error(resp, "Invalid json"))

def assert_json_key(resp, key, json):
    return testlib.assert_json_key(key, json, testlib.format_res_info(resp))

def assert_not_changed(resp, expected_path = None):
    testlib.assert_http_code(200, resp)
    json = decode_json(resp)
    assert_json_value(resp, "message", "Not Changed", json)
    if expected_path is not None:
        assert_json_key(resp, "revision", json)
        assert_json_value(resp, "path", expected_path, json)

def assert_non_ascii_key(resp):
    testlib.assert_http_code(400, resp)
    json = decode_json(resp)
    errors = assert_json_key(resp, "errors", json)
    # A json_array or json_map body is reported one error object per item,
    # while the URL path is reported as a single object.
    if isinstance(errors, list):
        testlib.assert_eq(len(errors), 1, "errors", resp)
        errors = errors[0]
    testlib.assert_eq(errors.get("key"),
                      "Key must contain only ASCII characters.",
                      "errors.key", resp)

def assert_json_error(resp, expected):
    json = decode_json(resp)
    error = assert_json_key(resp, "error", json)
    testlib.assert_eq(error, expected, "error", resp)

def assert_json_value(resp, key, expected, json):
    v = assert_json_key(resp, key, json)
    testlib.assert_eq(v, expected, key, resp)

def assert_json_value_in(resp, key, expected, json):
    v = assert_json_key(resp, key, json)
    testlib.assert_in(v, expected, resp)

def extract_val_rev(resp, json):
    return (assert_json_key(resp, "value", json),
            assert_json_key(resp, "revision", json))

def fetch_leaves(resp, content, leaves):
    for key, value in content.items():
        r = assert_json_key(resp, "revision", value)
        if key.endswith("/"):
            if "value" in value.keys():
                fetch_leaves(resp, value["value"], leaves)
            else:
                leaves[key] = "dir"
        else:
            v = assert_json_key(resp, "value", value)
            leaves[key] = v

def extract_snapshot(resp):
    (val, rev) = assert_val_rev(resp)
    return {k: extract_val_rev(resp, v)[0] for (k, v) in val.items()}

def assert_created(resp):
    testlib.assert_http_code(201, resp)
    json = decode_json(resp)
    assert_json_key(resp, "revision", json)
    assert_json_value(resp, "message", "Created", json)

def assert_updated(resp):
    testlib.assert_http_code(200, resp)
    json = decode_json(resp)
    assert_json_key(resp, "revision", json)
    assert_json_value(resp, "message", "Updated", json)

def assert_deleted(resp):
    testlib.assert_http_code(200, resp)
    json = decode_json(resp)
    assert_json_key(resp, "revision", json)
    assert_json_value(resp, "message", "Deleted", json)

def assert_not_found(resp):
    testlib.assert_http_code(404, resp)
    json = decode_json(resp)
    assert_json_value(resp, "message", "Not Found", json)

def assert_not_empty(resp):
    testlib.assert_http_code(400, resp)
    json = decode_json(resp)
    assert_json_value(resp, "message", "Not Empty", json)

def assert_conflict(resp, key):
    testlib.assert_http_code(409, resp)
    json = decode_json(resp)
    assert_json_key(resp, "revision", json)
    assert_json_value(resp, "message", "Conflict", json)
    assert_json_value(resp, "path", key, json)

def assert_exists(resp):
    testlib.assert_http_code(200, resp)
    json = decode_json(resp)
    assert_json_key(resp, "revision", json)
    assert_json_value(resp, "message", "Exists", json)

def assert_top_level_leaf(resp, keys):
    testlib.assert_http_code(400, resp)
    json = decode_json(resp)
    assert_json_value(resp, "message",
                      "Creating top level leaves is not allowed", json)
    assert_json_value_in(resp, "path", keys, json)

def assert_val_rev(resp):
    testlib.assert_http_code(200, resp)
    json = decode_json(resp)
    return extract_val_rev(resp, json)

def assert_dir(resp, dir):
    (root, rev) = assert_val_rev(resp)
    rootdir = assert_json_key(resp, dir, root)
    (v, r) = extract_val_rev(resp, rootdir)
    leaves = {}
    fetch_leaves(resp, v, leaves)
    return leaves

def assert_value(resp, expected):
    (v, r) = assert_val_rev(resp)
    testlib.assert_eq(v, expected, "value", resp)
    return r

class Feed:
    """Reads the json objects of a continuous feed as they arrive"""
    def __init__(self, resp):
        self.resp = resp
        self.chunks = resp.iter_content(chunk_size=None)
        self.decoder = json.JSONDecoder()
        self.buf = ""

    def next(self):
        while True:
            self.buf = self.buf.lstrip()
            if self.buf:
                try:
                    obj, end = self.decoder.raw_decode(self.buf)
                    self.buf = self.buf[end:]
                    return obj
                except json.JSONDecodeError:
                    pass
            self.buf += next(self.chunks).decode("utf-8")

    def close(self):
        self.resp.close()

def assert_event(event, path, value):
    testlib.assert_eq(event.get("path"), path, "path")
    testlib.assert_eq(event.get("value"), value, "value")
    assert "revision" in event, f"no revision in {event}"

class Metakv2Tests(testlib.BaseTestSet):
    def __init__(self, cluster):
        super().__init__(cluster)

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1, memsize=1024,
                                           buckets=[])

    def setup(self):
        pass

    def teardown(self):
        pass

    def test_teardown(self):
        testlib.ensure_deleted(self.cluster, METAKV2_ENDPOINT + "/root/",
                               params={'recursive': 'true'})
        resp = self.metakv2_get("/root/")
        assert_not_found(resp)

    def metakv2_get(self, key, recursive=False, depth=None):
        params = {}
        if recursive:
            params['recursive']='true'
        if depth is not None:
            params['depth']=depth

        return testlib.request('GET', self.cluster, METAKV2_ENDPOINT + key,
                               params=params)

    def metakv2_put(self, key, create=False, rev=None, recursive=False,
                    value=""):
        params = {}
        if create:
            params['create']='true'
        if recursive:
            params['recursive']='true'
        if rev is not None:
            params['rev']=rev

        return testlib.request('PUT', self.cluster, METAKV2_ENDPOINT + key,
                               data=value, params=params)

    def metakv2_get_snapshot(self, keys):
        input = "[" + ",".join(map(lambda x: "\"" + x + "\"", keys)) + "]"
        return testlib.post_succ(self.cluster,
                                 CONTROLLER_ENDPOINT + "/getSnapshot",
                                 data=input)

    def metakv2_set_multiple(self, kvrs, recursive=False):
        params = {}
        if recursive:
            params['recursive']='true'
        input = json.dumps(kvrs)
        return testlib.request('POST', self.cluster,
                               CONTROLLER_ENDPOINT + "/setMultiple",
                               data=input, params=params)

    def metakv2_delete(self, key, recursive=False):
        params = {}
        if recursive:
            params['recursive']='true'

        return testlib.request('DELETE', self.cluster,
                               METAKV2_ENDPOINT + key, params=params)

    def metakv2_watch(self, key, recursive=False, depth=None):
        params = {'feed': 'continuous'}
        if recursive:
            params['recursive']='true'
        if depth is not None:
            params['depth']=depth

        # Not verbose, as that reads the whole body, which never ends. The
        # timeout bounds each read, so that a missing event fails the test
        resp = testlib.request('GET', self.cluster, METAKV2_ENDPOINT + key,
                               params=params, stream=True, verbose=False,
                               session=requests.Session(), timeout=10)
        testlib.assert_http_code(200, resp)
        return Feed(resp)

    def assert_dir_content(self, dir, expected, recursive=True, depth=None):
        resp = self.metakv2_get(dir, recursive=recursive, depth=depth)
        content = assert_dir(resp, dir)
        testlib.assert_eq(content, expected, "content", resp)

    def get_put_leaf_test(self):
        key = "/root/subdir/key1"
        resp = self.metakv2_get(key)
        assert_not_found(resp)

        resp = self.metakv2_put(key, value="v1")
        assert_not_found(resp)

        resp = self.metakv2_put(key, value="v1", create=True)
        assert_not_found(resp)

        resp = self.metakv2_put(key, value="v1", create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_get(key)
        assert_value(resp, "v1")

        resp = self.metakv2_put(key, value="v2", create=True, recursive=True)
        assert_conflict(resp, key)

        resp = self.metakv2_put(key, value="v2", recursive=True)
        assert_updated(resp)

        resp = self.metakv2_put(key, value="v3")
        assert_updated(resp)

        resp = self.metakv2_put(key, value="v3", create=True)
        assert_conflict(resp, key)

        resp = self.metakv2_put(key, value="v3")
        assert_not_changed(resp, key)

        self.assert_dir_content("/root/", {key: 'v3'})

        resp = self.metakv2_get(key)
        rev = assert_value(resp, "v3")

        resp = self.metakv2_put(key, value="v4", rev = "fake")
        testlib.assert_http_code(400, resp)

        resp = self.metakv2_put(key, value="v4", rev = "fake:67")
        assert_conflict(resp, key)

        resp = self.metakv2_put(key, value="v4", rev = rev)
        assert_updated(resp)
        self.assert_dir_content("/root/", {key: 'v4'})

        resp = self.metakv2_put("/top", value="v4")
        assert_top_level_leaf(resp, ["/top"])

    def get_put_dir_test(self):
        subdir = "/root/subdir/"
        dir = "/root/subdir/dir/"
        resp = self.metakv2_get(subdir)
        assert_not_found(resp)

        resp = self.metakv2_put(dir)
        assert_not_found(resp)

        resp = self.metakv2_put(subdir, recursive=True)
        assert_created(resp)

        resp = self.metakv2_put(dir)
        assert_created(resp)

        resp = self.metakv2_put(dir)
        assert_exists(resp)

        self.assert_dir_content(subdir, {})
        self.assert_dir_content(dir, {})

    def get_directory_test(self):
        resp = self.metakv2_put("/root/subdir/key1", value="v1",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_put("/root/subdir/subdir1/key2", value="v2",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_put("/root/subdir/key3", value="v3",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_put("/root/subdir1/key4", value="v4",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_get("/root/subdir2/")
        assert_not_found(resp)

        resp = self.metakv2_get("/root/subdir2/", recursive=True)
        assert_not_found(resp)

        self.assert_dir_content("/root/subdir/",
                                {'/root/subdir/key1': 'v1',
                                 '/root/subdir/key3': 'v3'},
                                recursive = False)

        self.assert_dir_content("/root/subdir/",
                                {'/root/subdir/key1': 'v1',
                                 '/root/subdir/key3': 'v3',
                                 '/root/subdir/subdir1/key2': 'v2'})

        self.assert_dir_content("/root/subdir/",
                                {'/root/subdir/key1': 'v1',
                                 '/root/subdir/key3': 'v3',
                                 '/root/subdir/subdir1/': 'dir'}, depth = 1)

        self.assert_dir_content("/root/",
                                {'/root/subdir/': 'dir',
                                 '/root/subdir1/': 'dir'}, depth = 1)

        self.assert_dir_content("/root/",
                                {'/root/subdir/key1': 'v1',
                                 '/root/subdir/key3': 'v3',
                                 '/root/subdir1/key4': 'v4',
                                 '/root/subdir/subdir1/': 'dir'}, depth = 2)

        self.assert_dir_content("/root/",
                                {'/root/subdir/key1': 'v1',
                                 '/root/subdir/key3': 'v3',
                                 '/root/subdir1/key4': 'v4',
                                 '/root/subdir/subdir1/key2': 'v2'}, depth = 3)

        self.assert_dir_content("/root/", {}, recursive = False)

    def get_snapshot_test(self):
        resp = self.metakv2_put("/root/subdir/key1", value="v1",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_put("/root/subdir/subdir1/key2", value="v2",
                                create=True, recursive=True)
        assert_created(resp)

        resp = self.metakv2_get_snapshot(["/root/subdir/key1",
                                          "/root/subdir/subdir1/key2",
                                          "/root/subdir/subdir1",
                                          "/root/subdir/subdir1/key3"])
        snapshot = extract_snapshot(resp)
        testlib.assert_eq(snapshot,
                          {'/root/subdir/key1': 'v1',
                           '/root/subdir/subdir1/key2': 'v2'}, "snapshot", resp)

    def set_multiple_test(self):
        k1 = "/root/subdir/key1"
        k2 = "/root/subdir/subdir1/key2"
        k3 = "/root/subdir1/subdir2/key3"
        k4 = "/root/subdir/subdir1/key4"

        resp = self.metakv2_set_multiple({k1: {"value": "v1"},
                                          k2: {"value": "v2"},
                                          k3: {"value": "v3"}})
        assert_not_found(resp)

        resp = self.metakv2_set_multiple({k1: {"value": "v1", "create": True},
                                          k2: {"value": "v2", "create": True},
                                          k3: {"value": "v3", "create": True}})
        assert_not_found(resp)

        # corrupted revision
        resp = self.metakv2_set_multiple(
            {k1: {"value": "v1", "create": True},
             k2: {"value": "v2", "create": True},
             k3: {"value": "v3", "revision": "rev"}},
            recursive=True)
        testlib.assert_http_code(400, resp)
        json = decode_json(resp)
        errors = assert_json_key(resp, "errors", json)
        testlib.assert_eq(errors, [{}, {}, {'revision':
                                            'Corrupted revision string'}],
                          "errors", resp)

        resp = self.metakv2_set_multiple({k1: {"value": "v1", "create": True},
                                          k2: {"value": "v2", "create": True},
                                          k3: {"value": "v3", "create": True}},
                                         recursive=True)
        assert_updated(resp)

        # already exists
        resp = self.metakv2_set_multiple({k1: {"value": "v10"},
                                          k2: {"value": "v20"},
                                          k3: {"value": "v30", "create": True}},
                                         recursive=True)
        assert_conflict(resp, k3)

        self.assert_dir_content("/root/", {k1: "v1", k2: "v2", k3: "v3"})

        resp = self.metakv2_set_multiple({k1: {"value": "v10"},
                                          k2: {"value": "v20"}}, recursive=True)
        assert_updated(resp)

        self.assert_dir_content("/root/", {k1: "v10", k2: "v20", k3: "v3"})

        resp = self.metakv2_set_multiple(
            {k3: {"value": "v30"}, k4: {"value": "v40"}})
        assert_updated(resp)

        self.assert_dir_content("/root/", {k1: "v10", k2: "v20", k3: "v30",
                                           k4: "v40"})

        resp = self.metakv2_get(k1)
        rev = assert_value(resp, "v10")

        resp = self.metakv2_set_multiple(
            {k1: {"value": "v1", "revision": "fake:70"}})
        assert_conflict(resp, k1)

        resp = self.metakv2_set_multiple({k1: {"value": "v1", "revision": rev},
                                          k2: {"value": "v2"}})
        assert_updated(resp)
        self.assert_dir_content("/root/", {k1: "v1", k2: "v2", k3: "v30",
                                           k4: "v40"})

        resp = self.metakv2_set_multiple({"/top": {"value": "v1"}})
        assert_top_level_leaf(resp, ["/top"])

        resp = self.metakv2_set_multiple({"/top1": {"value": "v1"},
                                          "/top2": {"value": "v2"}})
        assert_top_level_leaf(resp, ["/top1", "/top2"])

    def delete_test(self):
        k1 = "/root/subdir/key1"
        k2 = "/root/subdir/subdir1/key2"
        k3 = "/root/subdir1/subdir2/key3"

        resp = self.metakv2_set_multiple({k1: {"value": "v1", "create": True},
                                          k2: {"value": "v2", "create": True},
                                          k3: {"value": "v3", "create": True}},
                                         recursive=True)
        assert_updated(resp)

        self.assert_dir_content("/root/", {k1: "v1", k2: "v2", k3: "v3"})

        resp = self.metakv2_delete("/root/subdir/")
        assert_not_empty(resp)

        resp = self.metakv2_delete("/root/subdir/key2")
        assert_not_found(resp)

        resp = self.metakv2_delete("/root/subdir/key1")
        assert_deleted(resp)

        self.assert_dir_content("/root/", {k2: "v2", k3: "v3"})

        resp = self.metakv2_delete("/root/subdir/subdir1", recursive=True)
        assert_not_found(resp)

        resp = self.metakv2_delete("/root/subdir/subdir1/", recursive=True)
        assert_deleted(resp)

        self.assert_dir_content("/root/", {k3: "v3"})

        resp = self.metakv2_delete("/root/subdir/")
        assert_deleted(resp)

        self.assert_dir_content("/root/", {k3: "v3"})

        resp = self.metakv2_set_multiple({k1: {"value": "v1", "create": True},
                                          k2: {"value": "v2", "create": True}},
                                         recursive=True)
        assert_updated(resp)

        self.assert_dir_content("/root/", {k1: "v1", k2: "v2", k3: "v3"})

        resp = self.metakv2_delete("/root/subdir/", recursive=True)
        assert_deleted(resp)
        self.assert_dir_content("/root/", {k3: "v3"})

    def key_charset_round_trip_test(self):
        # A key travels as a URL path, so a caller escapes it and the server
        # decodes it once, against the raw path. The two halves have to agree
        # on every character a caller can put in a key, and the ones below are
        # those a client either escapes or leaves alone depending on which
        # escaping rules it follows. "+" is the one to watch, since a query
        # string decoder reads it as a space and a path decoder does not.
        dir = "/root/charset/"
        cases = {"a+b": "a+b",
                 "a%41b": "a%2541b",
                 "a b": "a%20b",
                 "a#b": "a%23b",
                 "a?b": "a%3Fb",
                 "a&b": "a&b",
                 "a=b": "a=b",
                 "a;b": "a;b",
                 "a:b": "a:b",
                 "a@b": "a@b",
                 "a$b": "a$b",
                 "a,b": "a,b"}

        for key, escaped in cases.items():
            resp = self.metakv2_put(dir + escaped, value=key, create=True,
                                    recursive=True)
            assert_created(resp)

            resp = self.metakv2_get(dir + escaped)
            assert_value(resp, key)

        # The listing names each leaf the way the caller meant it, which is
        # what says the server decoded the key rather than storing the
        # escaped form it arrived as.
        self.assert_dir_content(dir, {dir + key: key for key in cases})

    def key_decoders_agree_test(self):
        # A key reaches the store two ways, in the URL of a PUT and in the
        # JSON body of setMultiple, and each arrives through a decoder of its
        # own. A key written one way has to be the same key when read the
        # other way, or a caller that mixes the two silently ends up with two
        # leaves. Only ASCII is covered here, see MB-69973 for the rest.
        dir = "/root/agree/"
        cases = {"a+b": "a+b",
                 "a%41b": "a%2541b",
                 "a b": "a%20b"}

        for key, escaped in cases.items():
            body = self.metakv2_set_multiple(
                {dir + key: {"value": "written as json", "create": True}},
                recursive=True)
            assert_updated(body)

            resp = self.metakv2_get(dir + escaped)
            assert_value(resp, "written as json")

            resp = self.metakv2_put(dir + escaped, value="written as a url")
            assert_updated(resp)

            resp = self.metakv2_get_snapshot([dir + key])
            testlib.assert_eq(extract_snapshot(resp),
                              {dir + key: "written as a url"}, "snapshot",
                              resp)

    def non_ascii_key_rejected_test(self):
        # The two decoders agree only below 128, so a non-ASCII key would be
        # stored under one term when it arrives in a URL and another when it
        # arrives in a JSON body. Every entry point refuses it instead.
        # MB-73647.
        #
        # "\u4f60" is above U+00FF, which used to reach list_to_binary/1 and
        # die with badarg, so the caller saw a 500. It has to be the same 400
        # as any other refused key, which is the MB-69973 half of this.
        dir = "/root/ascii/"

        for escaped in ["a%C3%A9b", "a%E4%BD%A0b"]:
            # recursive, so that a server without the guard would create the
            # directory and store the key rather than failing on the missing
            # parent. The refusal has to be what stops it.
            assert_non_ascii_key(self.metakv2_put(dir + escaped, value="v",
                                                  create=True,
                                                  recursive=True))
            assert_non_ascii_key(self.metakv2_get(dir + escaped))
            assert_non_ascii_key(self.metakv2_delete(dir + escaped))

        # The same keys through the JSON body, where they arrive as utf8
        # bytes rather than as codepoints. getSnapshot is called directly
        # because the helper asserts success.
        for key in ["a\u00e9b", "a\u4f60b"]:
            assert_non_ascii_key(self.metakv2_set_multiple(
                {dir + key: {"value": "v", "create": True}}))
            assert_non_ascii_key(testlib.request(
                'POST', self.cluster, CONTROLLER_ENDPOINT + "/getSnapshot",
                data=json.dumps([dir + key])))

        # A refused call must not have written on its way to the 400. The
        # key itself cannot be read back to check, since the guard refuses
        # the read as well, so the directory is the only witness: it exists
        # only if one of the calls above created it.
        assert_not_found(self.metakv2_get(dir))

    def watch_dir_test(self):
        key = "/root/subdir/key1"
        deeper = "/root/subdir/subdir1/key2"
        other = "/root/other/key3"
        new = "/root/subdir/key4"

        assert_created(self.metakv2_put(key, value="v1", create=True,
                                        recursive=True))
        assert_created(self.metakv2_put(deeper, value="v2", create=True,
                                        recursive=True))
        assert_created(self.metakv2_put(other, value="v3", create=True,
                                        recursive=True))

        feed = self.metakv2_watch("/root/subdir/")
        try:
            assert_event(feed.next(), key, "v1")

            # Neither is under the watch, which the next event arriving being
            # the one for key shows
            assert_updated(self.metakv2_put(deeper, value="v20"))
            assert_updated(self.metakv2_put(other, value="v30"))

            assert_updated(self.metakv2_put(key, value="v10"))
            assert_event(feed.next(), key, "v10")

            assert_deleted(self.metakv2_delete(key))
            assert_event(feed.next(), key, None)

            assert_created(self.metakv2_put(new, value="v4", create=True))
            assert_event(feed.next(), new, "v4")
        finally:
            feed.close()

        feed = self.metakv2_watch("/root/", recursive=True, depth=2)
        try:
            testlib.assert_eq({feed.next()["path"], feed.next()["path"]},
                              {new, other}, "paths")
            assert_updated(self.metakv2_put(deeper, value="v200"))
            assert_updated(self.metakv2_put(other, value="v300"))
            assert_event(feed.next(), other, "v300")
        finally:
            feed.close()

    def watch_subscribers(self):
        resp = testlib.diag_eval(
            self.cluster,
            "length(gen_event:which_handlers("
            "chronicle_kv:event_manager(metakv))).")
        return int(resp.text.strip())

    def watch_ends_with_connection_test(self):
        before = self.watch_subscribers()
        feed = self.metakv2_watch("/root/")
        testlib.poll_for_condition(
            lambda: self.watch_subscribers() == before + 1, sleep_time=0.1,
            timeout=10, msg="watch to subscribe")
        feed.close()
        testlib.poll_for_condition(
            lambda: self.watch_subscribers() == before, sleep_time=0.1,
            timeout=10, msg="watch to unsubscribe once the client has gone")

    def watch_missing_dir_test(self):
        key = "/root/missing/key1"
        feed = self.metakv2_watch("/root/missing/")
        try:
            assert_created(self.metakv2_put(key, value="v1", create=True,
                                            recursive=True))
            assert_event(feed.next(), key, "v1")
        finally:
            feed.close()

    def watch_bad_feed_test(self):
        resp = testlib.request('GET', self.cluster, METAKV2_ENDPOINT + "/root/",
                               params={'feed': 'normal'})
        testlib.assert_http_code(400, resp)
