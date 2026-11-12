%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc
%% A fake four-node cluster (two buckets, one node without a status, one
%% 7.x node) with node statuses shaped like real heartbeats, for tests that
%% build REST replies from ns_doctor's snapshot. publish/2 stores the
%% statuses in the snapshot either as received or projected, so a test can
%% check that a reply is the same both ways, i.e. that
%% ns_doctor:project_status/1 keeps every field the reply reads.
-module(fake_node_statuses).

-include("ns_common.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([setup/0,
         teardown/1,
         cases/0,
         set_cluster/2,
         statuses/1,
         publish/2,
         delete_snapshot/0,
         delete_tasks_version/0,
         assert_no_doctor_calls/0,
         stats_fan_out/0,
         bucket_names/0,
         bucket_props/2,
         bucket_map/1]).

-define(REMOTE, 'ns_1@remote.example').
-define(OLD7X, 'ns_1@old7x.example').
-define(ABSENT, 'ns_1@absent.example').
-define(BUCKET_UUID, <<"0123456789abcdef0123456789abcdef">>).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

setup() ->
    setup_cluster(),
    meck:new(ns_doctor, [passthrough]).

teardown(_) ->
    ns_doctor:delete_snapshot_table(),
    teardown_cluster().

%% {Variant, ClusterCompat, Enterprise} combinations worth comparing.
cases() ->
    [{healthy, [8, 0], true},
     {warmup, [8, 0], true},
     {healthy, [7, 6], true},
     {healthy, [8, 0], false}].

bucket_names() ->
    ["default", "magma"].

set_cluster(Compat, Enterprise) ->
    fake_ns_config:setup_cluster_compat_version(Compat),
    fake_chronicle_kv:setup_cluster_compat_version(Compat),
    fake_ns_config:update_snapshot({node, node(), is_enterprise}, Enterprise).

%% Publish rows the way ns_doctor does: either the statuses as received
%% (full, as get_nodes returns them) or projected.
publish(Statuses, Mode) ->
    ns_doctor:delete_snapshot_table(),
    ns_doctor:create_snapshot_table(),
    lists:foreach(fun ({Node, Status}) ->
                          ns_doctor:store_snapshot_row(Node, row(Mode, Status))
                  end, Statuses),
    ns_doctor:store_tasks_version("12345").

row(full, Status) -> Status;
row(projected, Status) -> ns_doctor:project_status(Status).

%% As if ns_doctor were restarting: readers fall back to calling it.
delete_snapshot() ->
    ns_doctor:delete_snapshot_table().

delete_tasks_version() ->
    ets:delete(ns_doctor_snapshot, tasks_version).

%% No builder may still go to the ns_doctor process: if one did, it would get
%% nothing here (ns_doctor isn't running) in both builds and the comparison
%% would pass without testing anything.
assert_no_doctor_calls() ->
    Calls = [{get_nodes, 0}, {get_node, 1}, {get_tasks_version, 0},
             {wait_statuses, 2}, {get_memory_data, 1}],
    ?assertEqual([], [{F, A} || {_, {ns_doctor, F, A}, _} <-
                                    meck:history(ns_doctor),
                                lists:member({F, length(A)}, Calls)]).

%% Calls to stats_interface:buckets_interesting/1 since the last check.
stats_fan_out() ->
    Calls = [Args || {_, {stats_interface, buckets_interesting, Args}, _}
                         <- meck:history(stats_interface)],
    meck:reset(stats_interface),
    Calls.

%% ---------------------------------------------------------------------------
%% Fixtures
%% ---------------------------------------------------------------------------

%% KV nodes; ?ABSENT has no status at all.
cluster_nodes() ->
    #{node() => {active, [kv, index, fts, n1ql]},
      ?REMOTE => {active, [kv, index, cbas, eventing, backup]},
      ?OLD7X => {active, [kv]},
      ?ABSENT => {active, [kv]}}.

encr_info() ->
    [{data_status, encrypted}, {dek_num, 2}, {issues, []},
     {oldest_dek_datetime, {{2026, 11, 1}, {10, 20, 30}}}].

%% Every key ns_heart sends (ns_heart:status_slow_keys/0 plus the quick and
%% linux keys), with values shaped like a real heartbeat. Keys that no
%% /pools/default reader uses are present on purpose: the projection must
%% drop them without changing the output.
full_status(Node, Opts) ->
    Ready = maps:get(ready, Opts, ["default", "magma"]),
    Hashes = maps:get(incoming, Opts, incoming_hashes(Node)),
    NeedsRebalance = maps:get(needs_rebalance, Opts, false),
    [{now, -576460750000000000},
     {active_buckets, ["default", "magma"]},
     {ready_buckets, Ready},
     {status_latency, 7},
     {stale_slow_status, -576460751000000000},
     {outgoing_replications_safeness_level,
      [{"default", maps:get(safeness, Opts, green)}, {"magma", yellow}]},
     {incoming_replications_conf_hashes, Hashes},
     {{service_status, fts}, [{needs_rebalance, false}]},
     {{service_status, index}, [{needs_rebalance, NeedsRebalance}]},
     {{service_status, cbas}, [{needs_rebalance, false}]},
     {{service_status, eventing}, [{needs_rebalance, false}]},
     {{service_status, backup}, [{needs_rebalance, false}]},
     {{service_status, n1ql}, [{needs_rebalance, false}]},
     {local_tasks, big_local_tasks(Node)},
     {memory, [{total, 123456789}, {processes, 23456789}]},
     {cpu_count, maps:get(cpu_count, Opts, 16)},
     {system_memory_data, [{system_total_memory, 68719476736}]},
     {node_storage_conf, [{db_path, "/data/cb/data"},
                          {index_path, "/index/cb"}]},
     {statistics, [{context_switches, {123, 0}}, {run_queue, 0}]},
     {system_stats, [{cpu_utilization_rate, 12.5}, {cpu_stolen_rate, 0},
                     {swap_total, 0}, {swap_used, 0},
                     {mem_total, 68719476736}, {mem_free, 34359738368},
                     {mem_limit, 68719476736}, {mem_actual_used, 30000000000},
                     {mem_cgroup_limit, 0}, {mem_cgroup_used, 0},
                     {cpu_cores_available, 16}, {cpu_host_cores_available, 16},
                     {allocstall, 0}]},
     {interesting_stats, [{cmd_get, 10.0}, {couch_docs_actual_disk_size, 4096},
                          {couch_views_actual_disk_size, 1024},
                          {curr_items, 100}, {mem_used, 104857600},
                          {ops, 25.0}]},
     {per_bucket_interesting_stats,
      [{"default", [{mem_used, 52428800}, {curr_items, 50}]},
       {"magma", [{mem_used, 52428800}, {curr_items, 50}]}]},
     {processes_stats, [{proc_memcached_cpu_utilization, 5.0}]},
     {version, [{public_key, "1.15"}, {ns_server, "8.0.4-6357-enterprise"},
                {kernel, "10.2"}]},
     {supported_compat_version, [8, 0]},
     {advertised_version, [8, 0, 4]},
     {system_arch, "x86_64-pc-linux-gnu"},
     {wall_clock, 98765},
     {memory_data, {68719476736, 30000000000, undefined}},
     {disk_data, [{"/", 104857600, 40}, {"/data", 1048576000, 25},
                  {"/index", 524288000, 10}]},
     {encryption_at_rest_info,
      [{config_encryption, encr_info()},
       {log_encryption, encr_info()},
       {audit_encryption, encr_info()},
       {{bucket_encryption, ?BUCKET_UUID}, encr_info()}]},
     {data_disk_bytes_available, 786432000},
     {data_disk_bytes_used, 262144000},
     %% not this node's product, so a missing field shows
     {prod, "columnar"},
     {prod_name, "Enterprise Analytics"},
     {cpu_pressure, [{some, 1.0}]},
     {io_pressure, [{some, 1.0}]},
     {loadavg, [1.0, 1.0, 1.0]},
     {meminfo, <<"MemTotal: 1 kB">>},
     {memory_pressure, [{some, 1.0}]},
     %% a key a future version might send
     {some_future_key, [{a, 1}]}].

%% What ns_heart reports for the replications into Node: one hash per
%% source node and bucket, matching the bucket map (so replication is
%% started), except from ?OLD7X into the local node for "default" (so that
%% node's replication shows as not started, 0.0).
incoming_hashes(Node) ->
    [{B, [{Src, case {B, Src, Node} =:= {"default", ?OLD7X, node()} of
                    true -> 0;
                    false ->
                        erlang:phash2(ns_bucket:replicated_vbuckets(
                                        bucket_map(B), Src, Node))
                end}
          || Src <- [node(), ?REMOTE, ?OLD7X, ?ABSENT], Src =/= Node]}
     || B <- ["default", "magma"]].

%% A 7.x node: no prod/prod_name, no encryption info, no
%% supported_compat_version.
old_status(Node) ->
    Drop = [prod, prod_name, encryption_at_rest_info, supported_compat_version],
    [KV || {K, _} = KV <- full_status(Node, #{cpu_count => 4,
                                              ready => ["default"]}),
           not lists:member(K, Drop)].

big_local_tasks(Node) ->
    [[{type, xdcr},
      {id, iolist_to_binary(io_lib:format("~p/default/default/~p",
                                          [Node, I]))},
      {errors, []}, {changes_left, I}, {docs_checked, I}, {docs_written, I},
      {max_vbreps, 16}
      | [{list_to_atom("xdcr_stat_" ++ integer_to_list(K)), K}
         || K <- lists:seq(1, 20)]]
     || I <- lists:seq(1, 5)].

%% Statuses as ns_doctor stores them (after update_status).
statuses(Variant) ->
    LastHeard = erlang:monotonic_time(),
    Old = LastHeard - erlang:convert_time_unit(60, second, native),
    Local =
        case Variant of
            healthy -> full_status(node(), #{needs_rebalance => true});
            warmup -> full_status(node(), #{ready => ["default"]})
        end,
    [{node(), [{last_heard, LastHeard} | Local]},
     {?REMOTE, [{last_heard, Old} |
                full_status(?REMOTE, #{safeness => yellow,
                                       cpu_count => 8})]},
     {?OLD7X, [{last_heard, LastHeard} | old_status(?OLD7X)]}].

%% ---------------------------------------------------------------------------
%% Setup
%% ---------------------------------------------------------------------------

setup_cluster() ->
    meck:new(config_profile, [passthrough]),
    meck:expect(config_profile, get,
                fun () -> ?DEFAULT_EMPTY_PROFILE_FOR_TESTS end),
    fake_ns_config:setup(),
    fake_chronicle_kv:setup(),
    stub_unrelated(),
    fake_config_helpers:setup_cluster_config(cluster_nodes()),
    setup_buckets(),
    fake_chronicle_kv:update_snapshot(
      server_groups, [[{uuid, <<"0">>}, {name, <<"Group 1">>},
                       {nodes, maps:keys(cluster_nodes())}]]),
    fake_ns_config:update_snapshot(
      lists:append(
        [[{{node, N, rest}, [{port, 8091}, {port_meta, global}]},
          {{node, N, eventing_dir}, "/data/cb/eventing"},
          {{node, N, cbas_dirs}, ["/data/cb/cbas"]},
          %% mcdMemoryReserved: configured on one node, derived from the
          %% node's memory on the others
          {{node, N, memcached},
           [{port, 11210} | [{max_size, 4096} || N =:= ?REMOTE]]}]
         || N <- maps:keys(cluster_nodes())])),
    ok.

%% Inputs of /pools/default that do not come from ns_doctor. They are the
%% same in both builds, so constants are enough.
stub_unrelated() ->
    meck:new(cb_dist, [passthrough]),
    meck:expect(cb_dist, address_family, fun () -> inet_tcp_dist end),
    meck:expect(cb_dist, client_cert_verification, fun () -> false end),
    meck:new(cb_epmd, [passthrough]),
    meck:expect(cb_epmd, port_for_node, fun (_, _) -> 21100 end),
    meck:new(capi_utils, [passthrough]),
    meck:expect(capi_utils, capi_url_bin,
                fun (_, Path, _) -> <<"http://h:8092", Path/binary>> end),
    meck:expect(capi_utils, capi_bucket_url_bin,
                fun (_, B, _, _) ->
                        iolist_to_binary(["http://h:8092/", B])
                end),
    meck:new(menelaus_web, [passthrough]),
    meck:expect(menelaus_web, get_uuid, fun () -> <<"uuid">> end),
    meck:new(service_index, [passthrough]),
    meck:expect(service_index, get_indexes_version, fun () -> {ok, 1} end),
    meck:new(ns_server_cert, [passthrough]),
    meck:expect(ns_server_cert, trusted_CAs, fun (_) -> [] end),
    meck:new(ns_cluster, [passthrough]),
    meck:expect(ns_cluster, counters, fun () -> [] end),
    meck:new(ns_audit_cfg, [passthrough]),
    meck:expect(ns_audit_cfg, get_uid, fun () -> "audit-uid" end),
    meck:new(menelaus_web_alerts_srv, [passthrough]),
    meck:expect(menelaus_web_alerts_srv, fetch_alerts, fun () -> {[], ""} end),
    meck:new(menelaus_web_autocompaction, [passthrough]),
    meck:expect(menelaus_web_autocompaction, build_global_settings,
                fun () -> {[]} end),
    meck:new(menelaus_web_rbac, [passthrough]),
    meck:expect(menelaus_web_rbac, check_permissions_url_version,
                fun (_) -> 1 end),
    meck:new(memory_quota, [passthrough]),
    meck:expect(memory_quota, get_quota,
                fun (Config, kv) -> meck:passthrough([Config, kv]);
                    (_, _) -> {ok, 1024}
                end),
    %% basic stats ask the nodes directly for those without
    %% per_bucket_interesting_stats in their status
    meck:new(stats_interface, [passthrough]),
    meck:expect(stats_interface, buckets_interesting, fun (_) -> [] end),
    meck:new(vbucket_map_mirror, [passthrough]),
    meck:expect(vbucket_map_mirror, node_vbuckets_dict,
                fun (B) ->
                        Map = bucket_map(B),
                        {ok, dict:from_list(
                               [{N, [VB || {VB, [M | _]} <-
                                               lists:zip(
                                                 lists:seq(0, length(Map) - 1),
                                                 Map), M =:= N]}
                                || N <- maps:keys(cluster_nodes())])}
                end),
    meck:new(bucket_info_cache, [passthrough]),
    meck:expect(bucket_info_cache, build_node_services,
                fun () -> {1, 1, <<"{}">>, <<"1">>} end).

bucket_props(Map, Extra) ->
    Servers = [node(), ?REMOTE, ?OLD7X, ?ABSENT],
    [{type, membase}, {servers, Servers}, {desired_servers, Servers},
     {num_replicas, 1}, {ram_quota, 104857600}, {map, Map} | Extra].

bucket_map("default") ->
    L = node(), R = ?REMOTE, O = ?OLD7X, A = ?ABSENT,
    [[L, R], [R, L], [O, L], [A, R]];
bucket_map("magma") ->
    L = node(), R = ?REMOTE, O = ?OLD7X,
    [[R, O], [L, O], [O, R], [L, R]].

setup_buckets() ->
    fake_chronicle_kv:update_snapshot(bucket_names, ["default", "magma"]),
    fake_chronicle_kv:update_snapshot(
      #{{bucket, "default", props} => bucket_props(bucket_map("default"), []),
        {bucket, "default", uuid} => ?BUCKET_UUID,
        {bucket, "magma", props} =>
            bucket_props(bucket_map("magma"), [{storage_mode, magma}]),
        {bucket, "magma", uuid} => <<"fedcba9876543210fedcba9876543210">>}).

teardown_cluster() ->
    fake_chronicle_kv:teardown(),
    fake_ns_config:teardown(),
    meck:unload().
