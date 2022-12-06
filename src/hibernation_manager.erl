%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(hibernation_manager).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% TODO: These default timeouts are a function of the blobStorage
%% upload/download speeds and the size of the data - therefore needs
%% re-evaluation.

-define(PAUSE_BUCKET_TIMEOUT,
        ?get_timeout(pause_bucket, infinity)).

-define(RESUME_BUCKET_TIMEOUT,
        ?get_timeout(resume_bucket, infinity)).

-define(RESUME_BUCKET_DRY_RUN_TIMEOUT,
        ?get_timeout({dry_run, resume_bucket}, 5 * 60 * 1000)).

-export([pause_bucket/2,
         resume_bucket/2]).

-type supported_services() ::  index | fts.

-spec build_remote_path(
        For :: data | supported_services(),
        RemotePath :: string()) -> string().
build_remote_path(For, RemotePath) ->
    filename:join(RemotePath, atom_to_list(For)).

get_data_remote_path(RemotePath) ->
    KvRemotePath = build_remote_path(data, RemotePath),
    "s3:" ++ Rest = KvRemotePath,
    Rest ++ "/".

-spec register_worker(For :: kv | supported_services()) -> true.
register_worker(For) ->
    WorkerName = list_to_atom(?MODULE_STRING ++ "-worker-" ++
                              atom_to_list(For)),
    erlang:register(WorkerName, self()).

supported_services() ->
    [index, fts].

%% Stubbed to test just kv service for now
build_service_workers_params(_RemotePath, _Snapshot) ->
    SupportedServices = supported_services(),
    ?log_debug("Supported services stubbed out: ~p", [SupportedServices]),
    [].

build_kv_worker_params(RemotePath, KvNodes) ->
    {kv, KvNodes, get_data_remote_path(RemotePath)}.

build_workers_params(RemotePath, KvNodes, Snapshot) ->
    [build_kv_worker_params(RemotePath, KvNodes) |
     build_service_workers_params(RemotePath, Snapshot)].

pause_bucket(Bucket, RemotePath) ->
    spawn_link_hibernation_manager(
      pause_bucket, ?cut(do_pause_bucket(Bucket, RemotePath))).

resume_bucket(Bucket, RemotePath) ->
    spawn_link_hibernation_manager(
      resume_bucket, ?cut(do_resume_bucket(Bucket, RemotePath))).

spawn_link_hibernation_manager(Op, Body) ->
    proc_lib:spawn_link(
      fun () ->
              leader_activities:run_activity(
                Op, majority,
                fun () ->
                        leader_registry:register_name(?MODULE, self()),
                        Body()
                end)
      end).

get_pause_kv_nodes(Bucket, Snapshot) ->
    {ok, BucketCfg} = ns_bucket:get_bucket(Bucket, Snapshot),
    ns_bucket:get_servers(BucketCfg).

do_pause_bucket(Bucket, RemotePath) ->
    Snapshot = hibernation_utils:get_snapshot(Bucket),
    KvNodes = get_pause_kv_nodes(Bucket, Snapshot),
    WorkersParams = build_workers_params(RemotePath, KvNodes, Snapshot),

    ok = kv_hibernation_agent:prepare_pause_bucket(Bucket, KvNodes, self()),

    ok = ns_bucket:update_bucket_props(Bucket, [{hibernation_state, pausing}]),
    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   pause_bucket_body(
                     For, Bucket, Snapshot, RP, Nodes)
           end, WorkersParams, ?PAUSE_BUCKET_TIMEOUT),

    ok = ns_bucket:update_bucket_props(Bucket, [{hibernation_state, paused}]),
    ok = hibernation_utils:check_test_condition(pause_after_node_ops_run),
    kv_hibernation_agent:unprepare_pause_bucket(Bucket, KvNodes).

-spec pause_bucket_body(For, Bucket, Snapshot, RemotePath, Nodes) -> ok
    when For :: kv | supported_services(),
         Bucket :: bucket_name(),
         Snapshot :: map(),
         RemotePath :: string(),
         Nodes :: [node()].
pause_bucket_body(For, Bucket, Snapshot, RemotePath, Nodes) ->
    ProgressCallback = fun (_) -> ok end,

    service_manager:with_trap_exit_spawn_monitor_pause_bucket(
      For, Bucket, Snapshot, RemotePath, Nodes, ProgressCallback, #{}).

get_filtered_bucket_cfg(BucketCfg) ->
    Filter = [servers, desired_servers, map],
    lists:filter(fun ({K, _V}) ->
                         not lists:member(K, Filter)
                 end, BucketCfg).

get_new_map(OldMap, ServerMapping) ->
    [[maps:get(Item, ServerMapping) || Item <- VbChain] || VbChain <- OldMap].

get_new_bucket_config(Bucket, PausedBucketCfg,
                      BucketVersion) when BucketVersion =:= ?VERSION_ELIXIR ->
    NewConfig = get_filtered_bucket_cfg(PausedBucketCfg) ++
        [{servers, []}, {hibernation_state, resuming}],
    {ok, PlacedConfig} = bucket_placer:place_bucket(Bucket, NewConfig),
    PlacedConfig.

validate_server_lists(DesiredServers, OldServerList) ->
    case length(DesiredServers) =:= length(OldServerList) of
        true ->
            ok;
        _ ->
            ?log_error("Hibernated and desired server lists size mismatch"),
            fail
    end.

get_server_mapping(PausedBucketCfg, DesiredServers) ->
    OldServerList = proplists:get_value(servers, PausedBucketCfg),
    ok = validate_server_lists(DesiredServers, OldServerList),
    maps:from_list(lists:zip(DesiredServers, OldServerList)).

restore_bucket_in_resuming(Bucket, NewBucketConfig, Metadata) ->
    BucketUUID = hibernation_utils:get_bucket_uuid(Metadata),
    Manifest = hibernation_utils:get_bucket_manifest(Metadata),
    ns_bucket:restore_bucket(Bucket, NewBucketConfig, BucketUUID, Manifest).

activate_restored_bucket(Bucket, PausedBucketCfg, DesiredServers,
                         ServerMapping) ->
    OldMap = proplists:get_value(map, PausedBucketCfg),
    NewMap = get_new_map(OldMap, ServerMapping),
    ns_bucket:set_restored_attributes(Bucket, NewMap, DesiredServers).

get_metadata(RemotePath) ->
    KvRemotePath = get_data_remote_path(RemotePath),
    hibernation_utils:get_bucket_metadata_from_s3(KvRemotePath).

get_paused_bucket_cfg(Metadata) ->
    BucketVersion = hibernation_utils:get_bucket_version(Metadata),
    PausedBucketCfg = hibernation_utils:get_bucket_config(Metadata),
    {BucketVersion, PausedBucketCfg}.

do_resume_bucket(Bucket, RemotePath) ->
    Snapshot = ns_cluster_membership:get_snapshot(),
    Metadata = get_metadata(RemotePath),
    {Version, PausedBucketCfg} = get_paused_bucket_cfg(Metadata),

    NewBucketConfig = get_new_bucket_config(Bucket, PausedBucketCfg, Version),
    DesiredServers = proplists:get_value(desired_servers, NewBucketConfig),
    ServerMapping = get_server_mapping(PausedBucketCfg, DesiredServers),

    %% Resume is performed in 2 stages.
    %%
    %% 1. dry_run phase: Services download
    %% bucket meta-data from the BlobStorage and evaluate if it is possible to
    %% resume the given bucket on the current cluster. If we get an ok from all
    %% the services we move on to the actual resume else the resume operation
    %% is aborted.
    %%
    %% 2. Actual resume: Services download bucket data (indexes etc) from the
    %% BlobStorage and send us ok - if any one of the Services fails, the
    %% entire Resume operation is aborted.

    DryRunWorkerParams = build_service_workers_params(RemotePath, Snapshot),
    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   resume_bucket_body(
                     For, Bucket, ServerMapping, RP, true, Nodes)
           end, DryRunWorkerParams, ?RESUME_BUCKET_DRY_RUN_TIMEOUT),

    %% Restore the bucket in resuming state, at this point no server list or
    %% map exists for the bucket. The bucket streaming endpoint will show a
    %% bucket exists in resuming state for other services to monitor the resume
    %% status
    ok = restore_bucket_in_resuming(Bucket, NewBucketConfig, Metadata),

    ok = hibernation_utils:check_test_condition(resume_before_node_ops_run),

    WorkersParams = build_workers_params(RemotePath, DesiredServers, Snapshot),
    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   resume_bucket_body(
                     For, Bucket, ServerMapping, RP, false, Nodes)
           end, WorkersParams, ?RESUME_BUCKET_TIMEOUT),

    ok = hibernation_utils:check_test_condition(resume_after_node_ops_run),

    %% At this point the bucket will go live with the appropriate map and server
    %% list
    OldToNewServerMap = maps:fold(fun(Key, Value, Acc) ->
                                          maps:put(Value, Key, Acc)
                                  end, #{}, ServerMapping),
    ok = activate_restored_bucket(Bucket, PausedBucketCfg, DesiredServers,
                                  OldToNewServerMap).

-spec resume_bucket_body(For, Bucket, ServerMapping, RemotePath, DryRun,
                         Nodes) -> ok
    when For :: kv | supported_services(),
         Bucket :: bucket_name(),
         ServerMapping :: #{node() => node()},
         RemotePath :: string(),
         DryRun :: true | false,
         Nodes :: [node()].
resume_bucket_body(For, Bucket, ServerMapping, RemotePath, DryRun, Nodes) ->
    ProgressCallback = fun (_) -> ok end,

    service_manager:with_trap_exit_spawn_monitor_resume_bucket(
      For, Bucket, ServerMapping, RemotePath, DryRun, Nodes, ProgressCallback,
      #{}).

-ifdef(TEST).

meck_base_modules() ->
    [ns_cluster_membership, bucket_placer, hibernation_utils, ns_config,
     ns_bucket, kv_hibernation_agent, service_manager].

meck_expect_base() ->
    meck:new(meck_base_modules(), [passthrough]),
    meck:expect(ns_cluster_membership,
                service_active_nodes,
                fun (_) ->
                       [node_a, node_b]
                end),
    meck:expect(ns_cluster_membership, get_snapshot,
                fun () ->
                        #{}
                end),
    meck:expect(bucket_placer, place_bucket,
                fun (_, NewConfig) ->
                        {ok, NewConfig ++ [{desired_servers, []}]}
                end),
    meck:expect(hibernation_utils, get_snapshot,
                fun (_) ->
                        #{}
                end),
    meck:expect(hibernation_utils, get_bucket_metadata_from_s3,
                fun (_) ->
                        [{bucket_cfg, [{map, []}, {servers, []}]},
                         {version, ?VERSION_ELIXIR}, {bucket_manifest, []},
                         {bucket_uuid, 1}]
                end),
    meck:expect(hibernation_utils, check_test_condition,
                fun (_) ->
                        ok
                end),
    meck:expect(ns_config, get_timeout,
                fun (_, Default) ->
                        Default
                end),
    meck:expect(ns_bucket, live_bucket_nodes_from_config,
                fun (_) ->
                        [node_a, node_b]
                end),
    meck:expect(ns_bucket, update_bucket_props,
                fun (_, _) ->
                        ok
                end),
    meck:expect(ns_bucket, get_bucket,
                fun (_, _) ->
                        {ok, []}
                end),
    meck:expect(ns_bucket, restore_bucket,
                fun (_,_,_,_) ->
                        ok
                end),
    meck:expect(ns_bucket, set_restored_attributes,
                fun (_,_,_) ->
                        ok
                end),
    meck:expect(kv_hibernation_agent, prepare_pause_bucket,
                fun (_, _, _) ->
                        ok
                end),
    meck:expect(kv_hibernation_agent, unprepare_pause_bucket,
                fun (_, _) ->
                        ok
                end).

hibernation_op_success() ->
    timer:sleep(100 + rand:uniform(100)),
    ok.

hibernation_op_fail(Service) ->
    case Service of
        kv ->
            timer:sleep(100 + rand:uniform(100)),
            exit(not_ok);
        index ->
            timer:sleep(500);
        fts ->
            timer:sleep(rand:uniform(200)),
            exit(not_ok)
    end.

run_test_and_assert(TestBody, SuccessTag, FailureTag) ->
    0 = ?flush(_),
    Parent = self(),

    erlang:spawn(
      fun () ->
              erlang:process_flag(trap_exit, true),
              Manager =
                  erlang:spawn_link(TestBody),

              receive
                  {'EXIT', Manager, Reason} ->
                      case Reason of
                          normal ->
                              Parent ! {test_result, exit_normal};
                          _ ->
                              Parent ! {test_result, exit_not_normal}
                      end
              end
      end),

    TestSuccess =
        receive
            {test_result, SuccessTag} ->
                true;
            {test_result, FailureTag} ->
                false
        after
            1500 ->
                ?flush({test_result, _}),
                false
        end,

    ?assertEqual(TestSuccess, true),
    0 = ?flush(_).

hibernation_manager_test() ->
    {foreach,
     fun meck_expect_base/0,
     fun () ->
             meck:unload(meck_base_modules())
     end,
     [{"Pause Bucket Success",
       fun () ->
               meck:expect(service_manager,
                           with_trap_exit_spawn_monitor_pause_bucket,
                           fun (_Service, _Bucket, _Snapshot, _RemotePath,
                                _Nodes, _ProgressCallback, _Opts) ->
                                   hibernation_op_success()
                           end),

               run_test_and_assert(
                 ?cut(do_pause_bucket("foo", "s3://foo-remote-path")),
                 exit_normal, exit_not_normal)
       end
       },
      {"Pause Bucket Failure",
       fun () ->
               meck:expect(service_manager,
                           with_trap_exit_spawn_monitor_pause_bucket,
                           fun (Service, _Bucket, _Snapshot, _RemotePath,
                                _Nodes, _ProgressCallback, _Opts) ->
                                   hibernation_op_fail(Service)
                           end),

               run_test_and_assert(
                 ?cut(do_pause_bucket("foo", "s3://foo-remote-path")),
                 exit_not_normal, exit_normal)
       end},
      {"Resume Bucket Success",
       fun () ->
              meck:expect(service_manager,
                          with_trap_exit_spawn_monitor_resume_bucket,
                          fun (_Service, _Bucket, _ServerMapping, _RemotePath,
                               _DryRun, _Nodes, _ProgressCallback, _Opts) ->
                                  hibernation_op_success()
                          end),

              run_test_and_assert(
                ?cut(do_resume_bucket("foo", "s3://foo-remote-path")),
                exit_normal, exit_not_normal)
        end},
      {"Resume Bucket Failure",
       fun () ->
               meck:expect(service_manager,
                           with_trap_exit_spawn_monitor_resume_bucket,
                           fun (Service, _Bucket, _ServerMapping, _RemotePath,
                                _DryRun, _Nodes, _ProgressCallback, _Opts) ->
                                   hibernation_op_fail(Service)
                           end),

               run_test_and_assert(
                 ?cut(do_resume_bucket("foo", "s3://foo-remote-path")),
                 exit_not_normal, exit_normal)
       end}]}.

force_unpause_via_calling_process_failure_body() ->
    Self = self(),
    meck:expect(ns_memcached, pause_bucket,
        fun(_) ->
            ok
        end),
    meck:expect(ns_memcached, unpause_bucket,
        fun(_) ->
            Self ! unpause_issued,
            ok
        end),
    meck:expect(hibernation_utils, check_test_condition,
         fun (_) ->
            ok
         end),
    meck:expect(hibernation_utils, sync_s3,
        fun(_,_,_) ->
            Self ! pause_started,
            receive nothing -> ok end
        end),
    meck:expect(replication_manager, set_incoming_replication_map,
        fun(_,_) ->
            ok
        end),
    meck:expect(ns_config, get_timeout,
        fun (_,_) ->
            5 * 60 * 100
        end),
    kv_hibernation_agent:start_link(),
    {HibManagerStubPid, Mref} =
        spawn_monitor(
          fun() ->
                  ParentPid = self(),
                  spawn_link(
                    fun() ->
                            kv_hibernation_agent:set_service_manager(
                              [node()], self()),
                            ok = kv_hibernation_agent:prepare_pause_bucket(
                                   "Bucket", [node()], ParentPid),
                            ok = kv_hibernation_agent:pause_bucket(
                                   "Bucket", "Path", node(), self())
                    end
                   ),
                  receive nothing -> ok end
          end),

    receive pause_started ->
            exit(HibManagerStubPid, shutdown)
    end,

    receive unpause_issued ->
            ok
    end,

    receive {'DOWN', Mref, _, HibManagerStubPid, _} ->
            ok
    end.

force_unpause_via_calling_process_failure_test() ->
    Modules = [ns_memcached, hibernation_utils, replication_manager, ns_config],
    meck:new(Modules, [passthrough]),
    run_test_and_assert(
      ?cut(force_unpause_via_calling_process_failure_body()),
      exit_normal, exit_not_normal),
    meck:unload(Modules).

resume_helpers_test_body() ->
    meck:expect(hibernation_utils, get_bucket_metadata_from_s3,
                fun (_) ->
                        [{bucket_cfg, [{map, [['n_0@127.0.0.1','n_1@127.0.0.1'],
                                              ['n_0@127.0.0.1','n_1@127.0.0.1'],
                                              ['n_0@127.0.0.1','n_1@127.0.0.1'],
                                              ['n_1@127.0.0.1','n_0@127.0.0.1'],
                                              ['n_1@127.0.0.1','n_0@127.0.0.1'],
                                              ['n_1@127.0.0.1','n_0@127.0.0.1']]
                                       },
                                       {servers, ['n_0@127.0.0.1',
                                                  'n_1@127.0.0.1']},
                                       {desired_servers, ['n_0@127.0.0.1',
                                                          'n_1@127.0.0.1']}]},
                         {version, ?VERSION_ELIXIR}, {bucket_manifest, []},
                         {bucket_uuid, 1}]
                end),

    meck:expect(bucket_placer, place_bucket,
                fun (_, BucketCfg) ->
                        {ok, BucketCfg ++ [{desired_servers, ['n_1@127.0.0.1',
                                                              'n_2@127.0.0.1']}
                                          ]}
                end),

    Bucket = "BucketName",
    Metadata = hibernation_utils:get_bucket_metadata_from_s3("/metadata"),
    {Version, PausedStubCfg} = get_paused_bucket_cfg(Metadata),
    NewBucketCfg = get_new_bucket_config(Bucket, PausedStubCfg, Version),
    DesiredServers = proplists:get_value(desired_servers, NewBucketCfg),
    ServerMap = get_server_mapping(PausedStubCfg, DesiredServers),
    OldToNewServerMap = maps:fold(fun(Key, Value, Acc) ->
                                          maps:put(Value, Key, Acc)
                                  end, #{}, ServerMap),
    OldMap = proplists:get_value(map, PausedStubCfg),
    NewMap = get_new_map(OldMap, OldToNewServerMap),
    ?assertEqual(NewMap, [['n_1@127.0.0.1','n_2@127.0.0.1'],
                          ['n_1@127.0.0.1','n_2@127.0.0.1'],
                          ['n_1@127.0.0.1','n_2@127.0.0.1'],
                          ['n_2@127.0.0.1','n_1@127.0.0.1'],
                          ['n_2@127.0.0.1','n_1@127.0.0.1'],
                          ['n_2@127.0.0.1','n_1@127.0.0.1']]).

resume_helpers_test() ->
    Modules = [hibernation_utils, bucket_placer],
    meck:new(Modules, [passthrough]),
    run_test_and_assert(?cut(resume_helpers_test_body()), exit_normal,
                        exit_not_normal),
    meck:unload(Modules).
-endif.
