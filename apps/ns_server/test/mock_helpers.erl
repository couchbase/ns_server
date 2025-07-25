%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc
%% This file contains a set of functions to help with starting up various
%% ns_server processes for the sake of testing. For example, we may want to
%% test auto-failover, or rebalance, and to do so we need to start up the
%% orchestrator which requires it's own set of processes (or mocks). We may
%% start processes or mock them, depending on general complexity and the needs
%% of the test(s) calling the functions in this module.
%%
%% The functions in this module are intended to set up processes in a generally
%% minimal and re-usable way, but this may not always be possible.
%%
%% To accomplish this in something of a re-usable way, we establish a pattern
%% where we:
%% 1. Export functions to set up some process
%% 2. These functions may compose other functions to set up their requirements
%% 3. These functions take, and return, a map of pids (accumulator style) which
%%    is used to track the pids of the processes they create, or the mocks that
%%    they set up. This lets us call each function multiple times and skip
%%    setting up a process that has already been set up, simplying test setup
%%    when we want to re-use certain functions.
%%    In addition, the mocking can be overriden by the caller, for some given
%%    function, if needed, by setting that key in the map of pids.
%% 4. We can shut down any processes set up by the functions in this module by
%%    calling `shutdown_processes/1' with the map of pids.
%%
%% This file is a work in progress, I'm not 100% sure that this is the best way
%% to do this, but it exists such that we can share these mocks between tests;
%% in particular is was added to share mocks between the failover and rebalance
%% tests. We may wish to evaluate this approach in the future if management of
%% these mocks becomes more complex.
-module(mock_helpers).

-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_common/include/cut.hrl").

-include("ns_common.hrl").

%% Export everything, we need to export the functions that set up the
%% mocks/processes so that we can call them from the test setup functions so
%% most everything must be exported anyway.
-compile(export_all).
-compile(nowarn_export_all).

%%%===================================================================
%%% API functions
%%%===================================================================

%% Convenience function to set up a bunch of mocks for a list of modules.
%% Returns a map of pids (accumulator style) for the processes that are set up
%% such that they can be shutdown later.
-spec setup_mocks(list()) -> map().
setup_mocks(Modules) ->
    setup_mocks(Modules, #{}).

%% Convenience function to set up a bunch of mocks for a list of modules using
%% the provided PidMap accumulator.
-spec setup_mocks(list(), map()) -> map().
setup_mocks(Modules, PidMap) ->
    functools:chain(PidMap,
                    [setup_mock(Module, _) || Module <- Modules]).

%% Shuts down all the processes that were set up by the functions in this
%% module.
-spec shutdown_processes(map()) -> ok.
shutdown_processes(PidMap) ->
    maps:foreach(
      fun(_Process, Pid) when is_pid(Pid) ->
              erlang:unlink(Pid),
              misc:terminate_and_wait(Pid, shutdown);
         (_, _) ->
              ok
      end, PidMap).

%%%===================================================================
%%% Helper functions
%%%===================================================================

%% Skip setting up a mock if it's already been set up. This allows a caller to
%% override a mock if needed, or for us to compose test setup functions without
%% having to worry about whether a mock has already been set up.
setup_mock(Module, PidMap) ->
    case maps:get(Module, PidMap, undefined) of
        undefined ->
            ?MODULE:Module(PidMap);
        _ ->
            PidMap
    end.

%%%===================================================================
%%% Process setup functions
%%%===================================================================

leader_registry(PidMap) ->
    %% Note, this won't work if we have already set up fake_ns_pubsub, but we
    %% are going to get rid of that anyway in future changes.
    leader_registry_tests:setup(),
    gen_event:sync_notify(leader_events, {new_leader, node()}),

    PidMap#{?FUNCTION_NAME => whereis(?FUNCTION_NAME),
            leader_events => whereis(leader_events)}.

auto_reprovision(PidMap) ->
    %% TODO: Nothing needs auto_reprovision to be enabled yet, just running,
    %% so we can disable it for now.
    fake_chronicle_kv:update_snapshot(auto_reprovision_cfg, [{enabled, false}]),

    PidMap0 = setup_mocks([leader_registry],
                          PidMap),

    {ok, AutoReprovisionPid} = auto_reprovision:start_link(),
    PidMap0#{?FUNCTION_NAME => AutoReprovisionPid}.

rebalance_report_manager(PidMap) ->
    fake_ns_config:update_snapshot(rest_creds, null),

    meck:new(cb_atomic_persistent_term, [passthrough]),
    meck:expect(cb_atomic_persistent_term, get_or_set_if_invalid,
                fun(_, _, F) ->
                        F(undefined)
                end),
    {ok, RebalanceReportManagerPid} = ns_rebalance_report_manager:start_link(),
    PidMap#{?FUNCTION_NAME => RebalanceReportManagerPid}.

ns_orchestrator(PidMap) ->
    PidMap0 = setup_mocks([ns_janitor_server,
                           ns_doctor,
                           rebalance_report_manager,
                           testconditions],
                          PidMap),

    {ok, OrchestratorPid} = ns_orchestrator:start_link(),
    PidMap0#{?FUNCTION_NAME => OrchestratorPid}.

compat_mode_manager(PidMap) ->
    {ok, CompatModeManagerPid} = compat_mode_manager:start_link(),
    PidMap#{?FUNCTION_NAME => CompatModeManagerPid}.

auto_failover(PidMap) ->
    PidMap0 = setup_mocks([compat_mode_events], PidMap),

    {ok, AutoFailoverPid} = auto_failover:start_link(),
    PidMap0#{?FUNCTION_NAME => AutoFailoverPid}.

compat_mode_events(PidMap) ->
    {ok, CompatModeEventsPid} = gen_event:start_link({local,
                                                      compat_mode_events}),
    PidMap#{?FUNCTION_NAME => CompatModeEventsPid}.

ns_node_disco_events(PidMap) ->
    {ok, NSNodeDiscoEventsPid} = gen_event:start_link({local,
                                                       ns_node_disco_events}),
    PidMap#{?FUNCTION_NAME => NSNodeDiscoEventsPid}.

chronicle_master(PidMap) ->
    PidMap0 = setup_mocks([chronicle], PidMap),

    {ok, ChronicleMasterPid} = chronicle_master:start_link(),
    PidMap0#{?FUNCTION_NAME => ChronicleMasterPid}.

%%%===================================================================
%%% Mock setup functions
%%%
%%% These functions just set up mocks, so we don't have a pid to add to the map.
%%% We just return an atom so that we can still handle skipping multiple
%%% setups/overriding setups.
%%%===================================================================

chronicle(PidMap) ->
    meck:new(chronicle),
    meck:expect(chronicle, acquire_lock, fun() -> {ok, self()} end),
    meck:expect(chronicle, set_peer_roles, fun(_,_) -> ok end),

    PidMap#{?FUNCTION_NAME => mocked}.

janitor_agent(PidMap) ->
    %% Janitor_agent mecks required to perform a full failover (with map).
    meck:new(janitor_agent, []),
    meck:expect(janitor_agent, query_vbuckets,
                fun(_,_,_,_) ->
                        %% We don't need to return anything useful for this
                        %% failover, we are failing over all but one node so
                        %% we don't have to choose between any.
                        {dict:from_list([{1, []}]), []}
                end),

    meck:expect(janitor_agent, fetch_vbucket_states,
                fun(VBucket, _) ->
                        %% We need to return some semi-valid vBucket stat map
                        %% from this. We might use a couple of different maps
                        %% for this test, so here we will generate it from
                        %% the map (assuming only 1 vBucket).
                        {ok, BucketConfig} = ns_bucket:get_bucket("default"),
                        ArrayMap = array:from_list(
                                     proplists:get_value(map, BucketConfig)),
                        [Active | Replicas] = array:get(VBucket, ArrayMap),
                        Seqnos = [{high_prepared_seqno, 1},
                                  {high_seqno, 1}],
                        A = [{Active, active, Seqnos}],
                        R = [{Replica, replica, Seqnos} || Replica <- Replicas],
                        A ++ R
                end),

    meck:expect(janitor_agent, find_vbucket_state,
                fun(Node, States) ->
                        meck:passthrough([Node, States])
                end),

    meck:expect(janitor_agent, apply_new_bucket_config,
                fun(_,_,_,_) ->
                        %% Just sets stuff in memcached, uninteresting here
                        ok
                end),

    meck:expect(janitor_agent, mark_bucket_warmed,
                fun(_,_) ->
                        %% Just sets stuff in memcached, uninteresting here
                        ok
                end),

    meck:expect(janitor_agent, check_bucket_ready,
                fun(_,_,_) ->
                        ready
                end),
    meck:expect(janitor_agent, delete_vbucket_copies,
                fun(_,_,_,_) ->
                        ok
                end),
    meck:expect(janitor_agent, finish_rebalance,
                fun(_,_,_) ->
                        ok
                end),
    meck:expect(janitor_agent, prepare_nodes_for_rebalance,
                fun(_,_,_) ->
                        ok
                end),

    meck:expect(janitor_agent, inhibit_view_compaction,
                fun (_, _, _) -> nack end),

    meck:expect(janitor_agent, uninhibit_view_compaction,
                fun (_, _, _, _) -> ok end),

    meck:expect(janitor_agent, get_mass_dcp_docs_estimate,
                fun (_, _, VBs) ->
                        {ok, lists:duplicate(length(VBs), {0, 0, random_state})}
                end),

    meck:expect(janitor_agent, bulk_set_vbucket_state,
                fun (_, _, _, _) -> ok end),

    meck:expect(janitor_agent, initiate_indexing,
                fun (_, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, wait_dcp_data_move,
                fun (_, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, get_vbucket_high_seqno,
                fun (_, _, _, _) -> 0 end),

    meck:expect(janitor_agent, wait_seqno_persisted,
                fun (_, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, set_vbucket_state,
                fun (_, _, _, _, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, wait_index_updated,
                fun (_, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, dcp_takeover,
                fun (_, _, _, _, _) -> ok end),

    meck:expect(janitor_agent, get_src_dst_vbucket_replications,
                fun (_, _) -> {[], []} end),

    PidMap#{?FUNCTION_NAME => mocked}.

%% auto failover for orchestrator
ns_janitor_server(PidMap) ->
    meck:new(ns_janitor_server),
    meck:expect(ns_janitor_server, start_cleanup,
                fun(_) -> {ok, self()} end),
    meck:expect(ns_janitor_server, terminate_cleanup,
                fun(_) ->
                        CallerPid = self(),
                        CallerPid ! {cleanup_done, foo, bar},
                        ok
                end),
    PidMap#{?FUNCTION_NAME => mocked}.

%% from manual failover setup
leader_activities(PidMap) ->
    meck:new(leader_activities),
    meck:expect(leader_activities, run_activity,
                fun(_Name, _Quorum, Body) ->
                        Body()
                end),
    meck:expect(leader_activities, run_activity,
                fun(_Name, _Quorum, Body, _Opts) ->
                        Body()
                end),

    meck:expect(leader_activities, activate_quorum_nodes,
                fun(_) -> ok end),
    meck:expect(leader_activities, deactivate_quorum_nodes,
                fun(_) -> ok end),
    PidMap#{?FUNCTION_NAME => mocked}.

ns_doctor(PidMap) ->
    meck:new(ns_doctor),
    meck:expect(ns_doctor, get_nodes, fun() -> [] end),

    meck:expect(
      ns_doctor, get_memory_data,
      fun(Nodes) ->
              {ok, [{Node, memsup:get_system_memory_data()} || Node <- Nodes]}
      end),

    PidMap#{?FUNCTION_NAME => mocked}.

rebalance_quirks(PidMap) ->
    meck:new(rebalance_quirks, [passthrough]),
    meck:expect(rebalance_quirks, get_quirks, fun(_,_) -> [] end),
    PidMap#{?FUNCTION_NAME => mocked}.

testconditions(PidMap) ->
    meck:new(testconditions, [passthrough]),
    meck:expect(testconditions, get, fun(_) -> ok end),
    PidMap#{?FUNCTION_NAME => mocked}.

rebalance_agent(PidMap) ->
    meck:new(rebalance_agent),
    meck:expect(rebalance_agent, prepare_rebalance, fun(_,_) -> ok end),
    meck:expect(rebalance_agent, deactivate_bucket_data, fun(_,_,_) -> ok end),

    meck:expect(rebalance_agent, unprepare_rebalance, fun(_,_) -> ok end),
    PidMap#{?FUNCTION_NAME => mocked}.

ns_storage_conf(PidMap) ->
    meck:new(ns_storage_conf),
    meck:expect(ns_storage_conf, delete_unused_buckets_db_files,
                fun() -> ok end),
    PidMap#{?FUNCTION_NAME => mocked}.

%%%===================================================================
%%% Misc functions
%%%===================================================================

-spec get_counter_value(atom()) -> term().
get_counter_value(Counter) ->
    case chronicle_compat:get(counters, #{}) of
        {ok, V} ->
            case proplists:is_defined(Counter, V) of
                true ->
                    {_, CounterValue} =
                        proplists:get_value(Counter, V),
                    CounterValue;
                false ->
                    counter_not_found
            end;
        _ -> counters_not_found
    end.

-spec poll_for_counter_value(atom(), any()) -> boolean().
poll_for_counter_value(Counter, Value) ->
    misc:poll_for_condition(
      fun() ->
              case get_counter_value(Counter) of
                  V when is_integer(V) ->
                      Value =:= V;
                  _ ->
                      false
              end
      end, 10000, 100).
