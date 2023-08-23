%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(guardrail_monitor).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_test.hrl").
-endif.

-behaviour(gen_server).

-export([is_enabled/0, get_config/0, start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).


%% Amount of time to wait between state checks (ms)
-define(CHECK_INTERVAL, ?get_param(check_interval, 20000)).

-define(SERVER, ?MODULE).

-record(state, {
                statuses = [] :: [{resource(), status()}],
                timer_ref = undefined :: undefined | reference()
               }).

-type resource() :: {bucket, bucket_name()}.
-export_type([resource/0]).
-type status() :: ok | data_ingress_status().
-export_type([status/0]).

-spec is_enabled() -> boolean().
is_enabled() ->
    cluster_compat_mode:is_cluster_trinity() andalso
        config_profile:get_bool({resource_management, enabled}).


-spec get_config() -> proplists:proplist().
get_config() ->
    ns_config:read_key_fast(resource_management, []).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).


%%%===================================================================
%%% Spawning and gen_server implementation
%%%===================================================================


init([]) ->
    self() ! check,
    {ok, #state{}}.

handle_call(_, _From, #state{} = State) ->
    {reply, ok, State}.

handle_cast(_, State) ->
    {noreply, State}.

handle_info(check, #state{statuses = OldStatuses} = State) ->
    %% Remind myself to check resource statuses again, after the check interval
    State1 = restart_timer(State),
    State2 =
        case is_enabled() of
            true ->
                NewStatuses = check_resources(),
                case OldStatuses == NewStatuses of
                    true ->
                        State1;
                    false ->
                        ?log_info("Resource statuses changed from ~p to ~p",
                                  [OldStatuses, NewStatuses]),
                        ns_config:set({node, node(), resource_statuses},
                                      NewStatuses),
                        State1#state{statuses = NewStatuses}
                end;
            false ->
                State1
        end,
    {noreply, State2};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% We need to make sure there is only one timer at any given moment, otherwise
%% the system would be fragile to future changes or diag/evals
restart_timer(#state{timer_ref = Ref} = State) when is_reference(Ref) ->
    erlang:cancel_timer(Ref),
    restart_timer(State#state{timer_ref = undefined});
restart_timer(#state{timer_ref = undefined} = State) ->
    State#state{timer_ref = erlang:send_after(?CHECK_INTERVAL, self(), check)}.


%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Checks all enabled resources and returns the status map
-spec check_resources() -> [{resource(), status()}].
check_resources() ->
    Config = get_config(),
    Stats = stats_interface:for_resource_management(),
    lists:flatmap(check(_, Stats), Config).

%% Checks if a resource threshold has been met, returning all the statuses for
%% that resource (for instance the status for each bucket)
check({bucket, Config}, Stats) ->
    lists:flatten(
      lists:map(
        fun ({BucketName, BucketConfig}) ->
                case proplists:get_value(BucketName, Stats) of
                    undefined ->
                        [];
                    BucketStats ->
                        check_bucket(Config, BucketName, BucketConfig,
                                     BucketStats)
                end
        end, ns_bucket:get_buckets()));
check({_Resource, _Config}, _Stats) ->
    %% Other resources do not need regular checks
    [].

check_bucket(Config, BucketName, BucketConfig, BucketStats) ->
    Results =
        lists:filtermap(
          fun (Resource) ->
                  ResourceConfig = proplists:get_value(Resource, Config),
                  Result =
                      case proplists:get_value(enabled, ResourceConfig) of
                          true ->
                              check_bucket_guard_rail(Resource, ResourceConfig,
                                                      BucketConfig,
                                                      BucketStats);
                          false ->
                              false
                      end,
                  NotifyStat = ns_server_stats:notify_gauge(
                                 {<<"resource_limit_reached">>,
                                  [{resource, Resource},
                                   {bucket, BucketName}]}, _),
                  case Result of
                      true ->
                          NotifyStat(1),
                          {true, Resource};
                      false ->
                          NotifyStat(0),
                          false
                  end
          end, proplists:get_keys(Config)),
    [{{bucket, BucketName}, Result} || Result <- Results].

check_bucket_guard_rail(Resource, ResourceConfig, BucketConfig, BucketStats) ->
    case proplists:get_value(Resource, BucketStats) of
        undefined ->
            false;
        Metric ->
            case Resource of
                resident_ratio ->
                    validate_bucket_resource_min(BucketConfig,
                                                 ResourceConfig, Metric)
            end
    end.

validate_bucket_resource_min(BucketConfig, ResourceConfig, Metric) ->
    CouchstoreLimit = proplists:get_value(couchstore_minimum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_minimum, ResourceConfig),
    case Metric of
        %% Ignore infinity/neg_infinity as these are not meaningful here
        infinity ->
            false;
        neg_infinity ->
            false;
        Value ->
            Limit =
                case ns_bucket:storage_mode(BucketConfig) of
                    magma -> MagmaLimit;
                    _ -> CouchstoreLimit
                end,
            Value < Limit
    end.

-ifdef(TEST).
modules() ->
    [ns_config, leader_registry, chronicle_compat, stats_interface,
     janitor_agent, ns_bucket, cluster_compat_mode, config_profile].

basic_test_setup() ->
    meck:new(modules(), [passthrough]).

basic_test_teardown() ->
    meck:unload(modules()).

check_bucket_t() ->
    %% Resource level check
    RRConfig = [{enabled, true},
                {couchstore_minimum, 10},
                {magma_minimum, 1}],
    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],

    %% RR% above minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 15}])),

    %% RR% at minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 10}])),

    %% RR% below minimum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 5}])),

    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],

    %% Bucket level check

    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore", CouchstoreBucket},
                         {"magma", MagmaBucket}]
                end),
    Config = [{resident_ratio, RRConfig}],

    %% RR% above couchstore minimum
    ?assertEqual(
       [],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{resident_ratio, 15}])),
    %% RR% below couchstore minimum
    ?assertEqual(
       [{{bucket, "couchstore"}, resident_ratio}],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{resident_ratio, 5}])),

    %% RR% above magma minimum
    ?assertEqual(
       [],
       check_bucket(Config, "magma", MagmaBucket,
                    [{resident_ratio, 2}])),
    %% RR% below magma minimum
    ?assertEqual(
       [{{bucket, "magma"}, resident_ratio}],
       check_bucket(Config, "magma", MagmaBucket,
                    [{resident_ratio, 0.5}])),

    %% Service level check

    %% RR% above couchstore minimum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{"couchstore", [{resident_ratio, 15}]}])),
    %% RR% below couchstore minimum
    ?assertListsEqual(
       [{{bucket, "couchstore"}, resident_ratio}],
       check({bucket, Config}, [{"couchstore", [{resident_ratio, 5}]}])),

    %% RR% above magma minimum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{"magma", [{resident_ratio, 2}]}])),
    %% RR% below magma minimum
    ?assertListsEqual(
       [{{bucket, "magma"}, resident_ratio}],
       check({bucket, Config}, [{"magma", [{resident_ratio, 0.5}]}])),
    ok.

check_resources_t() ->
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, false},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]}]}]
                end),
    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],
    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],
    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore_bucket", CouchstoreBucket},
                         {"magma_bucket", MagmaBucket}]
                end),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        []
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket", []}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 11}]},
                         {"magma_bucket",
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, true},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]}]}]
                end),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 11}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio},
                  {{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()).

basic_test_() ->
    %% We can re-use (setup) the test environment that we setup/teardown here
    %% for each test rather than create a new one (foreach) to save time.
    {setup,
     fun() ->
             basic_test_setup()
     end,
     fun(_) ->
             basic_test_teardown()
     end,
     [{"check bucket test", fun () -> check_bucket_t() end},
      {"check all resources test", fun () -> check_resources_t() end}]}.

check_test_modules() ->
    [ns_config, cluster_compat_mode, menelaus_web_guardrails,stats_interface,
     config_profile, ns_bucket].

check_test_setup() ->
    meck:new(check_test_modules(), [passthrough]).

regular_checks_t() ->
    meck:expect(ns_config, search_node_with_default,
                fun ({?MODULE, check_interval}, _Default) ->
                        %% Use tiny timeout to force a second check immediately
                        1
                end),
    meck:expect(ns_config, set,
                fun ({node, _, resource_statuses}, _) -> ok end),

    meck:expect(cluster_compat_mode, is_cluster_trinity, ?cut(true)),
    meck:expect(config_profile, get_bool,
                fun ({resource_management, enabled}) -> false end),

    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, true},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]}]}]
                end),
    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 10}]},
                         {"magma_bucket",
                          [{resident_ratio, 1}]}]
                end),

    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],
    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],
    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore_bucket", CouchstoreBucket},
                         {"magma_bucket", MagmaBucket}]
                end),

    {ok, _Pid} = start_link(),

    meck:expect(config_profile, get_bool,
                fun ({resource_management, enabled}) -> true end),

    %% Wait to see second check after enable (implying the first one completed)
    meck:wait(2, ns_config, read_key_fast, [resource_management, '_'],
              ?MECK_WAIT_TIMEOUT),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 1}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "couchstore_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 10}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "magma_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    %% Test bucket missing and stat missing
    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket", []}]
                end),
    meck:wait(1, ns_config, set, [{node, node(), resource_statuses}, []],
              ?MECK_WAIT_TIMEOUT),

    %% Confirm that expected functions were called in the first check
    meck:validate(ns_config),
    meck:validate(cluster_compat_mode),
    meck:validate(stats_interface).

check_test_teardown() ->
    gen_server:stop(?SERVER),
    meck:unload(check_test_modules()).

check_test_() ->
    {setup,
     fun () ->
             check_test_setup()
     end,
     fun(_) ->
             check_test_teardown()
     end,
     [{"regular checks test", fun () -> regular_checks_t() end}]}.

-endif.