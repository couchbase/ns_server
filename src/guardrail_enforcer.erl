%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(guardrail_enforcer).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_test.hrl").
-endif.

-behaviour(gen_server).

-export([start_link/0, get_status/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(NOTIFY_TIMEOUT, ?get_timeout(notify, 1000)).

-define(SERVER, ?MODULE).

-record(state, {
                statuses :: #{resource() => atom()}
               }).

-type resource() :: guardrail_monitor:resource().
-type status() :: guardrail_monitor:status().

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec get_status(resource()) -> undefined | ok | {error, atom()}.
get_status(Resource) ->
    case guardrail_monitor:is_enabled() of
        true ->
            gen_server:call(?SERVER, {status, Resource});
        false ->
            undefined
    end.

%%%===================================================================
%%% Spawning and gen_server implementation
%%%===================================================================

init([]) ->
    ns_pubsub:subscribe_link(ns_config_events,
                             fun resource_status_change_callback/1),
    self() ! check_changes,
    {ok, #state{statuses = #{}}}.

handle_call({status, Resource}, _From, State) ->
    Status = case maps:get(Resource, State#state.statuses, ok) of
                 %% Ignore retry flag
                 {S, retry} -> S;
                 S -> S
             end,
    {reply, Status, State};
handle_call(_Request, _From, State = #state{}) ->
    {reply, ok, State}.

handle_cast(_Request, State = #state{}) ->
    {noreply, State}.

handle_info(check_changes, #state{statuses = OldStatuses} = State0) ->
    ?flush(check_changes),
    {noreply, State0#state{statuses = update_statuses(OldStatuses)}};
handle_info(_Info, State = #state{}) ->
    {noreply, State}.

terminate(_Reason, _State = #state{}) ->
    ok.

code_change(_OldVsn, State = #state{}, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

resource_status_change_callback({{node, _, resource_statuses}, _}) ->
    ?SERVER ! check_changes;
resource_status_change_callback(_) ->
    ok.

update_statuses(OldStatuses) ->
    GetNodeStatuses =
        fun (Node) ->
                ns_config:search_node_with_default(
                    Node, ns_config:latest(), resource_statuses, [])
        end,
    %% We are not interested in the status of inactive nodes, such as those that
    %% have failed over
    FlatStatuses = lists:flatmap(GetNodeStatuses,
                                 ns_cluster_membership:actual_active_nodes()),
    AggStatuses = maps:map(
                    fun (Resource, Values) ->
                            get_aggregated_status(Resource, Values)
                    end, maps:from_list(misc:keygroup(1, FlatStatuses))),
    maybe_notify_services(OldStatuses, AggStatuses).

%% Notify services of any changes
maybe_notify_services(AllOld, AllNew) ->
    ChangedStatuses = get_changes(AllOld, AllNew),
    ?log_debug("Changed Statuses: ~p", [ChangedStatuses]),
    maps:merge(AllNew, maps:map(fun notify_service/2, ChangedStatuses)).

get_changes(AllOld, AllNew) ->
    maps:filtermap(
      fun (_Key, {Old, Old}) ->
              %% Don't notify for unchanged
              false;
          (_Key, {_Old, New}) ->
              %% Notify with new status if changed
              {true, New};
          (Key, New) ->
              case maps:get(Key, AllNew, undefined) of
                  undefined ->
                      %% Status has been removed, so we should notify with ok
                      {true, ok};
                  _ ->
                      %% Notify with new status when there is no old status
                      {true, New}
              end
      end, maps:merge_with(
             fun (_Key, V1, V2) ->
                     {V1, V2}
             end, AllOld, AllNew)
     ).

%% To ensure that we keep trying to set the status after a failed call, we
%% will return {Status, retry} if we failed
-spec notify_service(resource(), status()) ->
          status() | {status(), retry}.
notify_service({bucket, Bucket}, Status) ->
    case ns_bucket:get_bucket(Bucket) of
        {ok, BucketConfig} ->
            ?log_debug("Notifying {bucket, ~p}: ~p", [Bucket, Status]),
            RV = janitor_agent:maybe_set_data_ingress(
                   Bucket, Status, ns_bucket:get_servers(BucketConfig)),
            case RV of
                ok ->
                    Status;
                {errors, BadReplies} ->
                    ?log_error("Failed to set ingress status for bucket ~p."
                               "~nBadReplies:~n~p", [Bucket, BadReplies]),
                    {Status, retry}
            end;
        not_present ->
            ?log_debug("Can't notify {bucket, ~p} (bucket not present): ~p",
                       [Bucket, Status]),
            ok
    end;
notify_service(_Resource, Status) ->
    Status.

-spec get_aggregated_status(resource(), [{node(), status()}]) -> status().
get_aggregated_status(Resource, NodeStatuses) ->
    resolve_status_conflict(Resource, lists:map(fun ({_, S}) -> S end,
                                                NodeStatuses)).

-spec priority_order(resource()) -> [status()].
priority_order(_) ->
    [resident_ratio, data_size, disk_usage].

-spec resolve_status_conflict([status()] | resource(), [status()]) ->
          status().
resolve_status_conflict(PriorityOrder, Reasons) when is_list(PriorityOrder) ->
    %% Return the highest priority reason
    lists:foldl(
      fun (Reason, ok) ->
              case lists:member(Reason, Reasons) of
                  true -> Reason;
                  false -> ok
              end;
          %% All other reasons are lower priority as we are folding in priority
          %% order
          (_, Reason) ->
              Reason
      end, ok, PriorityOrder);
resolve_status_conflict(Resource, Reasons) ->
    resolve_status_conflict(priority_order(Resource), Reasons).

-ifdef(TEST).

test_handle_status(Response, Resource, Statuses) ->
    ?assertEqual({reply, Response, #state{statuses = Statuses}},
                 handle_call({status, Resource}, undefined,
                             #state{statuses = Statuses})).

get_status_test() ->
    test_handle_status(ok, {bucket, "bucket"}, #{}),

    test_handle_status(ok, {bucket, "bucket"}, #{{bucket, "bucket"} => ok}),

    %% Safely handle status awaiting retry
    test_handle_status(ok, {bucket, "bucket"},
                       #{{bucket, "bucket"} => {ok, retry}}),

    test_handle_status(resident_ratio, {bucket, "bucket"},
                       #{{bucket, "bucket"} => resident_ratio}),

    test_handle_status(data_size, {bucket, "bucket"},
                       #{{bucket, "bucket"} => data_size}).

get_changes_test() ->
    %% No statuses, no changes
    ?assertEqual(#{}, get_changes(#{}, #{})),
    %% Adding a status of ok
    ?assertEqual(#{test => ok}, get_changes(#{}, #{test => ok})),
    %% No change
    ?assertEqual(#{}, get_changes(#{test => ok}, #{test => ok})),
    %% Change from one status to another
    ?assertEqual(#{test => other},
                 get_changes(#{test => ok}, #{test => other})),
    %% Removing status should re-notify
    ?assertEqual(#{test => ok}, get_changes(#{test => other}, #{})),
    %% Removing ok will re-notify despite being unnecessary, to simplify logic
    ?assertEqual(#{test => ok}, get_changes(#{test => ok}, #{})).

get_aggregated_status_test() ->
    ?assertEqual(ok,
                 get_aggregated_status(
                   {bucket, "bucket"}, [{node1, ok}])),

    ?assertEqual(resident_ratio,
                 get_aggregated_status({bucket, "bucket"},
                                       [{node1, resident_ratio}])),

    ?assertEqual(resident_ratio,
                 get_aggregated_status({bucket, "bucket"},
                                         [{node1, resident_ratio},
                                          {node2, ok}])),

    ?assertEqual(resident_ratio,
                 get_aggregated_status({bucket, "bucket"},
                                         [{node1, resident_ratio},
                                          {node2, data_size}])),

    ?assertEqual(data_size,
                 get_aggregated_status({bucket, "bucket"},
                                         [{node1, data_size},
                                          {node2, ok}])).

resolve_status_conflict_test() ->
    %% Generic status conflict logic
    ?assertEqual(ok, resolve_status_conflict([], [])),
    ?assertEqual(ok, resolve_status_conflict([], [ok])),
    ?assertEqual(ok, resolve_status_conflict([], [ok, other])),
    ?assertEqual(other1,
                 resolve_status_conflict([other1], [ok, other1])),
    ?assertEqual(other1,
                 resolve_status_conflict([other1, other2],
                                         [ok, other1, other2])),
    ?assertEqual(other2,
                 resolve_status_conflict([other1, other2],
                                         [ok, other2])),

    %% Bucket status conflicts
    ?assertEqual(ok, resolve_status_conflict({bucket, ""}, [])),
    ?assertEqual(ok, resolve_status_conflict({bucket, ""}, [ok])),
    ?assertEqual(resident_ratio,
                 resolve_status_conflict({bucket, ""}, [resident_ratio])),
    ?assertEqual(resident_ratio,
                 resolve_status_conflict({bucket, ""}, [ok, resident_ratio])),

    ?assertEqual(data_size,
                 resolve_status_conflict({bucket, ""},
                                           [data_size])),
    ?assertEqual(resident_ratio,
                 resolve_status_conflict({bucket, ""},
                                           [resident_ratio, data_size])).

modules() ->
    [ns_cluster_membership,
     ns_pubsub,
     ns_config,
     ns_bucket,
     janitor_agent,
     guardrail_monitor].

basic_test_setup() ->
    meck:new(modules(), [passthrough]),
    meck:expect(ns_cluster_membership, actual_active_nodes,
                fun () -> [node1, node2, node3] end),
    meck:expect(ns_pubsub, subscribe_link,
                fun (ns_config_events, _) -> ok end),
    meck:expect(guardrail_monitor, is_enabled, ?cut(false)).

test_update_statuses(NewNodes) ->
    meck:expect(ns_config, search_node_with_default,
                fun (Node, _, resource_statuses, Default) ->
                        maps:get(Node, NewNodes, Default)
                end),
    ?SERVER ! check_changes.

update_statuses_t() ->
    {ok, _Pid} = start_link(),
    test_update_statuses(#{}),
    ?assertEqual(undefined, get_status(test)),
    meck:expect(guardrail_monitor, is_enabled, ?cut(true)),
    ?assertEqual(ok, get_status(test)),

    Servers = ns_cluster_membership:actual_active_nodes(),
    meck:expect(ns_bucket, get_bucket,
                fun ("bucket1") ->
                        {ok, [{type, membase},
                              {storage_mode, magma},
                              {servers, Servers}]}
                end),
    meck:expect(janitor_agent, maybe_set_data_ingress,
                fun (Bucket, Status, S) ->
                        ?log_debug("Setting ingress status for '~p' to ~p for "
                                   "~p", [Bucket, Status, S])
                end),

    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, ok}]}),
    ?assertEqual(ok, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", ok, Servers])),

    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, ok}]}),
    ?assertEqual(ok, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", ok, Servers])),

    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% Don't try to set ingress when status unchanged
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% Don't try to set ingress when status unchanged
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}],
                           node2 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% Don't set ingress when only one becomes ok
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}],
                           node2 => [{{bucket, "bucket1"}, ok}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% Update ingress when all nodes become ok
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, ok}],
                           node2 => [{{bucket, "bucket1"}, ok}]}),
    ?assertEqual(ok, get_status({bucket, "bucket1"})),
    ?assertEqual(2, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", ok, Servers])),

    %% Notify with ok when the status disappears
    test_update_statuses(#{node1 => []}),
    ?assertEqual(ok, get_status({bucket, "bucket1"})),
    ?assertEqual(3, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", ok, Servers])),

    meck:expect(janitor_agent, maybe_set_data_ingress,
                fun (Bucket, Status, S) ->
                        ?log_debug("Setting ingress status for '~p' to ~p for "
                                   "~p", [Bucket, Status, S]),
                        {errors, []}
                end),
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(2, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% When maybe_set_data_ingress has failed, we should retry even though the
    %% status has not changed
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(3, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    meck:expect(janitor_agent, maybe_set_data_ingress,
                fun (Bucket, Status, S) ->
                        ?log_debug("Setting ingress status for '~p' to ~p for "
                                   "~p", [Bucket, Status, S])
                end),
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(4, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% When set data ingress starts succeeding again, we should not keep
    %% retrying
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(4, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])),

    %% Update status to data_size
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, data_size}]}),
    ?assertEqual(data_size, get_status({bucket, "bucket1"})),
    ?assertEqual(1, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", data_size, Servers])),

    %% Update both data_size and resident_ratio at same time
    test_update_statuses(#{node1 => [{{bucket, "bucket1"}, data_size}],
                           node2 => [{{bucket, "bucket1"}, resident_ratio}]}),
    ?assertEqual(resident_ratio, get_status({bucket, "bucket1"})),
    ?assertEqual(5, meck:num_calls(janitor_agent, maybe_set_data_ingress,
                                   ["bucket1", resident_ratio, Servers])).

basic_test_teardown() ->
    gen_server:stop(?SERVER),
    meck:unload(modules()).

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
     [{"update statuses test", fun () -> update_statuses_t() end}]}.
-endif.
