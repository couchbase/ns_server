%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(health_monitor_tests).

-include("ns_common.hrl").
-include("cut.hrl").

-include_lib("eunit/include/eunit.hrl").

%% Not all monitors are testable yet, just the ones that we run on all nodes.
-define (TESTABLE_MONITORS,
         [
          ns_server_monitor,
          node_status_analyzer,
          node_monitor,
          dcp_traffic_monitor,
          kv_monitor,
          kv_stats_monitor
         ]).

test_setup() ->
    health_monitor:common_test_setup(),

    %% Each monitor may have it's own required setup
    lists:foreach(
      fun(Module) ->
              Module:common_test_setup()
      end, ?TESTABLE_MONITORS),

    %% service_monitor_worker (one of the child processes that
    %% health_monitor_sup spawns) is a chronicle compat refresh worker. To
    %% start up health_monitor_sup correctly we need to return a valid Pid.
    %% We also need to be able to shut down that Pid later. Create a process
    %% that we can effectively throw away to appease this code.
    PidToMonitor =
        erlang:spawn(
          fun() ->
                  %% Block in receive to ensure that this process remains
                  %% alive til we want to kill it
                  receive _ ->
                          ok
                  end
          end),

    meck:expect(chronicle_compat_events,
                start_refresh_worker,
                fun(_,_) ->
                        {ok, PidToMonitor}
                end),

    {ok, SupervisorPid} = health_monitor_sup:start_link(),
    SupervisorPid.

test_teardown(SupervisorPid) ->
    true = erlang:exit(SupervisorPid, normal),

    lists:foreach(
      fun(Module) ->
              Module:common_test_teardown()
      end, ?TESTABLE_MONITORS),

    health_monitor:common_test_teardown().

-spec is_node_status(node(), healthy | unhealthy) -> boolean().
is_node_status(Node, Status) ->
    NodeStatuses = node_status_analyzer:get_nodes(),
    case dict:find(Node, NodeStatuses) of
        error ->
            false;
        {ok, {Status, _RecvTs}} ->
            true;
        {ok, _} ->
            false
    end.

-spec is_node_healthy(node()) -> boolean().
is_node_healthy(Node) ->
    is_node_status(Node, healthy).

-spec is_node_unhealthy(node()) -> boolean().
is_node_unhealthy(Node) ->
    is_node_status(Node, unhealthy).

%% Test that the ns_server_monitor detects failures that cause the node to
%% become unhealthy, and that the system can recover once the node becomes
%% healthy again.
ns_server_monitor_failure_detection_t() ->
    %% First, make sure that we are healthy so that we can test a transition
    %% to unhealthy
    ?assert(misc:poll_for_condition(
              fun() ->
                      is_node_healthy(node())
              end, 30000, 100)),

    %% Block all refresh messages in ns_server_monitor to simulate node
    %% unresponsive-ness
    meck:new(ns_server_monitor, [passthrough]),
    meck:expect(ns_server_monitor, handle_info,
                fun(refresh, _State) ->
                        noreply;
                   (_Msg, _State) ->
                        meck:passthrough()
                end),

    %% Should turn the node unhealthy
    ?assert(misc:poll_for_condition(
              fun() ->
                      is_node_unhealthy(node())
              end, 30000, 100)),

    %% Delete our expectation to unblock the refresh messages in
    %% ns_server_monitor
    meck:delete(ns_server_monitor, handle_info, 2),

    %% And we should transition back to healthy
    ?assert(misc:poll_for_condition(
              fun() ->
                      is_node_healthy(node())
              end, 30000, 100)).

gen_test_() ->
    Tests = [
        fun ns_server_monitor_failure_detection_t/0
    ],

    {foreach,
     fun test_setup/0,
     fun test_teardown/1,
     Tests}.

%% Get a list of callbacks in the behaviour spec that have not been called
%% yet. Returns a list of the form [{Module, [{Function, Arity}]}].
callbacks_not_made() ->
    lists:filtermap(
        fun(Module) ->
            Callbacks = health_monitor:behaviour_info(callbacks),
            MissingCallbacks = lists:filter(
                fun({Fun, _Arity}) ->
                    %% Most functions should be called in the child (monitor
                    %% itself)
                    CalledInChild = meck:called(Module, Fun, '_'),

                    %% Some functions will be intercepted by the parent
                    %% (health_monitor) code and won't make it to the
                    %% child, we check that they were actually called
                    ChildPid = whereis(Module),
                    CalledInParent = meck:called(health_monitor,
                        Fun, '_', ChildPid),

                    not (CalledInChild orelse CalledInParent)
                end,
                Callbacks),
            case MissingCallbacks of
                [] -> false;
                _ -> {true, {Module, MissingCallbacks}}
            end
        end, ?TESTABLE_MONITORS).

behaviour_cover_test_setup() ->
    %% We will mock the health_monitor module itself and passthrough
    %% everything as we aren't really interested in functionality in this
    %% test. We need to meck the module to check the history later.
    meck:new(health_monitor, [passthrough]),

    %% Mock each individual monitor that we are testing here. Passthrough as
    %% above as we don't want to test the functionality, but we do need meck
    %% running to check the history later.
    lists:foreach(
        fun(Module) ->
            meck:new(Module, [passthrough])
        end, ?TESTABLE_MONITORS),

    test_setup().

behaviour_cover_test_teardown(SupPid) ->
    lists:foreach(
        fun(Module) ->
            meck:unload(Module)
        end, ?TESTABLE_MONITORS),

    meck:unload(health_monitor),
    test_teardown(SupPid).

%% Test that we are hitting every function in the behaviour API. This lets us
%% test that the monitors interact with one another as expected (and without
%% crashing).
behaviour_cover_t() ->
    meck:expect(ns_cluster_membership,
                should_run_service,
                fun(_,_,_) ->
                        true
                end),

    %% Need to refresh children to spawn the kv and index monitors
    health_monitor_sup:refresh_children(),

    %% Need to tell the node_monitor that there are other monitors to look at
    node_monitor ! node_changed,

    %% Called by auto_failover which we're not testing here.
    node_status_analyzer:get_nodes(),

    %% Never actually called, but we still want to test the rest of
    %% the modules.
    gen_server:cast(node_status_analyzer, foo),
    gen_server:cast(kv_monitor, foo),
    gen_server:cast(kv_stats_monitor, foo),

    %% For dcp_traffic_monitor we need to pretend that there is a bucket.
    PidToMonitor =
        erlang:spawn(
          fun() ->
                  %% Block in receive to ensure that this process remains
                  %% alive til we've called get_nodes() at least once
                  receive _ ->
                          ok
                  end
          end),

    Now = erlang:monotonic_time(),
    dcp_traffic_monitor:node_alive(node(), {"default", Now, PidToMonitor}),
    misc:terminate_and_wait(PidToMonitor, "reason"),

    ?assert(misc:poll_for_condition(
              fun() ->
                      %% Whilst it would be simpler to just check if we had
                      %% called every function we want to know which
                      %% functions were not called and we can re-use that
                      %% code here.
                      callbacks_not_made() =:= []
              end, 10000, 100), callbacks_not_made()).

behaviour_cover_test_() ->
    {setup,
     fun behaviour_cover_test_setup/0,
     fun behaviour_cover_test_teardown/1,
     [fun behaviour_cover_t/0]}.
