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
          node_monitor
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
