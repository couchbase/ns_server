%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% node_monitor:
%%  - Gathers status information from all monitors running on the local node
%%  and exchanges this information with the orchestrator.
%%

-module(node_monitor).

-behaviour(health_monitor).

-include("ns_common.hrl").

-export([start_link/0]).
-export([get_nodes/0,
         can_refresh/0,
         annotate_status/1]).
-export([init/0, handle_call/3, handle_cast/2, handle_info/2]).

-ifdef(TEST).
-export([health_monitor_test_setup/0,
         health_monitor_test_teardown/0]).
-endif.

start_link() ->
    health_monitor:start_link(?MODULE).

init() ->
    #{refresh_interval => health_monitor:get_refresh_interval()}.

handle_call(get_nodes, _From, MonitorState) ->
    #{nodes := Statuses} = MonitorState,
    Now = erlang:monotonic_time(),
    RV = dict:fold(
           fun (Node, {Status, {recv_ts, RecvTS}}, Acc) ->
                   [{Node, health_monitor:time_diff_to_status(
                             Now - RecvTS), Status} | Acc]
           end, [], Statuses),
    {reply, RV};

handle_call(Call, From, MonitorState) ->
    ?log_warning("Unexpected call ~p from ~p when in state:~n~p",
                 [Call, From, MonitorState]),
    {reply, nack}.

handle_cast(Cast, MonitorState) ->
    ?log_warning("Unexpected cast ~p when in state:~n~p", [Cast, MonitorState]),
    noreply.

handle_info(refresh, MonitorState) ->
    #{nodes_wanted := NodesWanted,
      refresh_interval := RefreshInterval} = MonitorState,
    Payload = latest_status(NodesWanted),
    %% We need to send our status to the node where the auto-failover logic
    %% is running. This is the mb_master node. Normally, this is also
    %% the node where the orchestrator is running.
    %% But, during certain scenarios, mb_master and the orchestrator node may
    %% be different.
    %% E.g. #1: During orchestrator failover, it make take some time for
    %% the new master to register the singleton processes. During
    %% that period, node where the orchestrator is registered will be
    %% different from the mb_master:master_node().
    %% E.g. #2: If for some reason mb_master heartbeats from
    %% the current master are not reaching some nodes, those
    %% nodes will try to become the new master. There may be a period
    %% where the mb_master ping pongs among two or more nodes. But,
    %% the node where orchestrator is registered will remain the same.
    %% Send our status to both the mb_master and the orchestrator.
    Orchestrator = case leader_registry:whereis_name(ns_orchestrator) of
                       undefined ->
                           [];
                       OC ->
                           [node(OC)]
                   end,
    %% Future possibility:
    %% Store identitity of the master in local state.
    %% Whenever master changes, mb_master can post an event which this
    %% module can listen to.
    %% Similar thing can be done for the orchestrator.
    Master = case mb_master:master_node() of
                 undefined ->
                     [];
                 M ->
                     [M]
             end,
    SendTo = lists:umerge3(Orchestrator, Master, [node()]),
    health_monitor:send_heartbeat(?MODULE, SendTo, Payload, RefreshInterval),
    noreply;

handle_info(Info, MonitorState) ->
    ?log_warning("Unexpected message ~p when in state:~n~p",
                 [Info, MonitorState]),
    noreply.

%% APIs
get_nodes() ->
    gen_server:call(?MODULE, get_nodes).

annotate_status(Status) ->
    {Status, {recv_ts, erlang:monotonic_time()}}.

%% Internal functions

%% Get latest status from all local health monitors
%% Output:
%%   [{Node1, [{monitor1, <node1_status>}, {monitor2, <node1_status>}, ...]},
%%    {Node2, [{monitor1, <node2_status>}, {monitor2, <node2_status>}, ...]},
%%    ...]
latest_status(NodesWanted) ->
    AllMonitors = lists:map(fun (Monitor) ->
                                    Module = health_monitor:get_module(Monitor),
                                    {Monitor, Module:get_nodes()}
                            end, health_monitor:local_monitors()),
    lists:map(
      fun (Node) ->
              Status = [{Monitor, node_status(Node, NodesDict)} ||
                           {Monitor, NodesDict} <- AllMonitors],
              {Node, Status}
      end, NodesWanted).

node_status(Node, Dict) ->
    case dict:find(Node, Dict) of
        {ok, Status} ->
            Status;
        _ ->
            []
    end.

can_refresh() ->
    true.

-ifdef(TEST).
%% See health_monitor.erl for tests common to all monitors that use these
%% functions
health_monitor_test_setup() ->
    meck:new(ns_server_monitor, [passthrough]),
    meck:expect(ns_server_monitor,
        get_nodes,
        fun() ->
            dict:append(node(), dict:new(), dict:new())
        end),

    meck:new(mb_master),
    meck:expect(mb_master, master_node, fun() -> node() end),

    ok.

health_monitor_test_teardown() ->
    meck:unload(ns_server_monitor),
    meck:unload(mb_master).

-endif.
