%% @author Couchbase <info@couchbase.com>
%% @copyright 2018 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
-module(chronicle_master).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include("cut.hrl").

-define(SERVER, {via, leader_registry, ?MODULE}).

-export([start_link/0,
         init/1,
         handle_call/3,
         handle_info/2,
         add_replica/3,
         remove_peer/1,
         activate_nodes/1,
         deactivate_nodes/1,
         upgrade_cluster/1]).

-define(CALL_TIMEOUT, ?get_timeout(call, 60000)).
-define(UPGRADE_TIMEOUT, ?get_timeout(upgrade, 240000)).

start_link() ->
    misc:start_singleton(gen_server2, start_link, [?SERVER, ?MODULE, [], []]).

wait_for_server_start() ->
    misc:wait_for_global_name(?MODULE).

add_replica(Node, GroupUUID, Services) ->
    call({add_replica, Node, GroupUUID, Services}).

activate_nodes(Nodes) ->
    call({activate_nodes, Nodes}).

deactivate_nodes(Nodes) ->
    call({deactivate_nodes, Nodes}).

remove_peer(Node) ->
    call({remove_peer, Node}).

upgrade_cluster([]) ->
    ok;
upgrade_cluster(OtherNodes) ->
    wait_for_server_start(),
    gen_server2:call(?SERVER, {upgrade_cluster, OtherNodes}, ?UPGRADE_TIMEOUT).

call(Oper) ->
    case chronicle_compat:backend() of
        chronicle ->
            ?log_debug("Calling chronicle_master with ~p", [Oper]),
            call(Oper, 3);
        ns_config ->
            ?log_debug("Performing operation ~p on ns_config", [Oper]),
            case handle_kv_oper(
                   Oper, chronicle_compat:transaction(ns_config, _, _)) of
                {ok, _} ->
                    ok;
                Error ->
                    Error
            end
    end.

call(_Oper, 0) ->
    exit(chronicle_master_call_failed);
call(Oper, Tries) ->
    wait_for_server_start(),
    try gen_server2:call(?SERVER, Oper, ?CALL_TIMEOUT) of
        RV -> RV
    catch
        exit:Error ->
            ?log_debug("Retry due to error: ~p", [Error]),
            timer:sleep(200),
            call(Oper, Tries - 1)
    end.

init([]) ->
    erlang:process_flag(trap_exit, true),
    {ok, undefined}.

handle_call({upgrade_cluster, NodesToAdd}, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    ?log_debug("Adding nodes ~p to chronicle cluster. Lock: ~p",
               [NodesToAdd, Lock]),
    ClusterInfo = chronicle:get_cluster_info(),

    ?log_debug("Preparing nodes ~p to join chronicle cluster with info ~p",
               [NodesToAdd, ClusterInfo]),
    Self = self(),
    ok = ns_cluster:prep_chronicle(NodesToAdd, Self, ClusterInfo),

    ?log_debug("Adding nodes ~p as replicas to chronicle cluster",
               [NodesToAdd]),
    ok = chronicle:add_replicas(Lock, NodesToAdd),

    ClusterInfo1 = chronicle:get_cluster_info(),

    ?log_debug("Asking nodes ~p to join chronicle cluster with info ~p",
               [NodesToAdd, ClusterInfo1]),
    ok = ns_cluster:join_chronicle(NodesToAdd, ClusterInfo1),

    ?log_debug("Promoting nodes ~p to voters, Lock: ~p", [NodesToAdd, Lock]),
    set_peer_roles(Lock, NodesToAdd, voter),
    ?log_info("Cluster successfully upgraded to chronicle"),
    {reply, ok, State};

handle_call(Oper, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    {reply, handle_oper(Oper, Lock), State}.

handle_info({'EXIT', From, Reason}, State) ->
    ?log_debug("Received exit from ~p with reason ~p. Exiting.",
               [From, Reason]),
    {stop, Reason, State}.

set_peer_roles(_Lock, [], _Role) ->
    ok;
set_peer_roles(Lock, Nodes, Role) ->
    ok = chronicle:set_peer_roles(Lock, [{N, Role} || N <- Nodes]).

operation_key() ->
    unfinished_topology_operation.

operation_key_set(Oper, Lock) ->
    {set, operation_key(), {Oper, Lock}}.

transaction(Keys, Oper, Lock, Fun) ->
    chronicle_kv:transaction(
      kv, [operation_key() | Keys],
      fun (Snapshot) ->
              case maps:find(operation_key(), Snapshot) of
                  {ok, {{AnotherOper, _Lock}, _Rev}}
                    when AnotherOper =/= Oper ->
                      RecoveryOper = recovery_oper(AnotherOper),
                      {commit, [operation_key_set(RecoveryOper, Lock)],
                       {need_recovery, RecoveryOper}};
                  _ ->
                      case Fun(Snapshot) of
                          {commit, Sets} ->
                              {commit, [operation_key_set(Oper, Lock) | Sets]};
                          {abort, Error} ->
                              {abort, Error}
                      end
              end
      end).

remove_oper_key(Lock) ->
    ?log_debug("Removing operation key with lock ~p", [Lock]),
    {ok, _} =
        chronicle_kv:transaction(
          kv, [operation_key()],
          fun (Snapshot) ->
                  case maps:get(operation_key(), Snapshot) of
                      {{_, Lock}, _Rev} ->
                          {commit, [{delete, operation_key()}]};
                      {{_, OtherLock}, _Rev} ->
                          ?log_info("Operation key with unknown lock ~p found",
                                    [OtherLock]),
                          {abort, operation_key_with_wrong_lock}
                  end
          end).

handle_kv_oper({add_replica, Node, GroupUUID, Services}, Transaction) ->
    ns_cluster_membership:add_node(Node, GroupUUID, Services, Transaction);
handle_kv_oper({remove_peer, Node}, Transaction) ->
    ns_cluster_membership:remove_node(Node, Transaction);
handle_kv_oper({activate_nodes, Nodes}, Transaction) ->
    ns_cluster_membership:activate(Nodes, Transaction);
handle_kv_oper({deactivate_nodes, Nodes}, Transaction) ->
    ns_cluster_membership:deactivate(Nodes, Transaction).

handle_topology_oper({add_replica, Node, _, _}, Lock) ->
    case chronicle:add_replica(Lock, Node) of
        {error, {already_member, Node, replica}} ->
            ?log_debug("Node ~p is already a member.", [Node]);
        ok ->
            ok
    end,
    ClusterInfo = chronicle:get_cluster_info(),
    ?log_debug("Cluster info: ~p", [ClusterInfo]),
    {ok, ClusterInfo};
handle_topology_oper({remove_peer, Node}, Lock) ->
    case chronicle:remove_peer(Lock, Node) of
        ok ->
            ok;
        {not_member, _} ->
            ?log_debug("Node ~p is not a member", [Node]),
            ok
    end;
handle_topology_oper({activate_nodes, Nodes}, Lock) ->
    set_peer_roles(Lock, Nodes, voter);
handle_topology_oper({deactivate_nodes, Nodes}, Lock) ->
    set_peer_roles(Lock, Nodes, replica).

handle_oper(Oper, Lock) ->
    ?log_debug("Starting kv operation ~p with lock ~p", [Oper, Lock]),
    case handle_kv_oper(Oper, transaction(_, Oper, Lock, _)) of
        {ok, _} ->
            ?log_debug("Starting topology operation ~p with lock ~p",
                       [Oper, Lock]),
            RV = handle_topology_oper(Oper, Lock),
            remove_oper_key(Lock),
            RV;
        {ok, _, {need_recovery, RecoveryOper}} ->
            ?log_debug("Recovery is needed for operation ~p", [RecoveryOper]),
            ok = handle_oper(RecoveryOper, Lock),
            handle_oper(Oper, Lock);
        Error ->
            Error
    end.

recovery_oper({add_replica, Node, _, _}) ->
    {remove_peer, Node};
recovery_oper(Oper) ->
    Oper.
