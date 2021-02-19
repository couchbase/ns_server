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
         add_replica/1,
         remove_peer/1,
         ensure_voters/1,
         deactivate_voters/1,
         upgrade_cluster/1]).

-define(CALL_TIMEOUT, ?get_timeout(call, 60000)).
-define(UPGRADE_TIMEOUT, ?get_timeout(upgrade, 240000)).

start_link() ->
    misc:start_singleton(gen_server2, start_link, [?SERVER, ?MODULE, [], []]).

wait_for_server_start() ->
    misc:wait_for_global_name(?MODULE).

add_replica(Node) ->
    call({add_replica, Node}).

ensure_voters(Nodes) ->
    call({ensure_voters, Nodes}).

deactivate_voters(Nodes) ->
    call({deactivate_voters, Nodes}).

remove_peer(Node) ->
    call({remove_peer, Node}).

upgrade_cluster([]) ->
    ok;
upgrade_cluster(OtherNodes) ->
    wait_for_server_start(),
    gen_server2:call(?SERVER, {upgrade_cluster, OtherNodes}, ?UPGRADE_TIMEOUT).

call(Call) ->
    wait_for_server_start(),
    gen_server2:call(?SERVER, Call, ?CALL_TIMEOUT).

init([]) ->
    erlang:process_flag(trap_exit, true),
    {ok, undefined}.

handle_call({add_replica, Node}, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    ?log_debug("Adding node ~p as a replica. Lock: ~p", [Node, Lock]),
    ok = chronicle:add_replica(Lock, Node),
    ClusterInfo = chronicle:get_cluster_info(),
    ?log_debug("Cluster info: ~p", [ClusterInfo]),
    {reply, {ok, ClusterInfo}, State};

handle_call({remove_peer, Node}, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    ?log_debug("Removing node ~p, Lock: ~p", [Node, Lock]),
    ok = chronicle:remove_peer(Lock, Node),
    {reply, ok, State};

handle_call({ensure_voters, Nodes}, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    {ok, Voters} = chronicle:get_voters(),
    case Nodes -- Voters of
        [] ->
            ok;
        NewVoters ->
            promote_to_voters(Lock, NewVoters)
    end,
    {reply, ok, State};

handle_call({deactivate_voters, Nodes}, _From, State) ->
    {ok, Lock} = chronicle:acquire_lock(),
    ?log_debug("Changing nodes ~p from voters to replicas, Lock: ~p",
               [Nodes, Lock]),
    ok = chronicle:set_peer_roles(Lock, [{N, replica} || N <- Nodes]),
    {reply, ok, State};

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

    promote_to_voters(Lock, NodesToAdd),
    ?log_info("Cluster successfully upgraded to chronicle"),
    {reply, ok, State}.

handle_info({'EXIT', From, Reason}, State) ->
    ?log_debug("Received exit from ~p with reason ~p. Exiting.",
               [From, Reason]),
    {stop, Reason, State}.

promote_to_voters(Lock, Nodes) ->
    ?log_debug("Promoting nodes ~p to voters, Lock: ~p", [Nodes, Lock]),
    ok = chronicle:set_peer_roles(Lock, [{N, voter} || N <- Nodes]).
