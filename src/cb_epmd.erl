%% @author Couchbase <info@couchbase.com>
%% @copyright 2019 Couchbase, Inc.
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

%% @doc Replaces standard erl_epmd module. Assigns static ports for cb nodes
%%      based on node names.
-module(cb_epmd).

%% External exports
-export([start/0, start_link/0, stop/0, port_for_node/2, port_please/2,
         port_please/3, names/0, names/1,
         register_node/2, register_node/3, is_local_node/1, node_type/1]).


%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

%% Starting erl_epmd only for backward compat
%% Old clusters will use epmd to discover this nodes. When upgrade is finished
%% epmd is not needed.
start() -> erl_epmd:start().
start_link() -> erl_epmd:start_link().
stop() -> erl_epmd:stop().

%% Node here comes without hostname and as string
%% (for example: "n_1", but not 'n_1@127.0.0.1')
port_please(Node, Hostname) ->
    port_please(Node, Hostname, infinity).

port_please(NodeStr, Hostname, Timeout) ->
    try cb_dist:get_preferred_dist(NodeStr) of
        Module ->
            case node_type(NodeStr) of
                %% needed for backward compat: old ns_server nodes use dynamic
                %% ports so the only way to know those ports is to ask real epmd
                %% for this reason we also keep registering new static ports on
                %% epmd because old nodes doesn't know anything about those
                %% ports
                {ok, ns_server, _} when Module == inet_tcp_dist;
                                        Module == inet6_tcp_dist ->
                    erl_epmd:port_please(NodeStr, Hostname, Timeout);
                {ok, Type, N} ->
                    {port, port(Type, N, Module), 5};
                {error, Reason} ->
                    {error, Reason}
            end
    catch
        error:Error ->
            {error, Error}
    end.

names() -> erl_epmd:names().

names(EpmdAddr) -> erl_epmd:names(EpmdAddr).

register_node(Name, PortNo) ->
    register_node(Name, PortNo, inet).

register_node(_Name, _PortNo, _Family) ->
    %% Since ports are static we don't need to register them, but
    %% there is one exception: because of backward compatibility
    %% we register non tls ns_server ports in order to let pre-madhatter
    %% nodes find this node. The registering itself is done on cb_dist.
    %% 'Creation' is zero because we don't use it anyway
    %% real 'creation' is generated in cb_dist.erl
    {ok, 0}.

port_for_node(Module, NodeStr) ->
    case node_type(NodeStr) of
        {ok, Type, N} ->
            {ok, port(Type, N, Module)};
        {error, Reason} ->
            {error, Reason}
    end.

is_local_node(Node) when is_atom(Node) -> is_local_node(atom_to_list(Node));
is_local_node(Node) ->
    [NodeName | _] = string:tokens(Node, "@"),
    case node_type(NodeName) of
        {ok, ns_server, _} -> false;
        {ok, _, _} -> true;
        {error, Reason} -> erlang:error(Reason)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

port(Type, N, Module) ->
    try
        base_port(Type) + list_to_integer(N) * 2 + shift(Module)
    catch
        C:E ->
            ST = erlang:get_stacktrace(),
            error_logger:error_msg("Port calc exception: ~p, called as "
                                   "port(~p, ~p, ~p), Stacktrace: ~p",
                                   [E, Type, N, Module, ST]),
            erlang:raise(C,E,ST)
    end.

port_shifts() ->
    [{inet_tcp_dist,  0},
     {inet6_tcp_dist, 0},
     {inet_tls_dist,  1},
     {inet6_tls_dist, 1}].

shift(Module) -> proplists:get_value(Module, port_shifts()).

base_port(ns_server) -> 21100;
base_port(babysitter) -> 21200;
base_port(couchdb) -> 21300.

node_type("ns_1") -> {ok, ns_server, "0"};
node_type("babysitter_of_ns_1") -> {ok, babysitter, "0"};
node_type("couchdb_ns_1") -> {ok, couchdb, "0"};

node_type("n_" ++ Nstr) -> {ok, ns_server, Nstr};
node_type("babysitter_of_n_" ++ Nstr) -> {ok, babysitter, Nstr};
node_type("couchdb_n_" ++ Nstr) -> {ok, couchdb, Nstr};

node_type("executioner") -> {ok, babysitter, "1"};

node_type(Name) -> {error, {unknown_node, Name}}.
