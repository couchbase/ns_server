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
    try {cb_dist:get_preferred_dist(NodeStr), node_type(NodeStr)} of
        %% needed for backward compat: old ns_server nodes use dynamic
        %% ports so the only way to know those ports is to ask real epmd
        %% for this reason we also keep registering new static ports on
        %% epmd because old nodes doesn't know anything about those
        %% ports
        {Module, ns_server} when Module == inet_tcp_dist;
                                 Module == inet6_tcp_dist ->
            erl_epmd:port_please(NodeStr, Hostname, Timeout);
        {Module, _} ->
            {port, port_for_node(Module, NodeStr), 5}
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
    {Type, N} = parse_node(NodeStr),
    base_port(Type, cb_dist:proto_to_encryption(Module)) + N.

is_local_node(Node) when is_atom(Node) -> is_local_node(atom_to_list(Node));
is_local_node(Node) ->
    [NodeName | _] = string:tokens(Node, "@"),
    case node_type(NodeName) of
        ns_server -> false;
        _ -> true
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

base_port(ns_server, false) -> 21100;
base_port(ns_server, true) -> 21150;
base_port(babysitter, false) -> 21200;
base_port(babysitter, true) -> 21250;
base_port(couchdb, false) -> 21300;
base_port(couchdb, true) -> 21350.

node_type(NodeStr) ->
    {Type, _} = parse_node(NodeStr),
    Type.

parse_node("ns_1") -> {ns_server, 0};
parse_node("babysitter_of_ns_1") -> {babysitter, 0};
parse_node("couchdb_ns_1") -> {couchdb, 0};

parse_node("n_" ++ Nstr) -> {ns_server, list_to_integer(Nstr)};
parse_node("babysitter_of_n_" ++ Nstr) -> {babysitter, list_to_integer(Nstr)};
parse_node("couchdb_n_" ++ Nstr) -> {couchdb, list_to_integer(Nstr)};

parse_node("executioner") -> {babysitter, 1};

parse_node(Name) -> erlang:error({unknown_node, Name}).
