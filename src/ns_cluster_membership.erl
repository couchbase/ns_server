%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2019 Couchbase, Inc.
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
-module(ns_cluster_membership).

-include("cut.hrl").
-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([get_nodes_with_status/1,
         get_nodes_with_status/2,
         get_nodes_with_status/3,
         server_groups/0,
         server_groups/1,
         active_nodes/0,
         active_nodes/1,
         inactive_added_nodes/0,
         actual_active_nodes/0,
         actual_active_nodes/1,
         get_cluster_membership/1,
         get_cluster_membership/2,
         get_node_server_group/2,
         activate/1,
         deactivate/1,
         failover/2,
         re_failover/1,
         system_joinable/0,
         is_balanced/0,
         get_recovery_type/2,
         update_recovery_type/2,
         add_node/3,
         remove_node/1,
         prepare_to_join/2,
         is_newly_added_node/1,
         attach_node_uuids/2
        ]).

-export([supported_services/0,
         allowed_services/1,
         supported_services_for_version/1,
         cluster_supported_services/0,
         topology_aware_services/0,
         topology_aware_services_for_version/1,
         default_services/0,
         set_service_map/2,
         get_service_map/2,
         failover_service_nodes/3,
         service_has_pending_failover/2,
         service_clear_pending_failover/1,
         node_active_services/1,
         node_active_services/2,
         node_services/1,
         node_services/2,
         service_active_nodes/1,
         service_active_nodes/2,
         service_actual_nodes/2,
         service_nodes/2,
         service_nodes/3,
         should_run_service/2,
         should_run_service/3,
         user_friendly_service_name/1]).

get_nodes_with_status(PredOrStatus) ->
    get_nodes_with_status(ns_config:latest(), PredOrStatus).

get_nodes_with_status(Config, PredOrStatus) ->
    get_nodes_with_status(Config,
                          ns_node_disco:nodes_wanted(Config), PredOrStatus).

get_nodes_with_status(Config, Nodes, any) ->
    get_nodes_with_status(Config, Nodes, fun (_) -> true end);
get_nodes_with_status(Config, Nodes, Status)
  when is_atom(Status) ->
    get_nodes_with_status(Config, Nodes, _ =:= Status);
get_nodes_with_status(Config, Nodes, Pred)
  when is_function(Pred, 1) ->
    [Node || Node <- Nodes,
             Pred(get_cluster_membership(Node, Config))].

server_groups() ->
    server_groups(ns_config:latest()).

server_groups(Config) ->
    {value, Groups} = ns_config:search(Config, server_groups),
    Groups.

active_nodes() ->
    active_nodes(ns_config:get()).

active_nodes(Config) ->
    get_nodes_with_status(Config, active).

inactive_added_nodes() ->
    get_nodes_with_status(inactiveAdded).

actual_active_nodes() ->
    actual_active_nodes(ns_config:get()).

actual_active_nodes(Config) ->
    get_nodes_with_status(Config, ns_node_disco:nodes_actual(), active).

get_cluster_membership(Node) ->
    get_cluster_membership(Node, ns_config:get()).

get_cluster_membership(Node, Config) ->
    case ns_config:search(Config, {node, Node, membership}) of
        {value, Value} ->
             Value;
        _ ->
            inactiveAdded
    end.

get_node_server_group(Node, Config) ->
    get_node_server_group_inner(Node, server_groups(Config)).

get_node_server_group_inner(_, []) ->
    undefined;
get_node_server_group_inner(Node, [SG | Rest]) ->
    case lists:member(Node, proplists:get_value(nodes, SG)) of
        true ->
            proplists:get_value(name, SG);
        false ->
            get_node_server_group_inner(Node, Rest)
    end.

system_joinable() ->
    ns_node_disco:nodes_wanted() =:= [node()].

activate(Nodes) ->
    ns_config:set([{{node, Node, membership}, active} ||
                      Node <- Nodes]).

deactivate(Nodes) ->
    ns_config:set([{{node, Node, membership}, inactiveFailed}
                   || Node <- Nodes]).

is_newly_added_node(Node) ->
    get_cluster_membership(Node) =:= inactiveAdded andalso
        get_recovery_type(ns_config:latest(), Node) =:= none.

is_balanced() ->
    not ns_orchestrator:needs_rebalance().

failover(Nodes, AllowUnsafe) ->
    ns_orchestrator:failover(Nodes, AllowUnsafe).

re_failover_possible(NodeString) ->
    case (catch list_to_existing_atom(NodeString)) of
        Node when is_atom(Node) ->
            RecoveryType = ns_config:search(ns_config:latest(), {node, Node, recovery_type}, none),
            Membership = ns_config:search(ns_config:latest(), {node, Node, membership}),
            Ok = (lists:member(Node, ns_node_disco:nodes_wanted())
                  andalso RecoveryType =/= none
                  andalso Membership =:= {value, inactiveAdded}),
            case Ok of
                true ->
                    {ok, Node};
                _ ->
                    not_possible
            end;
        _ ->
            not_possible
    end.

%% moves node from pending-recovery state to failed over state
%% used when users hits Cancel for pending-recovery node on UI
re_failover(NodeString) ->
    true = is_list(NodeString),
    case re_failover_possible(NodeString) of
        {ok, Node} ->
            KVList = [{{node, Node, membership}, inactiveFailed},
                      {{node, Node, recovery_type}, none}],
            ns_config:set(KVList),
            ok;
        not_possible ->
            not_possible
    end.

get_recovery_type(Config, Node) ->
    ns_config:search(Config, {node, Node, recovery_type}, none).

-spec update_recovery_type(node(), delta | full) -> ok | bad_node.
update_recovery_type(Node, NewType) ->
    RV = ns_config:run_txn(
           fun (Config, Set) ->
                   Membership = ns_config:search(Config, {node, Node, membership}),

                   case (Membership =:= {value, inactiveAdded}
                         andalso get_recovery_type(Config, Node) =/= none)
                       orelse Membership =:= {value, inactiveFailed} of
                       true ->
                           Config1 = Set({node, Node, membership}, inactiveAdded, Config),
                           {commit,
                            Set({node, Node, recovery_type}, NewType, Config1)};
                       false ->
                           {abort, bad_node}
                   end
           end),

    case RV of
        {commit, _} ->
            ok;
        {abort, bad_node} ->
            bad_node;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

add_node(Node, GroupUUID, Services) ->
    TXNRV =
        ns_config:run_txn(
          fun (Cfg, SetFn) ->
                  {value, NWanted} = ns_config:search(Cfg, nodes_wanted),
                  case lists:member(Node, NWanted) of
                      true ->
                          {abort, node_present};
                      false ->
                          NewNWanted = lists:usort([Node | NWanted]),
                          Cfg1 = SetFn(nodes_wanted, NewNWanted, Cfg),
                          Cfg2 = SetFn({node, Node, membership}, inactiveAdded,
                                       Cfg1),
                          CfgPreGroups = SetFn({node, Node, services}, Services,
                                               Cfg2),

                          {value, Groups} =
                              ns_config:search(Cfg, server_groups),
                          case add_node_to_groups(Groups, GroupUUID, Node) of
                              {error, Error} ->
                                  {abort, Error};
                              NewGroups ->
                                  Cfg3 = SetFn(server_groups, NewGroups,
                                               CfgPreGroups),
                                  {commit, Cfg3}
                          end
                  end
          end),
    case TXNRV of
        {commit, _} ->
            ok;
        {abort, Error} ->
            Error;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

add_node_to_groups(Groups, GroupUUID, Node) ->
    MaybeGroup0 = [G || G <- Groups,
                        proplists:get_value(uuid, G) =:= GroupUUID],
    MaybeGroup = case MaybeGroup0 of
                     [] ->
                         case GroupUUID of
                             undefined ->
                                 [hd(Groups)];
                             _ ->
                                 []
                         end;
                     _ ->
                         true = (undefined =/= GroupUUID),
                         MaybeGroup0
                 end,
    case MaybeGroup of
        [] ->
            {error, group_not_found};
        [TheGroup] ->
            GroupNodes = proplists:get_value(nodes, TheGroup),
            true = (is_list(GroupNodes)),
            NewGroupNodes = lists:usort([Node | GroupNodes]),
            NewGroup =
                lists:keystore(nodes, 1, TheGroup, {nodes, NewGroupNodes}),
            lists:usort([NewGroup | (Groups -- MaybeGroup)])
    end.

remove_node(RemoteNode) ->
    ok = ns_config:update(
           fun ({nodes_wanted, V}) ->
                   {update, {nodes_wanted, V -- [RemoteNode]}};
               ({server_groups, Groups}) ->
                   {update, {server_groups,
                             remove_node_from_server_groups(
                               RemoteNode, Groups)}};
               ({{node, Node, _}, _})
                 when Node =:= RemoteNode ->
                   delete;
               (_Other) ->
                   skip
           end).

remove_node_from_server_groups(RemoteNode, Groups) ->
    [lists:keystore(nodes, 1, G,
                    {nodes, proplists:get_value(nodes, G) -- [RemoteNode]}) ||
        G <- Groups].

prepare_to_join(RemoteNode, Cookie) ->
    MyNode = node(),
    %% Generate new node UUID while joining a cluster.
    %% We want to prevent situations where multiple nodes in
    %% the same cluster end up having same node uuid because they
    %% were created from same virtual machine image.
    ns_config:regenerate_node_uuid(),

    %% For the keys that are being preserved and have vclocks,
    %% we will just update_vclock so that these keys get stamped
    %% with new node uuid vclock.
    ns_config:update(
      fun ({directory,_}) ->
              skip;
          ({otp, _}) ->
              {update, {otp, [{cookie, Cookie}]}};
          ({nodes_wanted, _}) ->
              {set_initial, {nodes_wanted, [node(), RemoteNode]}};
          ({cluster_compat_mode, _}) ->
              {set_initial, {cluster_compat_mode, undefined}};
          ({{node, _, services}, _}) ->
              erase;
          ({{node, Node, membership}, _} = P) when Node =:= MyNode ->
              {set_initial, P};
          ({{node, Node, _}, _} = Pair) when Node =:= MyNode ->
              %% update for the sake of incrementing the
              %% vclock
              {update, Pair};
          ({cert_and_pkey, V}) ->
              {set_initial, {cert_and_pkey, V}};
          (_) ->
              erase
      end).

supported_services() ->
    supported_services_for_version(cluster_compat_mode:supported_compat_version()).

allowed_services(enterprise) ->
    supported_services();
allowed_services(community) ->
    supported_services() -- enterprise_only_services().

enterprise_only_services() ->
    [cbas, eventing, backup].

-define(PREHISTORIC, [0, 0]).

services_by_version() ->
    [{?PREHISTORIC, [kv, n1ql, index, fts]},
     {?VERSION_55,  [cbas, eventing]},
     {?VERSION_CHESHIRECAT, [backup]}].

topology_aware_services_by_version() ->
    [{?PREHISTORIC, [fts, index]},
     {?VERSION_55,  [cbas, eventing]},
     {?VERSION_CHESHIRECAT, [backup]}].

filter_services_by_version(Version, ServicesTable) ->
    lists:flatmap(fun ({V, Services}) ->
                          case cluster_compat_mode:is_enabled_at(Version, V) of
                              true ->
                                  Services;
                              false ->
                                  []
                          end
                  end, ServicesTable).

supported_services_for_version(ClusterVersion) ->
    filter_services_by_version(ClusterVersion, services_by_version()).


cluster_supported_services() ->
    supported_services_for_version(cluster_compat_mode:get_compat_version()).

default_services() ->
    [kv].

topology_aware_services_for_version(Version) ->
    filter_services_by_version(Version, topology_aware_services_by_version()).

topology_aware_services() ->
    topology_aware_services_for_version(cluster_compat_mode:get_compat_version()).

set_service_map(kv, _Nodes) ->
    %% kv is special; it's dealt with using different set of functions
    ok;
set_service_map(Service, Nodes) ->
    master_activity_events:note_set_service_map(Service, Nodes),
    ns_config:set({service_map, Service}, Nodes).

get_service_map(Config, kv) ->
    %% kv is special; just return active kv nodes
    ActiveNodes = active_nodes(Config),
    service_nodes(Config, ActiveNodes, kv);
get_service_map(Config, Service) ->
    ns_config:search(Config, {service_map, Service}, []).

failover_service_nodes(Config, Service, Nodes) ->
    Map = get_service_map(Config, Service),
    NewMap = Map -- Nodes,
    ok = ns_config:set([{{service_map, Service}, NewMap},
                        {{service_failover_pending, Service}, true}]).

service_has_pending_failover(Config, Service) ->
    ns_config:search(Config, {service_failover_pending, Service}, false).

service_clear_pending_failover(Service) ->
    ns_config:set({service_failover_pending, Service}, false).

node_active_services(Node) ->
    node_active_services(ns_config:latest(), Node).

node_active_services(Config, Node) ->
    AllServices = node_services(Config, Node),
    [S || S <- AllServices,
          lists:member(Node, service_active_nodes(Config, S))].

node_services(Node) ->
    node_services(ns_config:latest(), Node).

node_services(Config, Node) ->
    case ns_config:search(Config, {node, Node, services}) of
        false ->
            default_services();
        {value, Value} ->
            Value
    end.

should_run_service(Service, Node) ->
    should_run_service(ns_config:latest(), Service, Node).

should_run_service(Config, Service, Node) ->
    case ns_config_auth:is_system_provisioned()
        andalso get_cluster_membership(Node, Config) =:= active  of
        false -> false;
        true ->
            Svcs = node_services(Config, Node),
            lists:member(Service, Svcs)
    end.

service_active_nodes(Service) ->
    service_active_nodes(ns_config:latest(), Service).

service_active_nodes(Config, Service) ->
    get_service_map(Config, Service).

service_actual_nodes(Config, Service) ->
    ActualNodes = ordsets:from_list(actual_active_nodes(Config)),
    ServiceActiveNodes = ordsets:from_list(service_active_nodes(Config, Service)),
    ordsets:intersection(ActualNodes, ServiceActiveNodes).

service_nodes(Nodes, Service) ->
    service_nodes(ns_config:latest(), Nodes, Service).

service_nodes(Config, Nodes, Service) ->
    [N || N <- Nodes,
          ServiceC <- node_services(Config, N),
          ServiceC =:= Service].

user_friendly_service_name(kv) ->
    "data";
user_friendly_service_name(n1ql) ->
    "query";
user_friendly_service_name(fts) ->
    "full text search";
user_friendly_service_name(cbas) ->
    "analytics";
user_friendly_service_name(backup) ->
    "backup";
user_friendly_service_name(Service) ->
    atom_to_list(Service).

attach_node_uuids(Nodes, Config) ->
    UUIDDict = ns_config:get_node_uuid_map(Config),
    lists:map(
      fun (Node) ->
              case dict:find(Node, UUIDDict) of
                  {ok, UUID} ->
                      {Node, UUID};
                  error ->
                      {Node, undefined}
              end
      end, Nodes).

-ifdef(TEST).
supported_services_for_version_test() ->
    ?assertEqual(lists:sort([fts,kv,index,n1ql]),
                 lists:sort(supported_services_for_version(?VERSION_50))),
    ?assertEqual(lists:sort([fts,kv,index,n1ql,cbas,eventing]),
                 lists:sort(supported_services_for_version(?VERSION_55))),
    ?assertEqual(lists:sort([fts,kv,index,n1ql,cbas,eventing,backup]),
                 lists:sort(supported_services_for_version(
                              ?VERSION_CHESHIRECAT))).

topology_aware_services_for_version_test() ->
    ?assertEqual(lists:sort([fts,index]),
                 lists:sort(topology_aware_services_for_version(?VERSION_50))),
    ?assertEqual(lists:sort([fts,index,cbas,eventing]),
                 lists:sort(topology_aware_services_for_version(?VERSION_55))),
    ?assertEqual(lists:sort([fts,index,cbas,eventing,backup]),
                 lists:sort(topology_aware_services_for_version(
                              ?VERSION_CHESHIRECAT))).
-endif.
