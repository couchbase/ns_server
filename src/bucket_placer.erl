%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(bucket_placer).

-include("cut.hrl").
-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([is_enabled/0,
         place_bucket/2,
         rebalance/2,
         get_node_status_fun/1,
         is_balanced/3]).

-record(params, {weight_limit, tenant_limit, memory_quota}).

-record(node, {weight, memory_used, buckets}).

is_enabled() ->
    config_profile:get_bool(enable_bucket_placer).

get_weight_limit() ->
    config_profile:get_value(bucket_weight_limit, 10000).

get_tenant_limit() ->
    config_profile:get_value(tenant_limit, 25).

get_params() ->
    {ok, MemQuota} = memory_quota:get_quota(kv),
    #params{weight_limit = get_weight_limit(),
            tenant_limit = get_tenant_limit(),
            memory_quota = MemQuota * ?MIB}.

get_snapshot() ->
    chronicle_compat:get_snapshot(
      [ns_bucket:fetch_snapshot(all, _, [props]),
       ns_cluster_membership:fetch_snapshot(_)]).

place_bucket(BucketName, Props) ->
    case ns_bucket:get_width(Props) of
        undefined ->
            {ok, Props};
        _ ->
            do_place_bucket(BucketName, Props, get_params(), get_snapshot())
    end.

do_place_bucket(BucketName, Props, Params, Snapshot) ->
    RV = on_zones(
           fun (_, Nodes) ->
                   calculate_desired_servers(Nodes, BucketName, Props, Params)
           end, get_eligible_buckets(Snapshot), Snapshot),
    case RV of
        {ok, Servers} ->
            DesiredServers = lists:sort(lists:flatten(Servers)),
            {ok, ns_bucket:update_desired_servers(DesiredServers, Props)};
        Error ->
            Error
    end.

get_eligible_buckets(Snapshot) ->
    lists:filter(fun ({_, P}) -> ns_bucket:get_width(P) =/= undefined end,
                 ns_bucket:get_buckets(Snapshot)).

on_zones(Fun, Buckets, Snapshot) ->
    on_groups(fun (AllGroupNodes, _Group) ->
                      Nodes = construct_zone(AllGroupNodes, Snapshot, Buckets),
                      Fun(AllGroupNodes, Nodes)
              end, Snapshot).

on_groups(Fun, Snapshot) ->
    Groups = ns_cluster_membership:server_groups(Snapshot),

    Results =
        lists:map(
          fun (Group) ->
                  AllGroupNodes = proplists:get_value(nodes, Group),
                  Fun(AllGroupNodes, Group)
          end, Groups),

    {Good, Bad} =
        lists:partition(fun ({_, error}) ->
                                false;
                            ({_, {ok, _}}) ->
                                true
                        end, lists:zip(Groups, Results)),
    case Bad of
        [] ->
            {ok, [L || {_, {ok, L}} <- Good]};
        _ ->
            {error, [proplists:get_value(name, G) || {G, error} <- Bad]}
    end.

construct_zone(AllGroupNodes, Snapshot, Buckets) ->
    Nodes =
        ns_cluster_membership:service_nodes(
          Snapshot,
          ns_cluster_membership:active_nodes(
            Snapshot, AllGroupNodes),
          kv),
    [{N, construct_node(N, Buckets)} || N <- Nodes].

empty_node() ->
    #node{weight = 0, memory_used = 0, buckets = maps:new()}.

construct_node(NodeName, Buckets) ->
    apply_buckets_to_node(NodeName, empty_node(), Buckets).

apply_buckets_to_node(NodeName, InitialNode, Buckets) ->
    lists:foldl(
      fun ({BucketName, Props}, Node) ->
              DesiredServers = ns_bucket:get_desired_servers(Props),
              case lists:member(NodeName, DesiredServers) of
                  true ->
                      apply_bucket_to_node(Node, BucketName, Props);
                  false ->
                      remove_bucket_from_node(Node, BucketName)
              end
      end, InitialNode, Buckets).

apply_bucket_to_node(#node{weight = W, buckets = BM, memory_used = M} = Node,
                     BucketName, Props) ->
    {WeightDiff, _, MemDiff} = params_diff(BM, BucketName, Props),
    Node#node{weight = W + WeightDiff,
              memory_used = M + MemDiff,
              buckets = maps:put(BucketName, Props, BM)}.

remove_bucket_from_node(#node{weight = W, buckets = BM} = Node, BucketName) ->
    case maps:find(BucketName, BM) of
        {ok, Props} ->
            Node#node{weight = W - ns_bucket:get_weight(Props),
                      buckets = maps:remove(BucketName, BM)};
        error ->
            Node
    end.

calculate_desired_servers(Nodes, BucketName, Props, Params) ->
    Width = ns_bucket:get_width(Props),
    Possible =
        lists:filter(
          fun ({_, Node}) ->
                  bucket_placement_possible(Node, BucketName, Props, Params)
          end, Nodes),

    case (length(Possible) < Width) of
        true ->
            error;
        false ->
            Prioritized = lists:sort(priority(_, _, BucketName), Possible),
            Trimmed = lists:sublist(Prioritized, Width),

            {ok, [N || {N, _} <- Trimmed]}
    end.

params_diff(BucketsMap, BucketName, Props) ->
    case maps:find(BucketName, BucketsMap) of
        {ok, OldProps} ->
            {ns_bucket:get_weight(Props) - ns_bucket:get_weight(OldProps), 0,
             ns_bucket:raw_ram_quota(Props) -
                 ns_bucket:raw_ram_quota(OldProps)};
        error ->
            {ns_bucket:get_weight(Props), 1, ns_bucket:raw_ram_quota(Props)}
    end.

bucket_placement_possible(#node{buckets = BucketsMap, weight = TotalWeight,
                                memory_used = MemoryUsed},
                          BucketName, Props,
                          #params{weight_limit = WeightLimit,
                                  tenant_limit = TenantLimit,
                                  memory_quota = MemoryQuota}) ->
    {WeightDiff, TenantDiff, MemoryDiff} =
        params_diff(BucketsMap, BucketName, Props),
    TotalWeight + WeightDiff =< WeightLimit andalso
        maps:size(BucketsMap) + TenantDiff =< TenantLimit andalso
        MemoryUsed + MemoryDiff =< MemoryQuota.

priority({_, #node{weight = W1, buckets = BM1}},
         {_, #node{weight = W2, buckets = BM2}}, BucketName) ->
    case {maps:is_key(BucketName, BM1), maps:is_key(BucketName, BM2)} of
        {X1, X2} when X1 =/= X2 ->
            X1 > X2;
        _ ->
            W1 =< W2
    end.

rebalance(KeepNodes, undefined) ->
    rebalance(KeepNodes, []);
rebalance(KeepNodes, DefragmentZones) ->
    rebalance(KeepNodes, DefragmentZones, get_params(), get_snapshot()).

rebalance(KeepNodes, DefragmentZones, Params, Snapshot) ->
    Buckets = get_eligible_buckets(Snapshot),

    SortedByWeight =
        lists:sort(fun ({_, Props1}, {_, Props2}) ->
                           ns_bucket:get_weight(Props1) >=
                               ns_bucket:get_weight(Props2)
                   end, Buckets),

    Fun =
        fun (AllGroupNodes, Group) ->
                case lists:member(proplists:get_value(name, Group),
                                  DefragmentZones) of
                    true ->
                        defragment_zone(AllGroupNodes, KeepNodes,
                                        SortedByWeight, Params);
                    false ->
                        rebalance_zone(AllGroupNodes, KeepNodes, SortedByWeight,
                                       Params, Snapshot)
                end
        end,

    case on_groups(Fun, Snapshot) of
        {ok, Res} ->
            {ok, massage_rebalance_result(Res, SortedByWeight)};
        Error ->
            Error
    end.

zip_servers([[] | _], Acc) ->
    lists:reverse(Acc);
zip_servers(ResultsForZones, Acc) ->
    zip_servers([Rest || [_ | Rest] <- ResultsForZones],
                [lists:sort(
                   lists:flatten([Hd || [Hd | _] <- ResultsForZones])) | Acc]).

massage_rebalance_result(Res, Buckets) ->
    lists:filtermap(
      fun ({{BucketName, Props}, Servers}) ->
              case ns_bucket:get_desired_servers(Props) of
                  Servers ->
                      false;
                  _ ->
                      {true, {BucketName, Servers}}
              end
      end, lists:zip(Buckets, zip_servers(Res, []))).

rebalance_zone(AllGroupNodes, KeepNodes, Buckets, Params, Snapshot) ->
    Nodes = construct_zone(AllGroupNodes, Snapshot, Buckets),
    DesiredNodes =
        misc:update_proplist(
          [{N, empty_node()} || N <- lists:filter(
                                       lists:member(_, AllGroupNodes),
                                       KeepNodes)],
          lists:filter(fun ({Name, _}) ->
                               lists:member(Name, KeepNodes)
                       end, Nodes)),

    case place_buckets_on_nodes(DesiredNodes, Buckets, Params, []) of
        {ok, Servers} ->
            {ok, Servers};
        error ->
            defragment_zone([N || {N, _} <- DesiredNodes], Buckets, Params)
    end.

defragment_zone(AllGroupNodes, KeepNodes, Buckets, Params) ->
    DesiredNodes = lists:filter(lists:member(_, AllGroupNodes),
                                KeepNodes),
    defragment_zone(DesiredNodes, Buckets, Params).

defragment_zone(Nodes, Buckets, Params) ->
    EmptyZone = [{N, empty_node()} || N <- Nodes],
    place_buckets_on_nodes(EmptyZone, Buckets, Params, []).

place_buckets_on_nodes(_Nodes, [], _Params, AccServers) ->
    {ok, lists:reverse(AccServers)};
place_buckets_on_nodes(Nodes, [{BucketName, Props} | Rest], Params,
                       AccServers) ->
    case calculate_desired_servers(Nodes, BucketName, Props, Params) of
        error ->
            error;
        {ok, Servers} ->
            NewProps = ns_bucket:update_desired_servers(Servers, Props),
            NewNodes =
                lists:map(
                  fun ({NName, NStruct}) ->
                          {NName, apply_buckets_to_node(
                                    NName, NStruct, [{BucketName, NewProps}])}
                  end, Nodes),
            place_buckets_on_nodes(NewNodes, Rest, Params,
                                   [Servers | AccServers])
    end.

construct_json(Weight, NBuckets, Memory) ->
    {[{kv, {[{buckets, NBuckets}, {memory, Memory}, {weight, Weight}]}}]}.

get_node_status_fun(Snapshot) ->
    case is_enabled() of
        false ->
            fun (_) -> [] end;
        true ->
            get_node_status_fun(Snapshot, get_params())
    end.

get_node_status_fun(Snapshot, #params{weight_limit = WeightLimit,
                                      tenant_limit = TenantLimit,
                                      memory_quota = MemQuota}) ->
    Limits = {limits, construct_json(WeightLimit, TenantLimit, MemQuota)},
    {ok, NodesList} = on_zones(fun (_, Nodes) -> {ok, Nodes} end,
                               get_eligible_buckets(Snapshot), Snapshot),
    NodesMap = maps:from_list(lists:flatten(NodesList)),
    fun (Node) ->
            case maps:find(Node, NodesMap) of
                {ok, #node{weight = W, memory_used = M, buckets = B}} ->
                    [Limits,
                     {utilization, construct_json(W, maps:size(B), M)}];
                error ->
                    []
            end
    end.

is_balanced(BucketConfig, Servers, DesiredServers) ->
    case lists:sort(DesiredServers) =/= lists:sort(Servers) of
        true ->
            false;
        false ->
            Width = ns_bucket:get_width(BucketConfig),
            lists:all(
              fun (Group) ->
                      AllGroupNodes = proplists:get_value(nodes, Group),
                      GroupServers = lists:filter(
                                       lists:member(_, AllGroupNodes),
                                       Servers),
                      length(GroupServers) =:= Width
              end, ns_cluster_membership:server_groups())
    end.

-ifdef(TEST).
populate_nodes(Zones) ->
    ServerGroups = [[{name, Z}, {nodes, Nodes}] || {Z, Nodes} <- Zones],
    NodesWanted = [N || {_, Nodes} <- Zones, N <- Nodes],
    NodeKeys = [[{{node, N, membership}, active},
                 {{node, N, services}, [kv]}] || N <- NodesWanted],
    KVList = lists:flatten([[{server_groups, ServerGroups},
                             {nodes_wanted, NodesWanted}], NodeKeys]),
    maps:from_list([{K, {V, no_rev}} || {K, V} <- KVList]).

apply_bucket_to_snapshot(Name, Props, Snapshot) ->
    Buckets = ns_bucket:get_bucket_names(Snapshot),
    S1 = maps:put(ns_bucket:root(),
                  {lists:usort([Name | Buckets]), no_rev}, Snapshot),
    maps:put(ns_bucket:sub_key(Name, props), {Props, no_rev}, S1).

verify_bucket(Name, Zones, Snapshot) ->
    {ok, Props} = ns_bucket:get_bucket(Name, Snapshot),
    Width = ns_bucket:get_width(Props),
    DesiredServers = ns_bucket:get_desired_servers(Props),
    lists:foreach(
      fun ({Z, ZNodes}) ->
              ZServers = lists:filter(lists:member(_, ZNodes), DesiredServers),
              ?assertEqual({Name, Z, Width}, {Name, Z, length(ZServers)})
      end, Zones),
    AllZoneNodes = lists:flatten([NList || {_, NList} <- Zones]),
    ?assertEqual({Name, []}, {Name, DesiredServers -- AllZoneNodes}).

with_default_ram_quota(Props) ->
    misc:merge_proplists(fun (_, L, _) -> L end, Props, [{ram_quota, 1}]).

success_placement(Name, Props, Params, Zones, Snapshot) ->
    RV = do_place_bucket(Name, with_default_ram_quota(Props), Params, Snapshot),
    ?assertMatch({Name, {ok, _}}, {Name, RV}),
    {ok, NewProps} = RV,
    NewSnapshot = apply_bucket_to_snapshot(Name, NewProps, Snapshot),
    verify_bucket(Name, Zones, NewSnapshot),
    NewSnapshot.

apply_rebalance_rv_to_snapshot(RV, Snapshot) ->
    ?assertMatch({ok, _}, RV),
    {ok, NewServers} = RV,
    lists:foldl(
      fun ({BucketName, Servers}, Acc) ->
              {ok, Props} = ns_bucket:get_bucket(BucketName, Acc),
              NewProps = ns_bucket:update_desired_servers(Servers, Props),
              apply_bucket_to_snapshot(BucketName, NewProps, Acc)
      end, Snapshot, NewServers).

failed_placement(Name, Props, Params, Zones, Snapshot) ->
    RV = do_place_bucket(Name, with_default_ram_quota(Props), Params, Snapshot),
    ?assertMatch({Name, {error, _}}, {Name, RV}),
    {error, ZonesList} = RV,
    ?assertEqual(lists:sort(ZonesList), lists:sort(Zones)).

bucket_placer_test_() ->
    Zones = [{z1, [a1, b1, c1]}, {z2, [a2, b2, c2]}, {z3, [a3, b3, c3]}],
    ZoneNames = [Z || {Z, _} <- Zones],
    AllNodes = lists:flatten([N || {_, N} <- Zones]),

    Params = #params{weight_limit = 6, tenant_limit = 3, memory_quota = 10},
    Snapshot = maps:put(ns_bucket:root(), {[], no_rev}, populate_nodes(Zones)),

    SuccessPlacement = success_placement(_, _, Params, Zones, _),
    FailedPlacement = failed_placement(_, _, Params, ZoneNames, _),

    PreRebalanceSnapshot =
        fun (B2Width) ->
                functools:chain(
                  Snapshot,
                  [SuccessPlacement("B1", [{width, 2}, {weight, 2}], _),
                   SuccessPlacement("B2", [{width, B2Width}, {weight, 3}], _)])
        end,

    VerifyRebalance =
        fun (RV, Ejected, S) ->
                BucketNames = ns_bucket:get_bucket_names(S),
                NewZones = [{N, Nodes -- Ejected} || {N, Nodes} <- Zones],
                S1 = apply_rebalance_rv_to_snapshot(RV, S),
                [verify_bucket(Name, NewZones, S1) || Name <- BucketNames]
        end,

    Failover =
        fun (S1) ->
                S2 = lists:foldl(
                       fun ({Name, Props}, Acc) ->
                               DesiredServers =
                                   ns_bucket:get_desired_servers(Props),
                               NewProps = ns_bucket:update_desired_servers(
                                            DesiredServers -- [c1], Props),
                               apply_bucket_to_snapshot(Name, NewProps, Acc)
                       end, S1, ns_bucket:get_buckets(S1)),
                {rebalance(AllNodes -- [c1], [], Params, S2), S2}
        end,

    [{"Bucket placement test",
      fun () ->
              Snapshot1 =
                  functools:chain(
                    Snapshot,
                    [SuccessPlacement("B1", [{width, 1}, {weight, 1}], _),
                     SuccessPlacement("B2", [{width, 3}, {weight, 3}], _),
                     SuccessPlacement("B1", [{width, 2}, {weight, 2}], _)]),

              FailedPlacement("B3", [{width, 2}, {weight, 2}], Snapshot1),
              SuccessPlacement("B3", [{width, 1}, {weight, 2}], Snapshot1),

              functools:chain(
                Snapshot1,
                [SuccessPlacement("B1", [{width, 1}, {weight, 1}], _),
                 SuccessPlacement("B3", [{width, 2}, {weight, 2}], _)]),

              FailedPlacement("B1", [{width, 2}, {weight, 4}], Snapshot1)
      end},
     {"Weight = 0",
      fun () ->
              functools:chain(
                Snapshot,
                [SuccessPlacement("B1", [{width, 3}, {weight, 6}], _),
                 SuccessPlacement("B2", [{width, 2}, {weight, 0}], _),
                 SuccessPlacement("B3", [{width, 2}, {weight, 0}], _),
                 FailedPlacement("B3", [{width, 2}, {weight, 1}], _)])
      end},
     {"Tenant limit test",
      fun () ->
              functools:chain(
                Snapshot,
                [SuccessPlacement("B1", [{width, 3}, {weight, 0}], _),
                 SuccessPlacement("B2", [{width, 3}, {weight, 0}], _),
                 SuccessPlacement("B3", [{width, 3}, {weight, 0}], _),
                 FailedPlacement("B4", [{width, 1}, {weight, 0}], _)])
      end},
     {"Memory quota test",
      fun () ->
              functools:chain(
                Snapshot,
                [SuccessPlacement("B1", [{width, 3}, {weight, 0},
                                         {ram_quota, 8}], _),
                 SuccessPlacement("B2", [{width, 3}, {weight, 0},
                                         {ram_quota, 2}], _),
                 FailedPlacement("B3", [{width, 1}, {weight, 0}], _)])
      end},
     {"Node status fun",
      fun () ->
              S1 = functools:chain(
                     Snapshot,
                     [SuccessPlacement("B1", [{width, 3}, {weight, 3},
                                              {ram_quota, 5}], _),
                      SuccessPlacement("B2", [{width, 3}, {weight, 2},
                                              {ram_quota, 2}], _)]),
              Fun = get_node_status_fun(S1, Params),
              ?assertEqual(
                 [{limits,
                   {[{kv, {[{buckets, 3}, {memory, 10}, {weight, 6}]}}]}},
                  {utilization,
                   {[{kv, {[{buckets, 2}, {memory, 7}, {weight, 5}]}}]}}],
                 Fun(a2))
      end},
     {"Rebalance of balanced zone is a no op",
      fun () ->
              Snapshot1 = PreRebalanceSnapshot(3),
              RV = rebalance(AllNodes, [], Params, Snapshot1),
              ?assertEqual({ok, []}, RV)
      end},
     {"Rebalancing the node out",
      fun () ->
              Snapshot1 = PreRebalanceSnapshot(3),
              RV = rebalance(AllNodes -- [c1], [], Params, Snapshot1),
              ?assertEqual({error, [z1]}, RV),

              Snapshot2 = SuccessPlacement("B2", [{width, 2}, {weight, 3}],
                                           Snapshot1),
              RV1 = rebalance(AllNodes -- [c1], [], Params, Snapshot2),
              VerifyRebalance(RV1, [c1], Snapshot2)
      end},
     {"Recovery after failover",
      fun () ->
              RV = Failover(PreRebalanceSnapshot(3)),
              ?assertMatch({{error, [z1]}, _}, RV),
              {RV1, Snapshot1} = Failover(PreRebalanceSnapshot(2)),
              VerifyRebalance(RV1, [c1], Snapshot1)
      end}].

-endif.
