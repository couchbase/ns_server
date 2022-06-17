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

-export([is_enabled/0, place_bucket/2]).

-record(params, {weight_limit}).

-record(node, {weight, buckets}).

is_enabled() ->
    config_profile:get_bool(enable_bucket_placer).

get_weight_limit() ->
    config_profile:get_value(bucket_weight_limit, 10000).

get_params() ->
    #params{weight_limit = get_weight_limit()}.

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
    RV = on_zones(calculate_desired_servers(_, BucketName, Props, Params),
                  Snapshot),
    case RV of
        {ok, Servers} ->
            DesiredServers = lists:sort(lists:flatten(Servers)),
            {ok, lists:keystore(desired_servers, 1, Props,
                                {desired_servers, DesiredServers})};
        Error ->
            Error
    end.

get_eligible_buckets(Snapshot) ->
    lists:filter(fun ({_, P}) -> ns_bucket:get_width(P) =/= undefined end,
                 ns_bucket:get_buckets(Snapshot)).

on_zones(Fun, Snapshot) ->
    Groups = ns_cluster_membership:server_groups(Snapshot),
    Buckets = get_eligible_buckets(Snapshot),

    Results =
        lists:map(
          fun (Group) ->
                  Nodes = construct_zone(proplists:get_value(nodes, Group),
                                         Snapshot, Buckets),
                  Fun(Nodes)
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
    #node{weight = 0, buckets = maps:new()}.

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

apply_bucket_to_node(#node{weight = W, buckets = BM} = Node, BucketName,
                     Props) ->
    Node#node{weight = W + weight_diff(BM, BucketName, Props),
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

weight_diff(BucketsMap, BucketName, Props) ->
    case maps:find(BucketName, BucketsMap) of
        {ok, OldProps} ->
            ns_bucket:get_weight(Props) - ns_bucket:get_weight(OldProps);
        error ->
            ns_bucket:get_weight(Props)
    end.

bucket_placement_possible(#node{buckets = BucketsMap, weight = TotalWeight},
                          BucketName, Props,
                          #params{weight_limit = WeightLimit}) ->
    TotalWeight + weight_diff(BucketsMap, BucketName, Props)
        =< WeightLimit.

priority({_, #node{weight = W1, buckets = BM1}},
         {_, #node{weight = W2, buckets = BM2}}, BucketName) ->
    case {maps:is_key(BucketName, BM1), maps:is_key(BucketName, BM2)} of
        {X1, X2} when X1 =/= X2 ->
            X1 > X2;
        _ ->
            W1 =< W2
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
    ?assertEqual({Name, Width * length(Zones)}, {Name, length(DesiredServers)}).

success_placement(Name, Props, Params, Zones, Snapshot) ->
    RV = do_place_bucket(Name, Props, Params, Snapshot),
    ?assertMatch({Name, {ok, _}}, {Name, RV}),
    {ok, NewProps} = RV,
    NewSnapshot = apply_bucket_to_snapshot(Name, NewProps, Snapshot),
    verify_bucket(Name, Zones, NewSnapshot),
    NewSnapshot.

failed_placement(Name, Props, Params, Zones, Snapshot) ->
    RV = do_place_bucket(Name, Props, Params, Snapshot),
    ?assertMatch({Name, {error, _}}, {Name, RV}),
    {error, ZonesList} = RV,
    ?assertEqual(lists:sort(ZonesList), lists:sort(Zones)).

bucket_placer_test_() ->
    Zones = [{z1, [a1, b1, c1]}, {z2, [a2, b2, c2]}, {z3, [a3, b3, c3]}],
    ZoneNames = [Z || {Z, _} <- Zones],

    Params = #params{weight_limit = 6},
    Snapshot = maps:put(ns_bucket:root(), {[], no_rev}, populate_nodes(Zones)),

    SuccessPlacement = success_placement(_, _, Params, ZoneNames, _),
    FailedPlacement = failed_placement(_, _, Params, ZoneNames, _),

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
      end}].

-endif.
