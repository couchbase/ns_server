%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% Monitor and maintain the vbucket layout of each bucket.
%% There is one of these per bucket.
%%
%% @doc code related to fusion snapshot restore
%%

-module(fusion_backup).

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").

-export([validate_prepare_snapshot_restore/0,
         prepare_snapshot_restore/1]).

-spec validate_prepare_snapshot_restore() -> ok | {error, not_enabled}.
validate_prepare_snapshot_restore() ->
    case fusion_uploaders:get_state() of
        enabled ->
            ok;
        _ ->
            {error, not_enabled}
    end.

-spec prepare_snapshot_restore(
        [{ns_bucket:name(), ns_bucket:config(), list(), list()}]) ->
          {ok, list(), list()}.
prepare_snapshot_restore(BucketInfos) ->
    PlanUUID = couch_uuids:random(),
    KVNodes = ns_cluster_membership:service_active_nodes(kv),

    BucketResults =
        [prepare_single_bucket_restore(BucketConfig, KVNodes, Manifest) ||
            {_BucketName, BucketConfig, Manifest, _RawConfig}
                <- BucketInfos],

    RestorePlan = build_restore_plan(PlanUUID, KVNodes, BucketResults),
    RestoreBlueprint =
        [{nodes, KVNodes},
         {buckets, [#{name => BucketName, uuid => UUID, props => RawConfig,
                      map => Map, opts => Opts} ||
                       {{{UUID, Map, Opts}, _, _},
                        {BucketName, _, _, RawConfig}}
                           <- lists:zip(BucketResults, BucketInfos)]}],

    ale:info(?USER_LOGGER,
             "Prepared fusion snapshot restore. PlanUUID: ~p", [PlanUUID]),
    {ok, RestorePlan, RestoreBlueprint}.

build_restore_plan(PlanUUID, KVNodes, BucketResults) ->
    [{planUUID, PlanUUID},
     {namespaces, [NSInfo || {_, _, NSInfo} <- BucketResults]},
     {nodes, build_nodes_info(KVNodes, BucketResults)}].

build_nodes_info(KVNodes, BucketResults) ->
    {[{Node, lists:flatmap(
               fun ({_, NodeVolumesMap, _}) ->
                       case maps:find(Node, NodeVolumesMap) of
                           {ok, Volumes} ->
                               Volumes;
                           error ->
                               []
                       end
               end, BucketResults)} || Node <- KVNodes]}.

extract_vbucket_num(VolumeID) ->
    {match, [NumStr]} =
        re:run(VolumeID, "kvstore-(\\d+)$", [{capture, [1], list}]),
    list_to_integer(NumStr).

prepare_single_bucket_restore(BucketConfig, KVNodes, Manifest) ->
    NewBucketUUID = couch_uuids:random(),
    SourceNamespacePrefix = proplists:get_value(namespace, Manifest),
    NSInfo =
        {[{src, list_to_binary(SourceNamespacePrefix)},
          {dst, <<"kv/", NewBucketUUID/binary>>}]},
    Volumes = proplists:get_value(volumes, Manifest),
    NVBuckets = length(Volumes),
    VolumesMap = maps:from_list(
                   [{extract_vbucket_num(
                       proplists:get_value(volumeID, Volume)), {Volume}} ||
                       {Volume} <- Volumes]),
    NReplicas = ns_bucket:num_replicas(BucketConfig),
    Opts = ns_rebalancer:generate_vbucket_map_options(KVNodes, BucketConfig),
    VBMap = mb_map:generate_map(mb_map:no_nodes_map(NVBuckets, NReplicas),
                                NReplicas, KVNodes, Opts),
    NodeVBDict = mb_map:map_to_vbuckets_dict(VBMap),
    NodeVolumesMap =
        maps:from_list(
          [{N, [maps:get(VB, VolumesMap) || VB <- VBs]} ||
              {N, VBs} <- dict:to_list(NodeVBDict)]),
    {{NewBucketUUID, VBMap, Opts}, NodeVolumesMap, NSInfo}.
