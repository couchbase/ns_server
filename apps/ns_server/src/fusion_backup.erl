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
         prepare_snapshot_restore/1,
         validate_restore/2,
         restore/2,
         restore_in_progress/1]).
-export_type([validate_restore_bucket_error/0, validate_restore_error/0,
              restore_bucket_error/0]).

-define(BUCKET_RESTORE_TIMEOUT, ?get_timeout(bucket_restore, timer:minutes(6))).

-type validate_restore_bucket_error() ::
        {ns_bucket:name(), list() | binary()}.

-type validate_restore_error() ::
        not_enabled |
        nodes_mismatch |
        {need_nodes, [string()]} |
        {extra_nodes, [string()]}.

-type restore_error() ::
        wait_for_bucket |
        {failed_nodes, [node()]} |
        ns_orchestrator:bucket_create_error().

-type restore_bucket_error() ::
        {ns_bucket:name(), restore_error()}.

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
         {planUUID, PlanUUID},
         {buckets, [#{name => BucketName, uuid => UUID, props => RawConfig,
                      map => Map, opts => Opts, terms => Terms} ||
                       {{{UUID, Map, Terms, Opts}, _, _},
                        {BucketName, _, _Manifest, RawConfig}}
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
    Terms = [proplists:get_value(logManifestTerm, Volume) ||
                {Volume} <- Volumes],
    {{NewBucketUUID, VBMap, Terms, Opts}, NodeVolumesMap, NSInfo}.

-spec validate_restore(list(), list()) ->
          {ok, {[map()], list()}} |
          {error, validate_restore_error()} |
          {errors, [validate_restore_bucket_error()]}.
validate_restore(Blueprint, Volumes) ->
    chronicle_compat:pull(),
    KVNodes = ns_cluster_membership:service_active_nodes(kv),
    maybe
        true ?= (fusion_uploaders:get_state() =:= enabled) orelse
            {error, not_enabled},

        true ?= proplists:get_value(nodes, Blueprint) =:= KVNodes orelse
            {error, nodes_mismatch},

        VolumesNodeNames = [N || {N, _} <- Volumes],
        true ?= lists:sort([atom_to_list(N) || N <- KVNodes]) =:=
            lists:sort(VolumesNodeNames) orelse {error, nodes_mismatch},

        BucketInfos = proplists:get_value(buckets, Blueprint),
        ConfigsToValidate = [{maps:get(name, BucketInfo),
                              maps:get(props, BucketInfo)} ||
                                BucketInfo <- BucketInfos],

        %% Buckets were already validated in prepare_snapshot_restore
        %% (to report issues early) but cluster might have changed since,
        %% so we need another validation pass here to account for that.
        Validated = menelaus_web_buckets:parse_new_buckets(ConfigsToValidate),

        Errors = [{BucketName, Errors} || {errors, BucketName, Errors} <-
                                              Validated],
        true ?= Errors =:= [] orelse {errors, Errors},

        BucketConfigs = [ns_bucket:extract_bucket_props(ParsedConfig) ||
                            {ok, _BucketName, ParsedConfig} <- Validated],

        Zipped = lists:zip(BucketInfos, BucketConfigs),

        MapOptsErrors =
            lists:filtermap(
              fun ({BucketInfo, BucketConfig}) ->
                      Opts = maps:get(opts, BucketInfo),
                      case ns_rebalancer:generate_vbucket_map_options(
                             KVNodes, BucketConfig) of
                          Opts ->
                              false;
                          _ ->
                              {true, {maps:get(name, BucketInfo),
                                      <<"Map options mismatch">>}}
                      end
              end, Zipped),

        true ?= MapOptsErrors =:= []
            orelse {errors, MapOptsErrors},

        {ok, PreparedVolumes} ?= fusion_uploaders:validate_mounted_volumes(
                                   KVNodes, Volumes),

        {ok, {[BucketInfo#{config => BucketConfig} ||
                  {BucketInfo, BucketConfig} <- Zipped], PreparedVolumes}}
    end.

create_bucket(Servers, #{name := BucketName, uuid := UUID, map := Map,
                         opts := MapOpts, config := BucketConfig,
                         terms := Terms}) ->
    ?log_info("Creating bucket ~p with UUID = ~p", [BucketName, UUID]),
    case ns_orchestrator:create_membase_bucket(
           BucketName, [{fusion_restore_in_progress, true} | BucketConfig],
           UUID) of
        ok ->
            ?log_info("Set servers ~p on bucket ~p", [Servers, BucketName]),
            ok = ns_bucket:set_servers(BucketName, Servers),
            ?log_info("Set map for bucket ~p~nmap:~n~p~nopts: ~p",
                      [BucketName, Map, MapOpts]),
            {ok, _} = ns_bucket:store_last_balanced_vbmap(
                        BucketName, Map, MapOpts),
            Uploaders = [{N, Term + 1} ||
                            {[N | _], Term} <- lists:zip(Map, Terms)],
            ok = ns_bucket:set_map_and_uploaders(BucketName, Map, MapOpts,
                                                 Uploaders),
            ok = testconditions:check_test_condition(
                   ?NS_SERVER_LOGGER, restore_fusion_bucket, BucketName);
        Error ->
            Error
    end.

restore_bucket(Servers, Volumes, #{name := BucketName, map := Map}) ->
    maybe
        NodesVBMap = maps:from_list(
                       dict:to_list(mb_map:map_to_vbuckets_dict(Map))),

        ?log_info("Mount volumes ~p for bucket ~p. NodesVBMap: ~p",
                  [Volumes, BucketName, NodesVBMap]),
        ok ?= janitor_agent:mount_volumes(BucketName, Volumes, NodesVBMap,
                                          undefined),

        {ok, BucketConfig} = ns_bucket:get_bucket(BucketName),
        ?log_debug("Apply bucket config for bucket ~p~n~p",
                   [BucketName, BucketConfig]),
        ok ?= janitor_agent:apply_new_bucket_config(
                BucketName, Servers, BucketConfig, [{use_snapshot, fusion}],
                undefined_timeout),
        ok = ns_bucket:update_bucket_config(
               BucketName, lists:keydelete(fusion_restore_in_progress, 1, _)),

        ?log_debug("Wait for bucket ~p to be available on ~p",
                   [BucketName, Servers]),
        true ?= ns_rebalancer:wait_for_bucket(BucketName, Servers) =:= ok orelse
            {error, wait_for_bucket}
    end.

restore_in_progress(BucketConfig) ->
    proplists:get_bool(fusion_restore_in_progress, BucketConfig).

-spec restore(list(), list()) ->
          ok | [{ns_bucket:name(), restore_error()}].
restore(Volumes, BucketInfos) ->
    KVNodes = ns_cluster_membership:service_active_nodes(kv),
    BucketCreateReplies =
        [{BucketName, create_bucket(KVNodes, BucketInfo)} ||
            BucketInfo = #{name := BucketName} <- BucketInfos],
    BucketCreateErrors =
        [{BucketName, Error} ||
            {BucketName, Error = {error, _}} <- BucketCreateReplies],
    case BucketCreateErrors of
        [] ->
            RV = misc:parallel_map(
                   fun (BucketInfo = #{name := BucketName}) ->
                           {BucketName, restore_bucket(
                                          KVNodes, Volumes, BucketInfo)}
                   end, BucketInfos, ?BUCKET_RESTORE_TIMEOUT),
            BucketRestoreErrors =
                [{BucketName, Error} || {BucketName, {error, Error}} <- RV],
            case BucketRestoreErrors of
                [] ->
                    ok;
                _ ->
                    BucketRestoreErrors
            end;
        _ ->
            BucketCreateErrors
    end.
