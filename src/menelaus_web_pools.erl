%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-2020 Couchbase, Inc.
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

%% @doc implementation of pools REST API's

-module(menelaus_web_pools).

-include("ns_common.hrl").
-include("ns_heart.hrl").
-include("cut.hrl").

-export([handle_pools/1,
         check_and_handle_pool_info/2,
         handle_pool_info_streaming/2,
         handle_pool_settings_post/1,
         handle_terse_cluster_info/1]).

%% for hibernate
-export([handle_pool_info_wait_wake/4]).

-import(menelaus_util,
        [reply_json/2,
         reply_json/3,
         local_addr/1,
         encode_json/1,
         reply_ok/4,
         bin_concat_path/1,
         bin_concat_path/2,
         format_server_time/1,
         handle_streaming/2,
         reply/2]).

handle_pools(Req) ->
    %% TODO RBAC for the time being let's tell the UI that the user is admin
    %% later there will be an API to test the permissions

    Enterprise = cluster_compat_mode:is_enterprise(),
    AllowedServices =
        ns_cluster_membership:allowed_services(case Enterprise of
                                                   true ->
                                                       enterprise;
                                                   false ->
                                                       community
                                               end),
    RV1 = [{isAdminCreds, true},
           {isROAdminCreds, false},
           {isEnterprise, Enterprise},
           {allowedServices, AllowedServices},
           {isIPv6, misc:is_ipv6()},
           {isDeveloperPreview, cluster_compat_mode:is_developer_preview()}
           | get_content_for_provisioned_system()],
    RV = RV1 ++ menelaus_web_cache:versions_response(),
    reply_json(Req, {struct, RV}).

get_content_for_provisioned_system() ->
    {Pools, Settings, UUID} =
        case ns_config_auth:is_system_provisioned() of
            true ->
                UUID1 = menelaus_web:get_uuid(),
                Pools1 = [{struct,
                           [{name, <<"default">>},
                            {uri, <<"/pools/default?uuid=", UUID1/binary>>},
                            {streamingUri, <<"/poolsStreaming/default?uuid=", UUID1/binary>>}]}],
                Settings1 = {struct,
                             [{<<"maxParallelIndexers">>,
                               <<"/settings/maxParallelIndexers?uuid=", UUID1/binary>>},
                              {<<"viewUpdateDaemon">>,
                               <<"/settings/viewUpdateDaemon?uuid=", UUID1/binary>>}]},
                {Pools1, Settings1, UUID1};
            false ->
                {[], [], []}
        end,
    [{pools, Pools}, {settings, Settings}, {uuid, UUID}].

check_and_handle_pool_info(Id, Req) ->
    case ns_config_auth:is_system_provisioned() of
        true ->
            handle_pool_info(Id, Req);
        _ ->
            reply_json(Req, <<"unknown pool">>, 404)
    end.

handle_pool_info(Id, Req) ->
    LocalAddr = local_addr(Req),
    Query = mochiweb_request:parse_qs(Req),
    WaitChangeS = proplists:get_value("waitChange", Query),
    PassedETag = proplists:get_value("etag", Query),
    case WaitChangeS of
        undefined ->
            reply_json(Req, build_pool_info(Id, Req, normal, unstable,
                                            LocalAddr, undefined));
        _ ->
            WaitChange = list_to_integer(WaitChangeS),
            menelaus_event:register_watcher(self()),
            erlang:send_after(WaitChange, self(), wait_expired),
            handle_pool_info_wait(Req, Id, LocalAddr, PassedETag, undefined)
    end.

handle_pool_info_wait(Req, Id, LocalAddr, PassedETag, UpdateID) ->
    Info = build_pool_info(Id, Req, for_ui, stable, LocalAddr, UpdateID),
    ETag = integer_to_list(erlang:phash2(Info)),
    if
        ETag =:= PassedETag ->
            erlang:hibernate(?MODULE, handle_pool_info_wait_wake,
                             [Req, Id, LocalAddr, PassedETag]);
        true ->
            handle_pool_info_wait_tail(Req, Id, LocalAddr, ETag, UpdateID)
    end.

handle_pool_info_wait_wake(Req, Id, LocalAddr, PassedETag) ->
    receive
        wait_expired ->
            handle_pool_info_wait_tail(Req, Id, LocalAddr, PassedETag,
                                       undefined);
        {notify_watcher, ID} ->
            timer:sleep(200), %% delay a bit to catch more notifications
            LastID = menelaus_event:flush_watcher_notifications(ID),
            handle_pool_info_wait(Req, Id, LocalAddr, PassedETag, LastID);
        _ ->
            exit(normal)
    end.

handle_pool_info_wait_tail(Req, Id, LocalAddr, ETag, UpdateID) ->
    menelaus_event:unregister_watcher(self()),
    %% consume all notifications
    LastID = menelaus_event:flush_watcher_notifications(UpdateID),
    %% and reply
    {struct, PList} = build_pool_info(Id, Req, for_ui, unstable, LocalAddr,
                                      LastID),
    Info = {struct, [{etag, list_to_binary(ETag)} | PList]},
    reply_ok(Req, "application/json", encode_json(Info),
             menelaus_auth:maybe_refresh_token(Req)),
    %% this will cause some extra latency on ui perhaps,
    %% because browsers commonly assume we'll keepalive, but
    %% keeping memory usage low is imho more important
    exit(normal).


build_pool_info(Id, Req, normal, Stability, LocalAddr, UpdateID) ->
    InfoLevel =
        case menelaus_auth:has_permission({[admin, internal], all}, Req) of
            true ->
                case menelaus_auth:is_internal(Req) of
                    true ->
                        internal;
                    false ->
                        admin
                end;
            false ->
                normal
        end,

    %% NOTE: we limit our caching here for "normal" info
    %% level. Explicitly excluding UI (which InfoLevel = for_ui). This
    %% is because caching doesn't take into account "buckets version"
    %% which is important to deliver asap to UI (i.e. without any
    %% caching "staleness"). Same situation is with tasks version
    menelaus_web_cache:lookup_or_compute_with_expiration(
      {pool_details, InfoLevel, Stability, LocalAddr},
      fun () ->
              %% NOTE: token needs to be taken before building pool info
              Vsn = {ns_config:config_version_token(), nodes(), UpdateID},
              {do_build_pool_info(Id, InfoLevel, Stability, LocalAddr), 1000,
               Vsn}
      end,
      fun (_Key, _Value, {ConfigVersionToken, Nodes, OldUpdateID}) ->
              ConfigVersionToken =/= ns_config:config_version_token()
                  orelse Nodes =/= nodes()
                  orelse ((UpdateID =/= OldUpdateID) andalso
                          (UpdateID =/= undefined))
      end);
build_pool_info(Id, _Req, for_ui, Stability, LocalAddr, _UpdateID) ->
    do_build_pool_info(Id, for_ui, Stability, LocalAddr).

do_build_pool_info(Id, InfoLevel, Stability, LocalAddr) ->
    UUID = menelaus_web:get_uuid(),

    CanIncludeOtpCookie = InfoLevel =:= admin orelse InfoLevel =:= internal,
    Nodes = menelaus_web_node:build_nodes_info(CanIncludeOtpCookie, InfoLevel,
                                               Stability, LocalAddr),
    Config = ns_config:get(),

    TasksURI = bin_concat_path(["pools", Id, "tasks"],
                               [{"v", ns_doctor:get_tasks_version()}]),

    {ok, IndexesVersion0} = service_index:get_indexes_version(),
    IndexesVersion = list_to_binary(integer_to_list(IndexesVersion0)),

    GroupsV = erlang:phash2(ns_config:search(Config, server_groups)),

    PropList =
        [{name, list_to_binary(Id)},
         {nodes, Nodes},
         build_buckets_info(Config, Id, UUID, Nodes),
         build_uri_with_validation(remoteClusters,
                                   "/pools/default/remoteClusters", UUID),
         build_alerts(UUID),
         build_controllers(UUID),
         build_rebalance_params(Id, UUID),
         {nodeStatusesUri, <<"/nodeStatuses">>},
         {maxBucketCount, ns_bucket:get_max_buckets()},
         {autoCompactionSettings,
          menelaus_web_autocompaction:build_global_settings(Config)},
         {tasks, {struct, [{uri, TasksURI}]}},
         {counters, {struct, ns_cluster:counters()}},
         {indexStatusURI, <<"/indexStatus?v=", IndexesVersion/binary>>},
         {checkPermissionsURI,
          bin_concat_path(
            ["pools", Id, "checkPermissions"],
            [{"v", menelaus_web_rbac:check_permissions_url_version(Config)}])},
         {serverGroupsUri,
          <<"/pools/default/serverGroups?v=",
            (list_to_binary(integer_to_list(GroupsV)))/binary>>},
         {clusterName, list_to_binary(get_cluster_name())},
         {balanced, ns_cluster_membership:is_balanced()},
         menelaus_web_node:build_memory_quota_info(Config),
         build_ui_params(InfoLevel),
         build_internal_params(InfoLevel),
         build_unstable_params(Stability)],
    {struct, lists:flatten(PropList)}.

build_rebalance_params(Id, UUID) ->
    RebalanceStatus = case ns_orchestrator:is_rebalance_running() of
                          true ->
                              <<"running">>;
                          _ ->
                              <<"none">>
                      end,

    [{rebalanceStatus, RebalanceStatus},
     {rebalanceProgressUri,
      bin_concat_path(["pools", Id, "rebalanceProgress"])},
     {stopRebalanceUri, build_controller_uri("stopRebalance", UUID)}].

build_internal_params(internal) ->
    case ns_audit_cfg:get_uid() of
        undefined ->
            [];
        AuditUID ->
            [{auditUid, list_to_binary(AuditUID)}]
    end;
build_internal_params(_) ->
    [].

build_ui_params(for_ui) ->
    [{failoverWarnings, ns_bucket:failover_warnings()},
     {saslauthdEnabled, cluster_compat_mode:is_saslauthd_enabled()},
     {uiSessionTimeout,
      ns_config:read_key_fast(ui_session_timeout, undefined)}];
build_ui_params(_) ->
    [].

build_unstable_params(stable) ->
    [];
build_unstable_params(unstable) ->
    [{storageTotals,
      {[{Key, {StoragePList}} ||
           {Key, StoragePList} <- ns_storage_conf:cluster_storage_info()]}}].

build_buckets_info(Config, Id, UUID, Nodes) ->
     BucketsVer =
        erlang:phash2(
          ns_bucket:get_bucket_names(ns_bucket:get_buckets(Config)))
        bxor erlang:phash2(
               [{proplists:get_value(hostname, KV),
                 proplists:get_value(status, KV)} || {struct, KV} <- Nodes]),
    {buckets, {struct,
               [{uri, bin_concat_path(["pools", Id, "buckets"],
                                      [{"v", BucketsVer},
                                       {"uuid", UUID}])},
                {terseBucketsBase, <<"/pools/default/b/">>},
                {terseStreamingBucketsBase, <<"/pools/default/bs/">>}]}}.

build_controller(Name, UUID) ->
    build_controller(Name, atom_to_list(Name), UUID).

build_controller(Name, Endpoint, UUID) ->
    {Name, {struct, [{uri, build_controller_uri(Endpoint, UUID)}]}}.

build_uri_with_validation(Name, Endpoint, UUID) ->
    {Name, {struct, [{uri, build_uri_with_uuid(Endpoint, UUID)},
                     {validateURI, build_validate_uri(Endpoint)}]}}.

build_controller_uri(Endpoint, UUID) ->
    build_uri_with_uuid(["/controller/", Endpoint], UUID).

build_uri_with_uuid(Endpoint, UUID) ->
    iolist_to_binary([Endpoint, "?uuid=", UUID]).

build_validate_uri(Endpoint) ->
    iolist_to_binary([Endpoint, "?just_validate=1"]).

build_controllers(UUID) ->
    {controllers,
     {struct,
      [build_controller(addNode, "addNodeV2", UUID),
       build_controller(rebalance, UUID),
       build_controller(failOver, UUID),
       build_controller(startGracefulFailover, UUID),
       build_controller(reAddNode, UUID),
       build_controller(reFailOver, UUID),
       build_controller(ejectNode, UUID),
       build_controller(setRecoveryType, UUID),
       build_uri_with_validation(setAutoCompaction,
                                 "/controller/setAutoCompaction", UUID),
       {clusterLogsCollection,
        {struct,
         [{startURI, build_controller_uri("startLogsCollection", UUID)},
          {cancelURI, build_controller_uri("cancelLogsCollection", UUID)}]}},
       %% TODO Why is this such a special case?
       {replication,
        {struct,
         [{createURI, build_controller_uri("createReplication", UUID)},
          {validateURI, build_validate_uri("/controller/createReplication")}]
        }}]}}.

build_alerts(UUID) ->
    {Alerts, AlertsSilenceToken} = menelaus_web_alerts_srv:fetch_alerts(),
    [{alerts, [build_one_alert(Alert) || Alert <- Alerts]},
     {alertsSilenceURL,
      iolist_to_binary([build_controller_uri("resetAlerts", UUID), "&token=",
                        AlertsSilenceToken])}].

build_one_alert({_Key, Msg, Time}) ->
    LocalTime = calendar:now_to_local_time(misc:time_to_timestamp(Time)),
    StrTime = format_server_time(LocalTime),

    {struct, [{msg, Msg}, {serverTime, StrTime}]}.

handle_pool_info_streaming(Id, Req) ->
    LocalAddr = local_addr(Req),
    F = fun(Stability, UpdateID) ->
                build_pool_info(Id, Req, normal, Stability, LocalAddr, UpdateID)
        end,
    handle_streaming(F, Req).

get_cluster_name() ->
    get_cluster_name(ns_config:latest()).

get_cluster_name(Config) ->
    ns_config:search(Config, cluster_name, "").

pool_settings_post_validators(Config, CompatVersion) ->
    [validator:has_params(_),
     validator:touch(clusterName, _),
     validate_memory_quota(Config, CompatVersion, _),
     validator:unsupported(_)].

validate_memory_quota(Config, CompatVersion, ValidatorState) ->
    QuotaFields =
        [{memory_quota:service_to_json_name(Service), Service} ||
            Service <- memory_quota:aware_services(CompatVersion)],
    ValidationResult =
        lists:foldl(
          fun ({Key, _}, Acc) ->
                  validator:integer(Key, Acc)
          end, ValidatorState, QuotaFields),

    Quotas = lists:filtermap(
               fun ({Key, Service}) ->
                       case validator:get_value(Key, ValidationResult) of
                           undefined ->
                               false;
                           ServiceQuota ->
                               {true, {Service, ServiceQuota}}
                       end
               end, QuotaFields),

    case Quotas of
        [] ->
            ValidationResult;
        _ ->
            do_validate_memory_quota(Config, Quotas, ValidationResult)
    end.

do_validate_memory_quota(Config, Quotas, ValidatorState) ->
    Nodes = ns_node_disco:nodes_wanted(Config),
    {ok, NodeStatuses} = ns_doctor:wait_statuses(Nodes, 3 * ?HEART_BEAT_PERIOD),
    NodeInfos =
        lists:map(
          fun (Node) ->
                  NodeStatus = dict:fetch(Node, NodeStatuses),
                  {_, MemoryData} = lists:keyfind(memory_data, 1, NodeStatus),
                  NodeServices = ns_cluster_membership:node_services(Config, Node),
                  {Node, NodeServices, MemoryData}
          end, Nodes),

    case memory_quota:check_quotas(NodeInfos, Config, Quotas) of
        ok ->
            validator:return_value(quotas, Quotas, ValidatorState);
        {error, Error} ->
            {Key, Msg} = quota_error_msg(Error),
            validator:return_error(Key, Msg, ValidatorState)
    end.

quota_error_msg({total_quota_too_high, Node, TotalQuota, MaxAllowed}) ->
    Msg = io_lib:format("Total quota (~bMB) exceeds the maximum allowed quota (~bMB) on node ~p",
                        [TotalQuota, MaxAllowed, Node]),
    {'_', Msg};
quota_error_msg({service_quota_too_low, Service, Quota, MinAllowed}) ->
    Details = case Service of
                  kv ->
                      " (current total buckets quota, or at least 256MB)";
                  _ ->
                      ""
              end,

    ServiceStr = ns_cluster_membership:user_friendly_service_name(Service),
    Msg = io_lib:format("The ~s service quota (~bMB) "
                        "cannot be less than ~bMB~s.",
                        [ServiceStr, Quota, MinAllowed, Details]),
    {memory_quota:service_to_json_name(Service), Msg}.

handle_pool_settings_post(Req) ->
    do_handle_pool_settings_post_loop(Req, 10).

do_handle_pool_settings_post_loop(_, 0) ->
    erlang:error(exceeded_retries);
do_handle_pool_settings_post_loop(Req, RetriesLeft) ->
    try
        do_handle_pool_settings_post(Req)
    catch
        throw:retry_needed ->
            do_handle_pool_settings_post_loop(Req, RetriesLeft - 1)
    end.

do_handle_pool_settings_post(Req) ->
    Config = ns_config:get(),
    CompatVersion = cluster_compat_mode:get_compat_version(Config),

    validator:handle(
      do_handle_pool_settings_post_body(Req, Config, _),
      Req, form, pool_settings_post_validators(Config, CompatVersion)).

do_handle_pool_settings_post_body(Req, Config, Values) ->
    case lists:keyfind(quotas, 1, Values) of
        {_, Quotas} ->
            case memory_quota:set_quotas(Config, Quotas) of
                ok ->
                    ok;
                retry_needed ->
                    throw(retry_needed)
            end;
        false ->
            ok
    end,

    case lists:keyfind(clusterName, 1, Values) of
        {_, ClusterName} ->
            ok = ns_config:set(cluster_name, ClusterName);
        false ->
            ok
    end,

    do_audit_cluster_settings(Req),
    reply(Req, 200).

do_audit_cluster_settings(Req) ->
    %% this is obviously raceful, but since it's just audit...
    Quotas = lists:map(
               fun (Service) ->
                       {ok, Quota} = memory_quota:get_quota(Service),
                       {Service, Quota}
               end, memory_quota:aware_services(cluster_compat_mode:get_compat_version())),
    ClusterName = get_cluster_name(),
    ns_audit:cluster_settings(Req, Quotas, ClusterName).

handle_terse_cluster_info(Req) ->
    menelaus_util:assert_is_65(),
    case ns_config_auth:is_system_provisioned() of
        true ->
            RV = handle_terse_cluster_info_inner(Req),
            reply_json(Req, {struct, RV});
        false ->
            reply_json(Req, <<"unknown pool">>, 404)
    end.

handle_terse_cluster_info_inner(Req) ->
    LocalAddr = local_addr(Req),
    UUID = menelaus_web:get_uuid(),
    Orchestrator = case leader_registry:whereis_name(ns_orchestrator) of
                       undefined -> undefined;
                       RV -> node(RV)
                   end,

    NodeInfos = [begin
                     {struct, Props} =
                         menelaus_web_node:build_full_node_info(N, LocalAddr),
                     {N, Props}
                 end || N <- ns_node_disco:nodes_wanted()],

    Cfg = ns_config:get(),
    BCfgs = ns_bucket:get_buckets(Cfg),

    Buckets =
        extract_bucket_specific_data(
          BCfgs,
          fun(BName, BCfg) ->
                  RamQuota = ns_bucket:raw_ram_quota(BCfg),
                  CommonProps = [{ramQuota, RamQuota}],
                  case ns_bucket:bucket_type(BCfg) of
                      memcached ->
                          {BName, {struct, CommonProps}};
                      _ ->
                          NumReplicas = ns_bucket:num_replicas(BCfg),
                          EvictPolicy = ns_bucket:eviction_policy(BCfg),
                          Props = [{numReplicas, NumReplicas},
                                   {evictionPolicy, EvictPolicy}],
                          {BName, {struct, Props ++ CommonProps}}
                  end
          end),

    {Stats, StatsDesc} = get_stats_of_interest(Cfg, BCfgs),

    AFCfg = [{K, V} || {K, V} <- ns_config:search(Cfg, auto_failover_cfg, []),
                       lists:member(K, [enabled, timeout])],

    ARCfg = ns_config:search(Cfg, auto_reprovision_cfg, []),

    Nodes = [glean_node_details(BCfgs, NI, Stats) || NI <- NodeInfos],
    QuotaInfo = menelaus_web_node:build_memory_quota_info(Cfg),
    CCAState = ns_ssl_services_setup:client_cert_auth_state(Cfg),
    [V1 | V2] = lists:map(integer_to_list(_),
                          cluster_compat_mode:get_compat_version(Cfg)),

    [{clusterUUID, UUID},
     {autoFailover, {struct, AFCfg}},
     {autoReprovision, {struct, ARCfg}},
     {orchestrator, Orchestrator},
     {master, mb_master:master_node()},
     {isBalanced, ns_cluster_membership:is_balanced()},
     {quotaInfo, {struct, QuotaInfo}},
     {clusterCompatVersion, list_to_binary(V1 ++ "." ++ V2)},
     {clientCertAuthState, list_to_binary(CCAState)},
     {buckets, Buckets},
     {statsDescTable, StatsDesc},
     {nodes, Nodes}].

extract_bucket_specific_data(BucketCfgs, ExtractFun) ->
    BktsInfo =
        lists:foldl(
          fun({BName, BCfg}, Acc) ->
                  case ExtractFun(BName, BCfg) of
                      undefined ->
                          Acc;
                      Val ->
                          DisplayType = ns_bucket:display_type(BCfg),

                          case proplists:get_value(DisplayType, Acc) of
                              undefined ->
                                  [{DisplayType, {struct, [Val]}} | Acc];
                              {struct, Arr} ->
                                  NewVal = {DisplayType, {struct, [Val | Arr]}},
                                  lists:keyreplace(DisplayType, 1, Acc, NewVal)
                          end
                  end
          end, [], BucketCfgs),

    {struct, BktsInfo}.

get_stats_of_interest(Cfg, BCfgs) ->
    CommonStatsDesc = [{curr_connections,
                       <<"Total connections to this node">>}],
    MembaseStatsDesc =
        [{curr_items,
          <<"Total docs in active vBuckets on this node for this bucket">>},
         {vb_replica_curr_items,
          <<"Total docs in replica vBuckets on this node for this bucket">>},
         {vb_pending_curr_items,
          <<"Total docs in pending vBuckets on this node for this bucket">>},
         {<<"vb_active_resident_items_ratio">>,
          <<"Percentage of docs in active vBuckets in RAM on this node for "
            "this bucket">>},
         {vb_active_num,
          <<"Number of vBuckets in 'active' state on this node for this "
            "bucket">>},
         {vb_replica_num,
          <<"Number of vBuckets in 'replica' state on this node for this "
            "bucket">>},
         {vb_pending_num,
          <<"Number of vBuckets in 'pending' state on this node for this "
            "bucket">>},
         {ep_vb_total,
          <<"Number of vBuckets on this node for this bucket">>}],
    AllStatsDesc = MembaseStatsDesc ++ CommonStatsDesc,

    KVNodes = ns_cluster_membership:service_active_nodes(Cfg, kv),

    GetStatsFun =
        fun(BName, Node, StatKeys) ->
                RV = menelaus_stats:build_bucket_stats_ops_response([Node],
                                                                    BName,
                                                                    [],
                                                                    true),
                {struct, Op} = proplists:get_value(op, RV),
                {struct, Samples} = proplists:get_value(samples, Op),
                Timestamp = proplists:get_value(lastTStamp, Op),
                Stats = [begin
                             Val = case proplists:get_value(Key, Samples) of
                                       undefined ->
                                           undefined;
                                       Vals ->
                                           lists:last(Vals)
                                   end,
                             {Key, Val}
                         end || {Key, _DisplayText} <- StatKeys],
                {Node, {Stats, Timestamp}}
        end,

    GetBucketStatsFun =
        fun(Type, StatKeys) ->
                [begin
                     RV = [GetStatsFun(BName, Node, StatKeys) ||
                              Node <- KVNodes],
                     {BName, RV}
                 end || {BName, Props} <- BCfgs,
                        ns_bucket:bucket_type(Props) =:= Type]
        end,

    RV = GetBucketStatsFun(memcached, CommonStatsDesc) ++
        GetBucketStatsFun(membase, AllStatsDesc),

    {RV, {struct, AllStatsDesc}}.

glean_node_details(BucketCfgs, {Node, NodeInfo}, Stats) ->
    {struct, SysStats} = proplists:get_value(systemStats, NodeInfo),
    SwapTotal = proplists:get_value(swap_total, SysStats),
    SwapUsed = proplists:get_value(swap_used, SysStats),

    {struct, SC} = proplists:get_value(storage, NodeInfo),
    [{struct, SConf0}] = proplists:get_value(hdd, SC),
    SConf =
        lists:foldl(
          fun({Name, Key}, Acc) ->
                  Val = proplists:get_value(Key, SConf0),
                  [{Name, Val} | Acc]
          end, [], [{cbasDirs, cbas_dirs},
                    {indexPath, index_path},
                    {dbPath, path}]),

    BucketStats =
        extract_bucket_specific_data(
          BucketCfgs,
          fun(BName, _) ->
                  BStats = proplists:get_value(BName, Stats),
                  case proplists:get_value(Node, BStats) of
                      undefined ->
                          undefined;
                      {NodeSpecBStats, TS} ->
                          Props = [{stats, {struct, NodeSpecBStats}},
                                   {statsTimestamp, TS}],
                          {BName, {struct, Props}}
                  end
          end),

    KeysOfInterest = [hostname, version, os, uptime, cpuCount,
                      memoryTotal, memoryFree, clusterMembership,
                      status, services, nodeUUID],

    {struct,
     misc:proplist_keyfilter(lists:member(_, KeysOfInterest), NodeInfo) ++
         [{swapTotal, SwapTotal},
          {swapUsed, SwapUsed},
          {bucketStats, BucketStats},
          {storageConf, {struct, SConf}}]}.
