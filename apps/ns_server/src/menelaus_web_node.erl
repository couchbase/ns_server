%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

%% @doc implementation of node related REST API's

-module(menelaus_web_node).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-define(MAX_HOSTNAME_LENGTH, 1000).

-export([handle_node/2,
         build_full_node_info/1,
         build_full_node_info/2,
         build_full_node_info/3,
         build_memory_quota_info/1,
         build_nodes_info_fun/2,
         build_nodes_info/1,
         build_node_hostname/3,
         handle_throttle_capacity_get/1,
         handle_bucket_node_list/2,
         handle_bucket_node_info/3,
         find_node_hostname/2,
         find_node_hostname/3,
         handle_node_statuses/1,
         handle_node_rename/1,
         handle_node_altaddr_external/1,
         handle_node_altaddr_external_delete/1,
         handle_node_self_xdcr_ssl_ports/1,
         handle_node_settings_post/2,
         apply_node_settings/1,
         alternate_addresses_json/4,
         handle_setup_net_config/1,
         handle_change_external_listeners/2,
         handle_export_chronicle_snapshot/1,
         get_hostnames/2,
         get_hostnames/3,
         handle_node_init/1,
         get_context/3,
         get_context/4,
         get_config/1,
         get_stability/1,
         get_local_addr/1,
         get_snapshot/1,
         node_encryption_validators/0,
         node_init/2,
         node_init_validators/0]).

-import(menelaus_util,
        [local_addr/1,
         reply_json/2,
         reply_json/3,
         bin_concat_path/1,
         reply_not_found/1,
         reply/2]).

-record(ctx, {ns_config, snapshot, local_addr, include_cookie, stability}).

handle_node_init(Req) ->
    validator:handle(
      fun (Props) ->
          menelaus_util:survive_web_server_restart(
            fun () ->
                try
                    ok = node_init(Req, Props),
                    reply(Req, 200)
                catch
                    throw:{error, Code, Msg} ->
                       menelaus_util:global_error_exception(Code, Msg)
                end
            end)
      end, Req, form,
      node_init_validators() ++
      [validator:validate( %% Not putting this check in node_init_validators
                           %% 'cause we don't want to do it in /clusterInit
         fun (Hostname) ->
             case ns_cluster:is_host_allowed(Hostname) of
                 true -> ok;
                 false ->
                     Msg = io_lib:format(
                             "Can't use '~s' as a node name because "
                             "it is not allowed by the 'allowedHosts' setting",
                             [Hostname]),
                     {error, lists:flatten(Msg)}
             end
         end, hostname, _),
       validator:has_params(_), validator:unsupported(_)]).

node_init_validators() ->
    [validator:trimmed_string(dataPath, _),
     validator:trimmed_string(indexPath, _),
     validator:trimmed_string_multi_value(analyticsPath, _),
     validator:trimmed_string(eventingPath, _),
     validator:trimmed_string(javaHome, _),
     validator:validate(
       fun (_) ->
           case ns_cluster_membership:system_joinable() of
               true -> ok;
               false -> {error, "not supported when node is part of a cluster"}
           end
       end, afamily, _)] ++
    afamily_validators() ++
    [validator:validate(fun check_for_raw_addr/1, afamily, _),
     validator:default(afamily, unchanged, _),
     validator:validate(
       fun (_) ->
           case ns_cluster_membership:system_joinable() of
               true -> ok;
               false -> {error, "not supported when node is part of a cluster"}
           end
       end, hostname, _),
     validator:validate_relative(
       fun (Hostname, AFamily) ->
           AFamily2 = case AFamily of
                          unchanged -> misc:get_net_family();
                          _ -> AFamily
                      end,
           case misc:is_good_address(Hostname, AFamily2) of
               ok -> {value, Hostname};
               Error ->
                   Msg = ns_error_messages:address_check_error(Hostname, Error),
                   {error, Msg}
           end
       end, hostname, afamily, _)].

node_init(Req, Props) ->
    Settings =
        lists:flatmap(
          fun ({N1, N2}) ->
              [{N2, P} || P <- proplists:get_all_values(N1, Props)]
          end,
          [{dataPath, "path"}, {indexPath, "index_path"},
           {analyticsPath, "cbas_path"}, {eventingPath, "eventing_path"},
           {javaHome, "java_home"}]),

    case apply_node_settings(Settings) of
        not_changed -> ok;
        ok ->
            ns_audit:disk_storage_conf(Req, node(), Settings),
            ok;
        {error, Msgs} ->
            ErrorMsg = iolist_to_binary(lists:join(" ", Msgs)),
            throw({error, 400, ErrorMsg})
    end,

    case {proplists:get_value(afamily, Props),
          proplists:get_value(afamilyOnly, Props)} of
        {unchanged, undefined} -> ok;
        {AFamily, AFamilyOnly}  ->
            AFamilySettings =
                case AFamily of
                    unchanged -> [];
                    _ ->
                        Encryption = cb_dist:external_encryption(),
                        [{afamily, AFamily},
                         {externalListeners, [{AFamily, Encryption}]}]
                end,
            AFamilyOnlySettings =
                case AFamilyOnly of
                    undefined -> [];
                    _ -> [{afamilyOnly, AFamilyOnly}]
                end,
            CBDistCfg = AFamilySettings ++ AFamilyOnlySettings,
            case netconfig_updater:apply_config(CBDistCfg) of
                ok ->
                    %% Wait for web servers to restart
                    ns_config:sync_announcements(),
                    menelaus_event:sync(chronicle_compat_events:event_manager()),
                    cluster_compat_mode:is_enterprise() andalso
                        ns_ssl_services_setup:sync();
                {error, ErrorTerm} ->
                    Msg = iolist_to_binary(
                            netconfig_updater:format_error(ErrorTerm)),
                    throw({error, 400, Msg})
            end
    end,

    case proplists:get_value(hostname, Props) of
        undefined -> ok;
        Hostname ->
            case do_node_rename(Req, Hostname) of
                ok -> ok;
                {error, Msg2, Code} ->
                    throw({error, Code, Msg2})
            end
    end.

handle_node("self", Req) ->
    handle_node(node(), Req);
handle_node(S, Req) when is_list(S) ->
    handle_node(list_to_atom(S), Req);
handle_node(Node, Req) when is_atom(Node) ->
    case lists:member(Node, ns_node_disco:nodes_wanted()) of
        true ->
            Result = build_full_node_info(Req, Node),
            reply_json(Req, Result);
        false ->
            reply_json(Req, <<"Node is unknown to this cluster.">>, 404)
    end.

% S = [{ssd, []},
%      {hdd, [[{path, /some/nice/disk/path}, {quotaMb, 1234}, {state, ok}],
%            [{path, /another/good/disk/path}, {quotaMb, 5678}, {state, ok}]]}].
%
storage_conf_to_json(S) ->
    lists:map(
      fun ({StorageType, Locations}) -> % StorageType is ssd or hdd.
              {StorageType,
               lists:map(
                 fun (LocationPropList) ->
                         {lists:map(fun location_prop_to_json/1,
                                    LocationPropList)}
                 end,
                 Locations)}
      end,
      S).

location_prop_to_json({path, L}) -> {path, list_to_binary(L)};
location_prop_to_json({index_path, L}) -> {index_path, list_to_binary(L)};
location_prop_to_json({cbas_dirs, L}) ->
    {cbas_dirs, [list_to_binary(El) || El <- L]};
location_prop_to_json({eventing_path,L}) -> {eventing_path, list_to_binary(L)};
location_prop_to_json({java_home, undefined}) -> {java_home, <<>>};
location_prop_to_json({java_home, L}) -> {java_home, list_to_binary(L)};
location_prop_to_json({quotaMb, none}) -> {quotaMb, none};
location_prop_to_json({state, ok}) -> {state, ok};
location_prop_to_json(KV) -> KV.

build_full_node_info(Node) ->
    build_full_node_info(undefined, Node).

build_full_node_info(Req, Node) ->
    build_full_node_info(Req, Node, false).

build_full_node_info(Req, Node, IncludeOtpCookie) ->
    Ctx = get_context(Req, IncludeOtpCookie, unstable),
    Config = get_config(Ctx),
    Snapshot = get_snapshot(Ctx),
    {KV} = (build_nodes_info_fun(Ctx, false))(Node),
    NodeStatus = ns_doctor:get_node(Node),
    StorageConf =
        ns_storage_conf:storage_conf_from_node_status(Node, NodeStatus),
    R = {storage_conf_to_json(StorageConf)},
    DiskData = proplists:get_value(disk_data, NodeStatus, []),

    Fields = [{availableStorage,
               {[{hdd, [{[{path, list_to_binary(Path)},
                          {sizeKBytes, SizeKBytes},
                          {usagePercent, UsagePercent}]}
                        || {Path, SizeKBytes, UsagePercent} <- DiskData]}]}},
              {storageTotals,
               {[{Type, {PropList}}
                 || {Type, PropList} <-
                    ns_storage_conf:nodes_storage_info(
                      [Node], Config, Snapshot)]}},
              {storage, R}] ++ KV ++
        build_memory_quota_info(Config),
    {lists:filter(fun (X) -> X =/= undefined end,
                  Fields)}.

build_memory_quota_info(Config) ->
    lists:map(
      fun (Service) ->
              {ok, Quota} = memory_quota:get_quota(Config, Service),
              {memory_quota:service_to_json_name(Service), Quota}
      end, memory_quota:aware_services(Config)).

build_nodes_info(Ctx = #ctx{snapshot = Snapshot}) ->
    F = build_nodes_info_fun(Ctx, false),
    [F(N) || N <- ns_node_disco:nodes_wanted(Snapshot)].

%% builds health/warmup status of given node (w.r.t. given Bucket if
%% not undefined)
build_node_status(Node, Bucket, InfoNode, BucketsAll) ->
    case proplists:get_bool(down, InfoNode) of
        false ->
            ReadyBuckets = proplists:get_value(ready_buckets, InfoNode),
            NodeBucketNames = ns_bucket:node_bucket_names(Node, BucketsAll),
            case Bucket of
                undefined ->
                    case ordsets:is_subset(lists:sort(NodeBucketNames),
                                           lists:sort(ReadyBuckets)) of
                        true ->
                            <<"healthy">>;
                        false ->
                            <<"warmup">>
                    end;
                _ ->
                    case lists:member(Bucket, ReadyBuckets) of
                        true ->
                            <<"healthy">>;
                        false ->
                            case lists:member(Bucket, NodeBucketNames) of
                                true ->
                                    <<"warmup">>;
                                false ->
                                    <<"unhealthy">>
                            end
                    end
            end;
        true ->
            <<"unhealthy">>
    end.

fetch_buckets(all, Txn) ->
    ns_bucket:fetch_snapshot(all, Txn);
fetch_buckets(undefined, Txn) ->
    ns_bucket:fetch_snapshot(all, Txn, [uuid, props]);
fetch_buckets([_Bucket], {ns_config, _} = Txn) ->
    ns_bucket:fetch_snapshot(all, Txn);
fetch_buckets([Bucket], Txn) ->
    maps:merge(
      ns_bucket:fetch_snapshot(all, Txn, [uuid, props]),
      chronicle_compat:txn_get_many([collections:key(Bucket)], Txn)).

get_context(Req, IncludeOtpCookie, Stability) ->
    get_context(Req, undefined, IncludeOtpCookie, Stability).

get_context(Req, Buckets, IncludeOtpCookie, Stability) ->
    Config = ns_config:get(),
    Snapshot =
        chronicle_compat:get_snapshot(
          [fetch_buckets(Buckets, _),
           ns_cluster_membership:fetch_snapshot(_),
           chronicle_master:fetch_snapshot(_)], #{ns_config => Config}),

    LocalAddr = case Req of
                    undefined ->
                        misc:localhost();
                    {ip, IP} ->
                        IP;
                    _ ->
                        menelaus_util:local_addr(Req)
                end,

    #ctx{ns_config = Config,
         snapshot = Snapshot,
         local_addr = LocalAddr,
         include_cookie = IncludeOtpCookie,
         stability = Stability}.

get_stability(#ctx{stability = Stability}) ->
    Stability.

get_config(#ctx{ns_config = Config}) ->
    Config.

get_snapshot(#ctx{snapshot = Snapshot}) ->
    Snapshot.

get_local_addr(#ctx{local_addr = LocalAddr}) ->
    LocalAddr.

build_nodes_info_fun(Ctx, false) ->
    Fun = do_build_nodes_info_fun(Ctx, false),
    Fun(_, undefined);
build_nodes_info_fun(Ctx, true) ->
    do_build_nodes_info_fun(Ctx, true).

do_build_nodes_info_fun(#ctx{ns_config = Config,
                             snapshot = Snapshot,
                             include_cookie = IncludeOtpCookie,
                             stability = Stability,
                             local_addr = LocalAddr}, WithBucket) ->
    OtpCookie =
        case IncludeOtpCookie of
            true ->
                {otpCookie, erlang:get_cookie()};
            false ->
                []
        end,
    NodeStatuses = ns_doctor:get_nodes(),

    BucketsAll = ns_bucket:get_buckets(Snapshot),

    BucketPlacerInfoBuilder =
        case WithBucket of
            true ->
                fun (_) -> [] end;
            false ->
                bucket_placer:get_node_status_fun(Snapshot)
        end,

    LimitsAndBucketPlacerInfoBuilder =
        fun (WantENode) ->
                BucketPlacerJson = BucketPlacerInfoBuilder(WantENode),
                CapacityLimits =
                    [build_throttle_capacity_json(Config, WantENode) ||
                        config_profile:get_bool(enable_throttle_limits)],
                {PlacerLimits} =
                    proplists:get_value(limits, BucketPlacerJson, {[]}),
                case proplists:get_value(throttleCapacity, CapacityLimits) of
                    undefined ->
                        BucketPlacerJson;
                    _ ->
                        lists:keystore(limits, 1, BucketPlacerJson,
                                       {limits, {PlacerLimits ++
                                                     CapacityLimits}})
                end
        end,

    PerNodeStorageBackendBuilder =
        case WithBucket of
            true ->
                fun (_Node, undefined) ->
                        [];
                    (Node, BucketName) ->
                        {ok, BucketConfig} =
                            ns_bucket:get_bucket(BucketName, Snapshot),
                        build_storage_backend(Node, BucketConfig)
                end;
            false ->
                fun (_, _) -> [] end
        end,

    PerNodeEvictionPolicyBuilder =
        case WithBucket of
            true ->
                fun (_Node, undefined) ->
                        [];
                    (Node, BucketName) ->
                        {ok, BucketConfig} =
                            ns_bucket:get_bucket(BucketName, Snapshot),
                        build_eviction_policy(Node, BucketConfig)
                end;
            false ->
                fun (_, _) -> [] end
        end,

    fun(WantENode, Bucket) ->
            InfoNode = ns_doctor:get_node(WantENode, NodeStatuses),
            StableInfo =
                [{clusterMembership,
                  ns_cluster_membership:get_cluster_membership(
                    WantENode, Snapshot)},
                 {recoveryType,
                  ns_cluster_membership:get_recovery_type(Snapshot, WantENode)},
                 {status, build_node_status(WantENode, Bucket, InfoNode,
                                            BucketsAll)},
                 {otpNode, WantENode},
                 build_node_info(Config, Snapshot, WantENode, InfoNode,
                                 LocalAddr),
                 OtpCookie,
                 case Bucket of
                     undefined ->
                         build_couch_api_base(WantENode, LocalAddr);
                     _ ->
                         build_replication_info(Bucket, WantENode, NodeStatuses,
                                                Snapshot)
                 end,
                 build_failover_status(Snapshot, WantENode),
                 LimitsAndBucketPlacerInfoBuilder(WantENode)] ++
                 build_encryption_at_rest_info(Bucket, Snapshot, InfoNode) ++
                   PerNodeStorageBackendBuilder(WantENode, Bucket) ++
                   PerNodeEvictionPolicyBuilder(WantENode, Bucket),

            NodeHash = erlang:phash2(StableInfo),

            {lists:flatten([StableInfo,
                           [{nodeHash, NodeHash}],
                           case Stability of
                               stable ->
                                   [];
                               unstable ->
                                   build_extra_node_info(Config, WantENode,
                                                         InfoNode)
                           end])}
    end.

build_encryption_at_rest_info(Bucket, Snapshot, NsDoctorInfo) ->
    NodeSupportsEncryptionAtRest =
        cb_cluster_secrets:node_supports_encryption_at_rest(NsDoctorInfo),
    case NodeSupportsEncryptionAtRest of
        no_info -> [];
        false -> [];
        true ->
            AllInfos = proplists:get_value(encryption_at_rest_info,
                                           NsDoctorInfo, []),
            CfgInfo = proplists:get_value(config_encryption, AllInfos, []),
            LogInfo = proplists:get_value(log_encryption, AllInfos, []),
            AuditInfo = proplists:get_value(audit_encryption, AllInfos, []),

            Format = fun menelaus_web_encr_at_rest:format_encr_at_rest_info/1,

            NodeInfo = {[{configuration, Format(CfgInfo)},
                         {logs, Format(LogInfo)},
                         {audits, Format(AuditInfo)}]},

            [{encryptionAtRestInfo, NodeInfo}]
            ++
            case Bucket of
                undefined -> [];
                _ ->
                    BucketUUID = ns_bucket:uuid(Bucket, Snapshot),
                    BucketInfo = proplists:get_value(
                                   {bucket_encryption, BucketUUID},
                                   AllInfos, []),
                    [{bucketEncryptionAtRestInfo, Format(BucketInfo)}]
            end
    end.

build_storage_backend(Node, BucketConfig) ->
    NodeStorageBackend = ns_bucket:node_storage_mode_override(
                           Node, BucketConfig),
        case NodeStorageBackend of
            undefined ->
                [];
            _ ->
                [{storageBackend, NodeStorageBackend}]
        end.

build_eviction_policy(Node, BucketConfig) ->
    case ns_config:read_key_fast(allow_online_eviction_policy_change, false) of
        true ->
            NodeEvictionPolicy = ns_bucket:node_eviction_policy_override(
                                   Node, BucketConfig),
            case NodeEvictionPolicy of
                undefined ->
                    [];
                _ ->
                    EvictionPolicyBinary =
                        case NodeEvictionPolicy of
                            value_only -> <<"valueOnly">>;
                            full_eviction -> <<"fullEviction">>;
                            no_eviction -> <<"noEviction">>;
                            nru_eviction -> <<"nruEviction">>
                        end,
                    [{evictionPolicy, EvictionPolicyBinary}]
            end;
        false ->
            []
    end.

build_failover_status(Snapshot, Node) ->
    PrevFailoverNodes = chronicle_master:get_prev_failover_nodes(Snapshot),
    case lists:member(Node, PrevFailoverNodes) of
        true ->
            {failoverStatus, unfinished};
        false ->
            []
    end.

build_couch_api_base(WantENode, LocalAddr) ->
    [{Key, URL} || {Key, Node} <- ?COUCHDB_ENABLED([{couchApiBase, WantENode},
                                                    {couchApiBaseHTTPS,
                                                     {ssl, WantENode}}], []),
                   URL <- [capi_utils:capi_url_bin(Node, <<"/">>, LocalAddr)],
                   URL =/= undefined].

build_replication_info(Bucket, WantENode, NodeStatuses, Snapshot) ->
    {replication,
     case ns_bucket:get_bucket(Bucket, Snapshot) of
         not_present -> 0.0;
         {ok, BucketConfig} ->
             failover_safeness_level:extract_replication_uptodateness(
               Bucket, BucketConfig, WantENode, NodeStatuses)
     end}.

build_extra_node_info(Config, Node, InfoNode) ->

    {UpSecs, {MemoryTotalErlang, MemoryAllocedErlang, _}} =
        {proplists:get_value(wall_clock, InfoNode, 0),
         proplists:get_value(memory_data, InfoNode,
                             {0, 0, undefined})},

    SystemStats = proplists:get_value(system_stats, InfoNode, []),
    SigarMemTotal = proplists:get_value(mem_total, SystemStats),
    SigarMemFree = proplists:get_value(mem_free, SystemStats),
    {MemoryTotal, MemoryFree} =
        case SigarMemTotal =:= undefined orelse
             SigarMemFree =:= undefined orelse SigarMemTotal =:= 0 of
            true ->
                {MemoryTotalErlang, MemoryTotalErlang - MemoryAllocedErlang};
            _ ->
                {SigarMemTotal, SigarMemFree}
        end,

    NodesBucketMemoryTotal = case ns_config:search_node_prop(Node,
                                                             Config,
                                                             memcached,
                                                             max_size) of
                                 X when is_integer(X) -> X;
                                 undefined -> (MemoryTotal * 4) div (5 * ?MIB)
                             end,

    NodesBucketMemoryAllocated = NodesBucketMemoryTotal,
    [{systemStats, {proplists:get_value(system_stats, InfoNode, [])}},
     {interestingStats,
      {proplists:get_value(interesting_stats, InfoNode, [])}},
     %% TODO: deprecate this in API (we need 'stable' "startupTStamp"
     %% first)
     {uptime, list_to_binary(integer_to_list(UpSecs))},
     %% TODO: deprecate this in API
     {memoryTotal, erlang:trunc(MemoryTotal)},
     %% TODO: deprecate this in API
     {memoryFree, erlang:trunc(MemoryFree)},
     %% TODO: deprecate this in API
     {mcdMemoryReserved, erlang:trunc(NodesBucketMemoryTotal)},
     %% TODO: deprecate this in API
     {mcdMemoryAllocated, erlang:trunc(NodesBucketMemoryAllocated)}].

build_node_hostname(Config, Node, LocalAddr) ->
    build_node_hostname(Config, Node, LocalAddr, []).

build_node_hostname(Config, Node, LocalAddr, Options) ->
    H = misc:extract_node_address(Node),
    Host = case misc:is_localhost(H) of
               true  -> LocalAddr;
               false -> H
           end,
    PortName = proplists:get_value(port, Options, rest_port),
    Port = case service_ports:get_port(PortName, Config, Node) of
               undefined -> error(no_port);
               P -> P
           end,
    list_to_binary(misc:join_host_port(Host, Port)).

build_throttle_capacity_json(Config, Node) ->
    {throttleCapacity,
     {lists:map(
        fun({Param, Key, Default, _, _}) ->
                {Param, ns_config:search_node(Node, Config, Key, Default)}
        end, menelaus_web_settings:get_throttle_capacity_attributes())}}.

handle_throttle_capacity_get(Req) ->
    menelaus_util:assert_config_profile_flag(enable_throttle_limits),
    reply_json(Req, {[build_throttle_capacity_json(ns_config:get(), node())
                      || config_profile:get_bool(enable_throttle_limits)]}).

alternate_addresses_json(Node, Config, Snapshot, WantedPorts) ->
    {ExtHostname, ExtPorts} =
        service_ports:get_external_host_and_ports(
          Node, Config, Snapshot, WantedPorts),
    External = construct_ext_json(ExtHostname, ExtPorts),
    [{alternateAddresses, {External}} || External =/= []].

server_groups_json(ServerGroup) ->
    [{serverGroup, ServerGroup} || cluster_compat_mode:is_enterprise()].

construct_ext_json(undefined, _Ports) ->
    [];
construct_ext_json(Hostname, []) ->
    [{external, {[{hostname, list_to_binary(Hostname)}]}}];
construct_ext_json(Hostname, Ports) ->
    [{external, {[{hostname, list_to_binary(Hostname)},
                  {ports, {Ports}}]}}].

build_node_info(Config, Snapshot, WantENode, InfoNode, LocalAddr) ->
    Versions = proplists:get_value(version, InfoNode, []),
    Version = proplists:get_value(ns_server, Versions, "unknown"),
    OS = proplists:get_value(system_arch, InfoNode, "unknown"),
    CpuCount = proplists:get_value(cpu_count, InfoNode, 0),
    NodeUUID = ns_config:search_node_with_default(WantENode, Config, uuid,
                                                  undefined),
    ConfiguredHostname =
      misc:join_host_port(
        misc:extract_node_address(WantENode),
        service_ports:get_port(rest_port, Config, WantENode)),

    PortKeys =
        [{memcached_port, direct},
         %% this is used by xdcr over ssl since 2.5.0
         {ssl_rest_port, httpsMgmt}] ++
        ?COUCHDB_ENABLED([{ssl_capi_port, httpsCAPI}] , []),

    PortsKV = lists:filtermap(
                fun ({Key, JKey}) ->
                        case service_ports:get_port(Key, Config, WantENode) of
                            undefined ->
                                false;
                            Value ->
                                {true, {JKey, Value}}
                        end
                end, PortKeys),

    ShortNode = misc:node_name_short(node()),
    DistPorts = [{distTCP, cb_epmd:port_for_node(inet_tcp_dist, ShortNode)},
                 {distTLS, cb_epmd:port_for_node(inet_tls_dist, ShortNode)}],

    WantedPorts =
        [memcached_port, ssl_rest_port, rest_port] ++
        ?COUCHDB_ENABLED([ssl_capi_port, capi_port], []),

    AFamily = ns_config:search_node_with_default(WantENode, Config,
                                                 address_family, undefined),
    AFamilyOnly = misc:get_afamily_only(Config, WantENode),

    NEncryption = misc:is_node_encryption_enabled(Config, WantENode),
    N2NClientCert = cb_dist:client_cert_verification(),
    Listeners = case ns_config:search_node_with_default(WantENode, Config,
                                                        erl_external_listeners,
                                                        undefined) of
                    undefined ->
                        undefined;
                    L ->
                        [{[{afamily, AF}, {nodeEncryption, E}]} || {AF, E} <- L]
                end,
    ServerGroup =
        ns_cluster_membership:get_node_server_group(WantENode, Snapshot),
    ProdCompatVersion = cluster_compat_mode:current_prod_compat_version(),
    RV = [{hostname, build_node_hostname(Config, WantENode, LocalAddr)},
          {nodeUUID, NodeUUID},
          {clusterCompatibility,
           cluster_compat_mode:effective_cluster_compat_version()},
          {prod, list_to_binary(cluster_compat_mode:prod())},
          {prodName, list_to_binary(cluster_compat_mode:prod_name())},
          {version, list_to_binary(Version)},
          {os, list_to_binary(OS)},
          {cpuCount, CpuCount},
          {ports, {PortsKV ++ DistPorts}},
          {services, ns_cluster_membership:node_services(Snapshot, WantENode)},
          {nodeEncryption, NEncryption},
          {nodeEncryptionClientCertVerification, N2NClientCert},
          {addressFamilyOnly, AFamilyOnly},
          {configuredHostname, list_to_binary(ConfiguredHostname)}
         ] ++ [{addressFamily, AFamily} || AFamily =/= undefined]
        ++ [{externalListeners, Listeners} || Listeners =/= undefined]
        ++ [{prodCompatVersion, ProdCompatVersion} ||
               ProdCompatVersion =/= undefined]
        ++ alternate_addresses_json(WantENode, Config, Snapshot,
                                    WantedPorts)
        ++ server_groups_json(ServerGroup),

    case WantENode =:= node() of
        true ->
            [{thisNode, true} | RV];
        _ -> RV
    end.

get_hostnames(Req, Arg) ->
    get_hostnames(Req, Arg, []).

get_hostnames(Req, NodeStatus, Options) when is_atom(NodeStatus) ->
    Snapshot = ns_cluster_membership:get_snapshot(),
    Nodes = ns_cluster_membership:get_nodes_with_status(Snapshot, NodeStatus),
    get_hostnames(Req, Nodes, Options);
get_hostnames(Req, Nodes, Options) when is_list(Nodes) ->
    Config = ns_config:get(),
    LocalAddr = local_addr(Req),
    lists:filtermap(
      fun (N) ->
          try build_node_hostname(Config, N, LocalAddr, Options) of
              NodeHostname -> {true, {N, NodeHostname}}
          catch
              %% Might happen when the node is CE and we are searching by
              %% ssl port
              error:no_port -> false
          end
      end, Nodes).

%% Node list
%% GET /pools/default/buckets/{Id}/nodes
%%
%% Provides a list of nodes for a specific bucket (generally all nodes) with
%% links to stats for that bucket
handle_bucket_node_list(BucketName, Req) ->
    %% NOTE: since 4.0 release we're listing all active nodes as
    %% part of our approach for dealing with query stats
    NHs = get_hostnames(Req, active),
    Servers =
        [{[{hostname, Hostname},
           {uri, bin_concat_path(["pools", "default", "buckets", BucketName,
                                  "nodes", Hostname])},
           {stats, {[{uri,
                      bin_concat_path(
                        ["pools", "default", "buckets", BucketName,
                         "nodes", Hostname, "stats"])}]}}]}
         || {_, Hostname} <- NHs],
    reply_json(Req, {[{servers, Servers}]}).

normalize_hostport(HostPortStr, Req) ->
    LocalAddr = local_addr(Req),
    {HostnameStr, PortStr} = misc:split_host_port(HostPortStr, "8091"),
    HostnameStr2 = case misc:is_localhost(HostnameStr) of
                       true  -> LocalAddr;
                       false -> HostnameStr
                   end,
    misc:join_host_port(HostnameStr2, PortStr).

find_node_hostname(HostPortStr, Req) ->
    find_node_hostname(HostPortStr, Req, active).

find_node_hostname(HostPortStr, Req, NodeStatus) ->
    try normalize_hostport(HostPortStr, Req) of
        Normalized ->
            HostPortBin = list_to_binary(Normalized),
            NHs = get_hostnames(Req, NodeStatus) ++
                  get_hostnames(Req, NodeStatus, [{port, ssl_rest_port}]),
            case [N || {N, CandidateHostPort} <- NHs,
                       CandidateHostPort =:= HostPortBin] of
                [] ->
                    {error, not_found};
                [Node] ->
                    {ok, Node}
            end
    catch
        throw:{error, Reason} -> {error, {invalid_node, Reason}}
    end.

%% Per-Node Stats URL information
%% GET /pools/default/buckets/{Id}/nodes/{NodeId}
%%
%% Provides node hostname and links to the default bucket and node-specific
%% stats for the default bucket
%%
%% TODO: consider what else might be of value here
handle_bucket_node_info(BucketName, Hostname, Req) ->
    case find_node_hostname(Hostname, Req) of
        {error, not_found} ->
            reply_not_found(Req);
        {error, {invalid_node, Reason}} ->
            menelaus_util:reply_text(Req, Reason, 400);
        _ ->
            BucketURI = bin_concat_path(["pools", "default", "buckets",
                                         BucketName]),
            NodeStatsURI = bin_concat_path(
                             ["pools", "default", "buckets", BucketName,
                              "nodes", Hostname, "stats"]),
            reply_json(Req,
                       {[{hostname, list_to_binary(Hostname)},
                         {bucket, {[{uri, BucketURI}]}},
                         {stats, {[{uri, NodeStatsURI}]}}]})
    end.

average_failover_safenesses(Node, NodeInfos, BucketsAll) ->
    average_failover_safenesses_rec(Node, NodeInfos, BucketsAll, 0, 0).

average_failover_safenesses_rec(_Node, _NodeInfos, [], Sum, Count) ->
    try Sum / Count
    catch error:badarith -> 1.0
    end;
average_failover_safenesses_rec(Node, NodeInfos,
                                [{BucketName, BucketConfig} | RestBuckets],
                                Sum, Count) ->
    Level = failover_safeness_level:extract_replication_uptodateness(
              BucketName, BucketConfig, Node, NodeInfos),
    average_failover_safenesses_rec(Node, NodeInfos, RestBuckets, Sum + Level,
                                    Count + 1).

%% this serves fresh nodes replication and health status
handle_node_statuses(Req) ->
    OldStatuses = ns_doctor:get_nodes(),
    #ctx{ns_config = Config,
         local_addr = LocalAddr,
         snapshot = Snapshot} = get_context(Req, false, stable),
    BucketsAll = ns_bucket:get_buckets(Snapshot),
    FreshStatuses = ns_heart:grab_fresh_failover_safeness_infos(
                      ns_bucket:get_bucket_names(Snapshot)),
    NodeStatuses =
        lists:map(
          fun (N) ->
                  InfoNode = ns_doctor:get_node(N, FreshStatuses),
                  Dataless =
                      not lists:member(
                            kv,
                            ns_cluster_membership:node_services(Snapshot, N)),
                  V = case proplists:get_bool(down, InfoNode) of
                          true ->
                              {[{status, unhealthy},
                                {otpNode, N},
                                {dataless, Dataless},
                                {replication,
                                 average_failover_safenesses(
                                   N, OldStatuses, BucketsAll)}]};
                          false ->
                              {[{status, healthy},
                                {gracefulFailoverPossible,
                                 graceful_failover_possible(N, BucketsAll)},
                                {otpNode, N},
                                {dataless, Dataless},
                                {replication, average_failover_safenesses(
                                                N, FreshStatuses, BucketsAll)}]}
                      end,
                  {build_node_hostname(Config, N, LocalAddr), V}
          end, ns_node_disco:nodes_wanted(Snapshot)),
    reply_json(Req, {NodeStatuses}, 200).

graceful_failover_possible(Node, Buckets) ->
    case ns_rebalancer:check_graceful_failover_possible([Node], Buckets) of
        true -> true;
        {false, _} -> false
    end.

handle_node_rename(Req) ->
    Params = mochiweb_request:parse_post(Req),

    Reply =
        case proplists:get_value("hostname", Params) of
            undefined -> {error, <<"The name cannot be empty">>, 400};
            Hostname ->
                case ns_cluster:is_host_allowed(Hostname) of
                    true -> do_node_rename(Req, Hostname);
                    false -> {error, <<"Not allowed">>, 400}
                end
        end,

    case Reply of
        ok ->
            reply(Req, 200);
        {error, Error, Status} ->
            reply_json(Req, [Error], Status)
    end.

do_node_rename(Req, Hostname) ->
    case ns_cluster:change_address(Hostname) of
        ok ->
            ns_audit:rename_node(Req, node(), Hostname),
            ok;
        not_renamed ->
            ok;
        not_self_started ->
            Msg = <<"Could not rename the node because name was "
                    "fixed at server start-up.">>,
            ns_audit:access_forbidden(Req),
            ns_server_stats:notify_counter(<<"rest_request_access_forbidden">>),
            {error, Msg, 403};
        {address_save_failed, E} ->
            Msg = io_lib:format("Could not save address after "
                                "rename: ~p", [E]),
            {error, iolist_to_binary(Msg), 500};
        already_part_of_cluster ->
            Msg = <<"Renaming is disallowed for nodes that are "
                    "already part of a cluster">>,
            {error, Msg, 400};
        {Type, _} = Error when Type == cannot_resolve;
                               Type == cannot_listen;
                               Type == address_not_allowed ->
            Msg = ns_error_messages:address_check_error(Hostname, Error),
            {error, Msg, 400}
    end.

handle_node_self_xdcr_ssl_ports(Req) ->
    case cluster_compat_mode:tls_supported() of
        false ->
            ns_audit:access_forbidden(Req),
            ns_server_stats:notify_counter(<<"rest_request_access_forbidden">>),
            reply_json(Req, [], 403);
        true ->
            Snapshot = ns_cluster_membership:get_snapshot(),
            Ports = [{httpsMgmt, service_ports:get_port(ssl_rest_port)}] ++
                alternate_addresses_json(node(), ns_config:latest(), Snapshot,
                                         [ssl_rest_port] ++
                                             ?COUCHDB_ENABLED([ssl_capi_port], [])),
            reply_json(Req, {Ports})
    end.

validate_path({java_home, JavaHome}, _) ->
    validate_java_home(JavaHome);
validate_path(PathTuple, DbPath) ->
    validate_ix_cbas_path(PathTuple, DbPath).

validate_java_home([]) ->
    false;
validate_java_home(not_changed) ->
    false;
validate_java_home(JavaHome) ->
    case misc:run_external_tool(
           path_config:component_path(bin, "cbas"),
           ["-validateJavaHome", "-javaHome", JavaHome], []) of
        {0, _} ->
            false;
        {Code, Output} ->
            ?log_debug("Java home validation of ~p failed with code=~p, ~p",
                       [JavaHome, Code, Output]),
            {true, iolist_to_binary(
                     io_lib:format(
                       "'~s' has incorrect version of java or is not a "
                       "java home directory", [JavaHome]))}
    end.

validate_ix_cbas_path({_Param, DbPath}, DbPath) ->
    false;
validate_ix_cbas_path({Param, Path}, DbPath) ->
    PathTokens = filename:split(Path),
    DbPathTokens = filename:split(DbPath),
    case lists:prefix(DbPathTokens, PathTokens) of
        true ->
            {true, iolist_to_binary(
                      io_lib:format("'~p' (~s) must not be a sub-directory "
                                    "of 'data_path' (~s)",
                                    [Param, Path, DbPath]))};
        false -> false
    end.

validate_and_expand_path(java_home, []) ->
    {ok, {java_home, []}};
validate_and_expand_path(java_home, not_changed) ->
    {ok, {java_home, not_changed}};
validate_and_expand_path(Field, []) ->
    {error, iolist_to_binary(
              io_lib:format("~p cannot contain empty string", [Field]))};
validate_and_expand_path(Field, Path) ->
    case misc:is_absolute_path(Path) of
        true ->
            case misc:realpath(Path, "/") of
                {ok, RP} ->
                    {ok, {Field, RP}};
                {error, _, ExpandedSubPath, RemPathComps, {error, enoent}} ->
                    %% We get here if a sub-directory hierarchy is not present
                    %% in the path. We create a path using the expanded sub-path
                    %% and the remaining path components.
                    NewPath = filename:join([ExpandedSubPath | RemPathComps]),
                    {ok, {Field, NewPath}};
                Err ->
                    {error,
                     iolist_to_binary(
                      io_lib:format("Path expansion failed for ~p: ~p",
                                    [Field, Err]))}
            end;
        false ->
            {error, iolist_to_binary(
                      io_lib:format("An absolute path is required for ~p",
                                    [Field]))}
    end.

-spec handle_node_settings_post(string() | atom(), any()) -> no_return().
handle_node_settings_post("self", Req) ->
    handle_node_settings_post(node(), Req);
handle_node_settings_post(NodeStr, Req) when is_list(NodeStr) ->
    try list_to_existing_atom(NodeStr) of
        Node -> handle_node_settings_post(Node, Req)
    catch
        error:badarg -> menelaus_util:reply_not_found(Req)
    end;
handle_node_settings_post(Node, Req) when is_atom(Node) ->
    Params = mochiweb_request:parse_post(Req),

    case lists:member(Node, ns_node_disco:nodes_actual())  of
        true ->
            Apply = fun () ->
                        case remote_api:apply_node_settings(Node, Params) of
                            not_changed ->
                                reply(Req, 200);
                            ok  ->
                                ns_audit:disk_storage_conf(Req, Node, Params),
                                reply(Req, 200);
                            {error, Msgs} ->
                                reply_json(Req, Msgs, 400)
                        end
                    end,
            case Node == node() of
                true -> menelaus_util:survive_web_server_restart(Apply);
                false -> Apply()
            end;
        false ->
            case lists:member(Node, ns_node_disco:nodes_wanted()) of
                true ->
                    menelaus_util:reply_text(Req, "Node is not available.",
                                             503);
                false ->
                    menelaus_util:reply_not_found(Req)
            end
    end.

-spec apply_node_settings(Params :: [{Key :: string(), Value :: term()}]) ->
        ok | not_changed | {error, [Msg :: binary()]}.
apply_node_settings(Params) ->
    try
        Paths = validate_settings_paths(extract_settings_paths(Params)),

        DbPath = proplists:get_value(path, Paths),
        IxPath = proplists:get_value(index_path, Paths),
        CBASDirs = proplists:get_all_values(cbas_path, Paths),
        JavaHome = proplists:get_value(java_home, Paths),
        EvPath = proplists:get_value(eventing_path, Paths),

        RV1 =
            case ns_storage_conf:setup_disk_storage_conf(DbPath, IxPath,
                                                         CBASDirs, EvPath) of
                restart ->
                    %% performing required restart from
                    %% successfull path change
                    {ok, _} = ns_server_cluster_sup:restart_ns_server(),
                    ok;
                Other ->
                    Other
            end,

        RV2 =
            case RV1 of
                {errors, _} ->
                    RV1;
                _ ->
                    {RV1, ns_storage_conf:update_java_home(JavaHome)}
            end,

        case RV2 of
            {not_changed, not_changed} ->
                not_changed;
            {errors, Errors} ->
                {error, Errors};
            _ ->
                ok
        end
    catch
        throw:{error, ErrorMsgs} ->
            {error, [iolist_to_binary(M) || M <- ErrorMsgs]}
    end.

extract_settings_paths(Params) ->
    case lists:foldl(
           fun (Key, Acc) ->
                   proplists:delete(Key, Acc)
           end, Params, ["cbas_path", "path", "index_path", "eventing_path",
                         "java_home"]) of
        [] ->
            ok;
        Extras ->
            Keys = [list_to_atom(Key) || {Key, _Value} <- Extras],
            Msg = io_lib:format("Unknown keys were specified: ~p",
                                [Keys]),
            throw({error, [Msg]})
    end,

    {ok, DefaultDbPath} = ns_storage_conf:this_node_dbdir(),
    {ok, DefaultIxPath} = ns_storage_conf:this_node_ixdir(),
    {ok, DefaultEvPath} = ns_storage_conf:this_node_evdir(),

    CBASDirsToSet =
        case [Dir || {"cbas_path", Dir} <- Params] of
            [] -> ns_storage_conf:this_node_cbas_dirs();
            Dirs -> Dirs
        end,

    [{path, proplists:get_value("path", Params, DefaultDbPath)},
     {index_path, proplists:get_value("index_path", Params, DefaultIxPath)},
     {eventing_path, proplists:get_value("eventing_path", Params,
                                         DefaultEvPath)},
     {java_home, proplists:get_value("java_home", Params, not_changed)}] ++
        [{cbas_path, P} || P <- CBASDirsToSet].

validate_settings_paths(Paths) ->
    ValidateRes = [validate_and_expand_path(K, V) || {K, V} <- Paths],
    ValidationErrors = [E || {error, E} <- ValidateRes],

    ValidationErrors == [] orelse throw({error, ValidationErrors}),

    ResPaths = [P || {ok, P} <- ValidateRes],

    DbPath = proplists:get_value(path, ResPaths),
    ValidationErrors1 =
        lists:filtermap(validate_path(_, DbPath), ResPaths),

    ValidationErrors1 == [] orelse throw({error, ValidationErrors1}),

    ResPaths.

parse_validate_ports(Params) ->
    lists:foldl(
      fun ({RestName, Value}, Acc) ->
              try
                  PortKey =
                      case service_ports:find_by_rest_name(RestName) of
                          undefined ->
                              throw({error, [<<"No such port.">>]});
                          P ->
                              P
                      end,
                  Port = menelaus_util:parse_validate_port_number(Value),
                  [{PortKey, Port} | Acc]
              catch
                  throw:{error, [Msg]} ->
                      menelaus_util:web_exception(
                        400, io_lib:format("Invalid Port ~p : ~s",
                                           [RestName, Msg]))
              end
      end, [], Params).

parse_validate_hostname(undefined) ->
    menelaus_util:web_exception(400, "hostname should be specified");
parse_validate_hostname(Hostname) ->
    HN = string:trim(Hostname),
    case length(HN) =< ?MAX_HOSTNAME_LENGTH andalso
         misc:is_valid_hostname(HN) of
        true ->
            HN;
        false ->
            menelaus_util:web_exception(
              400, io_lib:format(
                     "Invalid hostname specified. "
                     "Hostname should be ~p characters or less and "
                     "either a valid IPv4, IPv6, or FQDN",
                     [?MAX_HOSTNAME_LENGTH]))
    end.

value_frequencies([], Counts) ->
    maps:to_list(Counts);
value_frequencies([H|T], Counts) ->
    Inc = fun(Value) -> Value + 1 end,
    NewCounts = maps:update_with(H, Inc, 1, Counts),
    value_frequencies(T, NewCounts).

check_duplicate_ports(Ports) ->
    PortValues = [V || {_, V} <- Ports],
    Counts = value_frequencies(PortValues, #{}),
    DuplicatePorts = [A || {A, B} <- Counts, B > 1],
    [A || {A, B} <- Ports, lists:member(B, DuplicatePorts)].

-ifdef(TEST).
check_duplicate_ports_test() ->
    ?assertEqual([], check_duplicate_ports([])),
    ?assertEqual([rest_port, query_port],
                 check_duplicate_ports(
                   [{rest_port, 1050}, {capi_port, 2000}, {query_port, 1050},
                    {fts_http_port, 5000}, {cbas_http_port, 6000}])).
-endif.

get_rest_names(Keynames) ->
    [service_ports:find_rest_name_by_port_key(P) || P <- Keynames].

%% The below port validations are performed:
%%  - Provisioned: Verify if all ports being setup for "external" have their
%%    particular service enabled on the node.
%%  - Not Provisioned: If the node is not provisioned we allow modifying the
%%    external ports for any service, because we don't know which ones will
%%    eventually be selected.
parse_validate_external_params(Params) ->
    Hostname = parse_validate_hostname(proplists:get_value("hostname", Params)),
    Ports = parse_validate_ports(proplists:delete("hostname", Params)),
    DuplicateKeynames = check_duplicate_ports(Ports),
    maybe
        [] ?= DuplicateKeynames,
        ValidResponse = [{external, [{hostname, Hostname}, {ports, Ports}]}],
        case ns_config_auth:is_system_provisioned() of
            true ->
                Services = [rest | ns_cluster_membership:node_services(node())],
                ServicePorts = service_ports:services_port_keys(Services),
                {_Allowed, NotAllowed} =
                    lists:partition(lists:member(_, ServicePorts),
                                    [V || {V, _} <- Ports]),
                case NotAllowed of
                    [] ->
                        ValidResponse;
                    _ ->
                        NAPorts = get_rest_names(NotAllowed),
                        Msg = io_lib:format(
                                "Cannot set external ports ~p as "
                                "services are unavailable on the node.",
                                [NAPorts]),
                        {error, Msg}
                end;
            false ->
                ValidResponse
        end
    else
        [_|_] ->
            Printing = get_rest_names(DuplicateKeynames),
            FormatPrint = lists:join(" ", Printing),
            {error, io_lib:format("Some ports have the same number: ~s",
                                  [FormatPrint])}
    end.

%% This replaces any existing alternate_addresses config of this node.
%% For now this is fine because external is only element in alternate_addresses.
handle_node_altaddr_external(Req) ->
    Params = mochiweb_request:parse_post(Req),
    case parse_validate_external_params(Params) of
        {error, M} ->
            menelaus_util:reply_text(Req, M, 400);
        External ->
            ns_config:set({node, node(), alternate_addresses}, External),
            menelaus_util:reply(Req, 200)
    end.

%% Delete alternate_addresses as external is the only element in
%% alternate_addresses.
handle_node_altaddr_external_delete(Req) ->
    ns_config:delete({node, node(), alternate_addresses}),
    menelaus_util:reply(Req, 200).

is_raw_addr_node(Node) ->
    {_, Host} = misc:node_name_host(Node),
    misc:is_raw_ip(Host).

check_for_raw_addr(AFamily) ->
    CurAFamily = cb_dist:address_family(),
    %% Fail the request if the cluster is provisioned and has any node
    %% setup with raw IP address.
    case AFamily of
        CurAFamily ->
            ok;
        _ ->
            RawAddrNodes = lists:filter(fun is_raw_addr_node/1,
                                        ns_node_disco:nodes_wanted()),
            case RawAddrNodes of
                [] ->
                    ok;
                _ ->
                    M = io_lib:format("Can't change address family when "
                                      "nodes are configured with raw IP "
                                      "addresses: ~p", [RawAddrNodes]),
                    {error, M}
            end
    end.

verify_net_config_allowed(State) ->

    NodeEncryption = validator:get_value(nodeEncryption, State),
    AFamily = validator:get_value(afamily, State),
    AutoFailover = ns_config_auth:is_system_provisioned() andalso
                   auto_failover:is_enabled(),
    Encrypted = misc:should_cluster_data_be_encrypted(),
    IsCommunity = not cluster_compat_mode:is_enterprise(),

    if
        IsCommunity andalso NodeEncryption =:= true ->
            M = <<"Node encryption is not supported in community edition">>,
            validator:return_error(nodeEncryption, M, State);
        IsCommunity andalso AFamily =:= inet6 ->
            M = <<"IPv6 is not supported in community edition">>,
            validator:return_error(afamily, M, State);
        AutoFailover ->
            M = "Can't change network configuration when auto-failover "
                "is enabled.",
            validator:return_error('_', M, State);
        Encrypted andalso NodeEncryption =:= false ->
            M = <<"Can't disable nodeEncryption when the cluster "
                  "encryption level has been set to ">>,
            EL = atom_to_binary(misc:get_cluster_encryption_level(), latin1),
            validator:return_error(nodeEncryption, <<M/binary, EL/binary>>,
                                   State);
        true ->
            State
    end.

net_config_validators(SafeAction) ->
    afamily_validators() ++
    node_encryption_validators() ++
    [validator:has_params(_),
     validator:unsupported(_)] ++
     case SafeAction of
         true -> [];
         false ->
             [verify_net_config_allowed(_),
              validator:validate(fun check_for_raw_addr/1, afamily, _)]
     end.

afamily_validators() ->
    IsEnterprise = cluster_compat_mode:is_enterprise(),
    AFamilyAllowedValues =
        case IsEnterprise of
            true -> ["ipv4", "ipv6"];
            false -> ["ipv4"]
        end,
    AFamilyValidateFun =
        case IsEnterprise of
            true ->
                fun ("ipv4") -> {value, inet};
                    ("ipv6") -> {value, inet6}
                end;
            false ->
                fun ("ipv4") -> {value, inet}
                end
        end,

    [validator:one_of(afamily, AFamilyAllowedValues, _),
     validator:boolean(afamilyOnly, _),
     validator:validate(AFamilyValidateFun, afamily, _)].

node_encryption_validators() ->
    IsEnterprise = cluster_compat_mode:is_enterprise(),
    NodeEncryptionAllowedValues =
        case IsEnterprise of
            true -> ["on", "off"];
            false -> ["off"]
        end,
    NodeEncryptionValidateFun =
        case IsEnterprise of
            true ->
                fun ("on") -> {value, true};
                    ("off") -> {value, false}
                end;
            false ->
                fun ("off") -> {value, false}
                end
        end,

    [validator:boolean(clientCertVerification, _),
     validator:one_of(nodeEncryption, NodeEncryptionAllowedValues, _),
     validator:validate(NodeEncryptionValidateFun, nodeEncryption, _),
     validator:validate_multiple(
       fun ([Encr, ClientVer]) ->
            ClientVer2 = case ClientVer of
                             undefined -> cb_dist:client_cert_verification();
                             _ -> ClientVer
                         end,
            Encr2 = case Encr of
                        undefined -> cb_dist:external_encryption();
                        _ -> Encr
                    end,
            menelaus_web_cert:validate_client_cert_CAs(
              ns_config:search(ns_config:latest(), cluster_encryption_level,
                               control),
              ns_ssl_services_setup:client_cert_auth_state(),
              Encr2 andalso ClientVer2)
       end, [nodeEncryption, clientCertVerification], _)].

handle_setup_net_config(Req) ->
    validator:handle(
      fun (Values) ->
          menelaus_util:survive_web_server_restart(
            fun () ->
                case netconfig_updater:apply_config(Values) of
                    ok ->
                        %% Wait for web servers to restart
                        ns_config:sync_announcements(),
                        menelaus_event:sync(
                          chronicle_compat_events:event_manager()),
                        cluster_compat_mode:is_enterprise() andalso
                            ns_ssl_services_setup:sync(),
                        menelaus_util:reply(Req, 200);
                    {error, ErrorTerm} ->
                        Msg = iolist_to_binary(
                                netconfig_updater:format_error(ErrorTerm)),
                        menelaus_util:reply_global_error(Req, Msg)
                end
            end)
      end, Req, form, net_config_validators(false)).

handle_change_external_listeners(disable_unused, Req) ->
    case netconfig_updater:change_external_listeners(disable_unused, []) of
        ok -> menelaus_util:reply(Req, 200);
        {error, ErrorTerm} ->
            Msg = iolist_to_binary(netconfig_updater:format_error(ErrorTerm)),
            menelaus_util:reply_global_error(Req, Msg)
    end;
handle_change_external_listeners(Action, Req) ->
    validator:handle(
      fun (Props) ->
              case netconfig_updater:change_external_listeners(Action, Props) of
                  ok ->
                      case Action of
                          enable ->
                              AFamily = proplists:get_value(afamily, Props),
                              Encryption = proplists:get_value(
                                             nodeEncryption, Props),
                              Opts = [{node_afamily, AFamily}
                                          || AFamily =/= undefined] ++
                                     [{node_encryption, Encryption}
                                          || Encryption =/= undefined],
                              case ns_cluster:verify_otp_connectivity(
                                     node(), Opts) of
                                  {ok, _} ->
                                      menelaus_util:reply(Req, 200);
                                  {error, _, {_, Msg}} ->
                                      menelaus_util:reply_global_error(Req, Msg)
                              end;
                          disable ->
                              menelaus_util:reply(Req, 200)
                      end;
                  {error, ErrorTerm} ->
                      Msg = iolist_to_binary(
                              netconfig_updater:format_error(ErrorTerm)),
                      menelaus_util:reply_global_error(Req, Msg)
              end
      end, Req, form, net_config_validators(Action == disable)).

-ifdef(TEST).
validate_ix_cbas_path_test() ->
    ?assertEqual(false, validate_ix_cbas_path({path, "/abc/def"}, "/abc/def")),
    ?assertEqual(false, validate_ix_cbas_path({path2, "/abc/def"}, "/abc/def")),
    ?assertMatch({true, _}, validate_ix_cbas_path({path2, "/ab/de"}, "/ab")),
    ?assertMatch({true, _}, validate_ix_cbas_path({path2, "/ab/de/f"}, "/ab")),
    ?assertEqual(false, validate_ix_cbas_path({path2, "/abc/def"}, "/abc/de")),
    ?assertEqual(false, validate_ix_cbas_path({path2, "/abc"}, "/abc/hi")).
-endif.

handle_export_chronicle_snapshot(Req) ->
    menelaus_util:ensure_local(Req),
    Dir = path_config:component_path(data),
    Path = filename:join(Dir, "exported_chronicle_snapshots"),
    ok = misc:ensure_writable_dir(Path),

    %% cleanup directory as best we can.
    {ok, Files} = file:list_dir(Path),
    [file:delete(filename:join(Path, F)) || F <- Files],

    case chronicle:export_snapshot(Path) of
        ok ->
            menelaus_util:reply_text(Req, Path, 200);
        {error, _} = Err ->
            ?log_debug("Exporting snapshot failed with reason: ~p", [Err]),
            menelaus_util:reply_text(Req, <<"Internal Error">>, 500)
    end.
