%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Web server for menelaus.

-module(menelaus_web).

-author('NorthScale <info@northscale.com>').

-behavior(ns_log_categorizing).

-include("menelaus_web.hrl").
-include("ns_common.hrl").
-include("ns_heart.hrl").
-include("ns_stats.hrl").
-include("rbac.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0,
         start_link/1,
         http_server/1,
         loop/2,
         webconfig/0,
         webconfig/1,
         get_uuid/0,
         get_addr/2,
         init/1,
         response_time_ms/1]).

-export([ns_log_cat/1, ns_log_code_string/1, ns_log_prepare_message/2]).

-import(menelaus_util,
        [redirect_permanently/2,
         reply/2,
         reply_text/3,
         reply_text/4,
         reply_ok/3,
         reply_json/3,
         reply_not_found/1,
         get_option/2]).

-define(PLUGGABLE_UI, "_p").
-define(PROMETHEUS_API, "_prometheus").

%% External API

start_link() ->
    start_link([]).
start_link(Options) ->
    Defaults = [{name, ?MODULE} | webconfig()],
    MergedOptions = misc:update_proplist(Defaults, Options),
    supervisor:start_link(?MODULE, [MergedOptions]).

init([Options]) ->
    IsEnterprise = cluster_compat_mode:is_enterprise(),
    Specs = [{menelaus_web_ipv4,
              {?MODULE, http_server, [[{afamily, inet} | Options]]},
              permanent, 5000, worker, dynamic}] ++
            [{menelaus_web_ipv6,
              {?MODULE, http_server, [[{afamily, inet6} | Options]]},
              permanent, 5000, worker, dynamic} || IsEnterprise],
    {ok, {{one_for_all, 10, 10}, Specs}}.

get_addr(AFamily, IsSSL) ->
    case misc:disable_non_ssl_ports() andalso not IsSSL of
        true ->
            misc:localhost(AFamily, []);
        false ->
            misc:inaddr_any(AFamily, [])
    end.

get_name(Name, inet) ->
    get_name(Name, "ipv4");
get_name(Name, inet6) ->
    get_name(Name, "ipv6");
get_name(Name, String) when is_list(String) ->
    list_to_atom(lists:flatten(io_lib:format("~p_~s", [Name, String]))).

generate_http_server_options(Options) ->
    {AppRoot, Options1} = get_option(approot, Options),
    {AFamily, Options2} = get_option(afamily, Options1),
    {Name, Options3} = get_option(name, Options2),
    {SSLOptsFun, Options4} = get_option(ssl_opts_fun, Options3),
    SSLOpts = case SSLOptsFun of
                  undefined -> [];
                  F when is_function(F) -> [{ssl_opts, F()}]
              end,
    Plugins = menelaus_pluggable_ui:find_plugins(),
    IsSSL = proplists:get_bool(ssl, Options4),
    Loop = fun (Req) ->
                   ?MODULE:loop(Req, {AppRoot, IsSSL, Plugins})
           end,
    [{ip, get_addr(AFamily, IsSSL)},
     {name, get_name(Name, AFamily)},
     {loop, Loop} | SSLOpts] ++ Options4.

http_server(Options) ->
    ServerAFamily = proplists:get_value(afamily, Options),
    Type =  misc:get_afamily_type(ServerAFamily),
    maybe_start_http_server(Type, Options).

maybe_start_http_server(off, _Options) ->
    ignore;
maybe_start_http_server(Type, Options) ->
    ServerOptions = generate_http_server_options(Options),
    LogOptions = lists:filtermap(
                   fun ({ssl, _}) -> true;
                       ({ip, _}) -> true;
                       ({port, _}) -> true;
                       ({ssl_opts, L}) ->
                            {true, lists:map(fun ({K, _}) when K =:= password;
                                                               K =:= key ->
                                                     {K, "********"};
                                                 (KV) -> KV
                                             end, L)};
                       (_) -> false
                   end, ServerOptions),

    case mochiweb_http:start_link(ServerOptions) of
        {ok, Pid} ->
            ?log_info("Started web service with options:~n~p", [LogOptions]),
            {ok, Pid};
        Other ->
            {Msg, Values} = {"Failed to start web service with ~p, Reason : ~p",
                             [LogOptions, Other]},
            case Type of
                optional ->
                    ?log_warning("Ignoring error: " ++ Msg, Values),
                    ignore;
                required ->
                    ?MENELAUS_WEB_LOG(?START_FAIL, Msg, Values),
                    Other
            end
    end.

get_approot() ->
    case application:get_env(ns_server, approot) of
        {ok, AppRoot} ->
            AppRoot;
        _ ->
            menelaus_deps:local_path(["priv", "public"], ?MODULE)
    end.

webconfig() ->
    [{port, service_ports:get_port(rest_port)},
     {nodelay, true},
     {approot, get_approot()},
     %% 2048 (default) + 1024 for app telemetry websockets
     {max, 3072}].

webconfig(Prop) ->
    proplists:get_value(Prop, webconfig()).

parse_path(RawPath) ->
    RawPathSingleSlash = lists:flatten(mochiweb_util:normalize_path(RawPath)),
    case RawPathSingleSlash of
        "/" ++ RawPathStripped ->
            {Path, _, _} = mochiweb_util:urlsplit_path(RawPathStripped),
            Path;
        _ -> menelaus_util:web_exception(400, "Bad Request")
    end.

loop(Req0, Config) ->
    ok = menelaus_sup:barrier_wait(),
    StartTime = erlang:monotonic_time(millisecond),
    Req = mochiweb_request:set_meta(menelaus_start_time, StartTime, Req0),

    menelaus_util:handle_request(
      Req,
      fun () ->
              %% Using raw_path so encoded slash characters like %2F are
              %% handed correctly, in that we delay converting %2F's to slash
              %% characters until after we split by slashes.
              RawPath = mochiweb_request:get(raw_path, Req),
              Path = parse_path(RawPath),
              PathTokens = lists:map(fun mochiweb_util:unquote/1,
                                     string:tokens(Path, "/")),
              request_tracker:request(
                rest,
                fun () ->
                        loop_inner(Req, Config, Path, PathTokens)
                end)
      end).

%% Use the old permission until the cluster compat mode is bumped. This is
%% needed for REST APIs existing prior to morpheus but whose permissions
%% changed in morpheus.
when_morpheus(NewPermission, OldPermission) ->
    case cluster_compat_mode:is_cluster_morpheus() of
        true -> NewPermission;
        false -> OldPermission
    end.

-type action() :: {done, term()} |
                  {ui, boolean(), fun()} |
                  {ui, boolean(), fun(), [term()]} |
                  {rbac_permission() | no_check | local, fun()} |
                  {rbac_permission() | no_check | local, fun(), [term()]}.

-spec get_action(mochiweb_request(), {term(), boolean(), term()}, string(), [string()]) -> action().
get_action(Req, {AppRoot, IsSSL, Plugins}, Path, PathTokens) ->
    case mochiweb_request:get(method, Req) of
        Method when Method =:= 'GET'; Method =:= 'HEAD' ->
            case PathTokens of
                [] ->
                    {done, redirect_permanently("/ui/index.html", Req)};
                ["saml", "auth"] ->
                    {ui, IsSSL, fun menelaus_web_saml:handle_auth/1};
                ["saml", "deauth"] ->
                    {no_check, fun menelaus_web_saml:handle_deauth/1};
                ["saml", ?SAML_CONSUME_ENDPOINT_PATH] ->
                    {ui, IsSSL,
                     fun menelaus_web_saml:handle_get_saml_consume/1};
                ["saml", ?SAML_METADATA_ENDPOINT_PATH] ->
                    {ui, IsSSL,
                     fun menelaus_web_saml:handle_saml_metadata/1};
                ["saml", ?SAML_LOGOUT_ENDPOINT_PATH] ->
                    {ui, IsSSL,
                     fun menelaus_web_saml:handle_get_saml_logout/1};
                ["saml", "error"] ->
                    {ui, IsSSL, fun menelaus_web_saml:handle_get_error/1};
                ["ui"] ->
                    {done, redirect_permanently("/ui/index.html", Req)};
                ["_ui", "canUseCertForAuth"] ->
                    {ui, IsSSL,
                     fun menelaus_web_misc:handle_can_use_cert_for_auth/1};
                ["_ui", "authMethods"] ->
                    {ui, IsSSL,
                     fun menelaus_web_misc:handle_get_ui_auth_methods/1};
                ["versions"] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_misc:handle_versions/1};
                ["whoami"] ->
                    {no_check, fun menelaus_web_rbac:handle_whoami/1};
                ["pools"] ->
                    {{[pools], read}, fun menelaus_web_pools:handle_pools/1};
                ["pools", "default"] ->
                    {{[pools], read}, fun menelaus_web_pools:check_and_handle_pool_info/2, ["default"]};
                ["pools", "default", "terseClusterInfo"] ->
                    {{[pools], read},
                     fun menelaus_web_pools:handle_terse_cluster_info/1};
                %% NOTE: see MB-10859. Our docs used to
                %% recommend doing this which due to old
                %% code's leniency worked just like
                %% /pools/default. So temporarily we allow
                %% /pools/nodes to be alias for
                %% /pools/default
                ["pools", "nodes"] ->
                    {{[pools], read}, fun menelaus_web_pools:check_and_handle_pool_info/2, ["default"]};
                ["_uiroles"] ->
                    {{[ui], read}, fun menelaus_web_rbac:handle_get_uiroles/1};
                ["_uiEnv"] ->
                    {done, serve_ui_env(Req)};
                ["poolsStreaming", "default"] ->
                    {{[pools], read}, fun menelaus_web_pools:handle_pool_info_streaming/2, ["default"]};
                ["pools", "default", "buckets"] ->
                    {{[{bucket, any}, settings], read}, fun menelaus_web_buckets:handle_bucket_list/1, []};
                ["pools", "default", "saslBucketsStreaming"] ->
                    {{[admin, buckets], read},
                     fun menelaus_web_buckets:handle_sasl_buckets_streaming/2,
                     ["default"]};
                ["pools", "default", "buckets", Id] ->
                    {{[{bucket, Id}, settings], read},
                     fun menelaus_web_buckets:handle_bucket_info/3,
                     ["default", Id]};
                ["pools", "default", "bucketsStreaming", Id] ->
                    {{[{bucket, Id}, settings], read},
                     fun menelaus_web_buckets:handle_bucket_info_streaming/3,
                     ["default", Id]};
                ["pools", "default", "buckets", Id, "ddocs"] ->
                    {{[{bucket, Id}, views], read},
                     fun menelaus_web_buckets:handle_ddocs_list/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "docs"] ->
                    {{[{collection, [Id, "_default", "_default"]},
                       data, docs], read},
                     fun menelaus_web_crud:handle_list/2, [Id]};
                ["pools", "default", "buckets", Id, "docs", DocId] ->
                    {{[{collection, [Id, "_default", "_default"]},
                       data, docs], read},
                     fun menelaus_web_crud:handle_get/3, [Id, DocId]};
                ["pools", "default", "buckets", BucketId, "scopes", ScopeId,
                 "collections", CollectionId, "docs"] ->
                    {{[{collection, [BucketId, ScopeId, CollectionId]},
                       data, docs], read},
                     fun menelaus_web_crud:handle_list/4,
                     [BucketId, ScopeId, CollectionId]};
                ["pools", "default", "buckets", BucketId, "scopes", ScopeId,
                 "collections", CollectionId, "docs", DocId] ->
                    {{[{collection, [BucketId, ScopeId, CollectionId]},
                       data, docs], read},
                     fun menelaus_web_crud:handle_get/5,
                     [BucketId, ScopeId, CollectionId, DocId]};
                ["pools", "default", "buckets", "@" ++ _ = Id, "stats"] ->
                    {{[{bucket, any}, stats], read},
                     fun menelaus_stats:handle_stats_section/3,
                     ["default", Id]};
                ["pools", "default", "buckets", Id, "stats"] ->
                    {{[{bucket, Id}, stats], read},
                     fun menelaus_stats:handle_bucket_stats/3,
                     ["default", Id]};
                ["pools", "default", "buckets", Id, "localRandomKey"] ->
                    {{[{collection, [Id, "_default", "_default"]},
                       data, docs], read},
                     fun menelaus_web_buckets:handle_local_random_key/2, [Id]};
                ["pools", "default", "buckets", BucketId, "scopes", ScopeId,
                 "collections", CollectionId, "localRandomKey"] ->
                    {{[{collection, [BucketId, ScopeId, CollectionId]},
                       data, docs], read},
                     fun menelaus_web_buckets:handle_local_random_key/4,
                     [BucketId, ScopeId, CollectionId]};
                ["pools", "default", "buckets", Id, "statsDirectory"] ->
                    {{[{bucket, Id}, stats], read}, fun menelaus_stats:serve_stats_directory/3,
                     ["default", Id]};
                ["pools", "default", "nodeServices"] ->
                    {{[pools], read}, fun menelaus_web_cluster:serve_node_services/1, []};
                ["pools", "default", "nodeServicesStreaming"] ->
                    {{[pools], read}, fun menelaus_web_cluster:serve_node_services_streaming/1, []};
                ["pools", "default", "b", BucketName] ->
                    {{[{bucket, BucketName}, settings], read},
                     fun menelaus_web_buckets:serve_short_bucket_info/2, [BucketName]};
                ["pools", "default", "bs", BucketName] ->
                    {{[{bucket, BucketName}, settings], read},
                     fun menelaus_web_buckets:serve_streaming_short_bucket_info/2, [BucketName]};
                ["pools", "default", "buckets", Id, "nodes"] ->
                    {{[{bucket, Id}, settings], read},
                     fun menelaus_web_node:handle_bucket_node_list/2, [Id]};
                ["pools", "default", "buckets", Id, "nodes", NodeId] ->
                    {{[{bucket, Id}, settings], read},
                     fun menelaus_web_node:handle_bucket_node_info/3, [Id, NodeId]};
                ["pools", "default", "buckets", "@" ++ _ = Id, "nodes", NodeId,
                 "stats"] ->
                    {{[{bucket, any}, stats], read},
                     fun menelaus_stats:handle_stats_section_for_node/4,
                     ["default", Id, NodeId]};
                ["pools", "default", "buckets", Id, "nodes", NodeId, "stats"] ->
                    {{[{bucket, Id}, stats], read},
                     fun menelaus_stats:handle_bucket_node_stats/4,
                     ["default", Id, NodeId]};
                ["pools", "default", "buckets", Id, "stats", StatName] ->
                    {{[{bucket, Id}, stats], read},
                     fun menelaus_stats:handle_specific_stat_for_buckets/4,
                     ["default", Id, StatName]};
                ["pools", "default", "buckets", Id, "recoveryStatus"] ->
                    {{[{bucket, Id}, recovery], read},
                     fun menelaus_web_recovery:handle_recovery_status/3,
                     ["default", Id]};
                ["pools", "default", "buckets", Id, "scopes"] ->
                    {{[{collection, [Id, any, any]}, collections], read},
                     fun menelaus_web_collections:handle_get/2, [Id]};
                ["pools", "default", "replications"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "remoteClusters"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "serverGroups"] ->
                    {{[server_groups], read},
                     fun menelaus_web_groups:handle_server_groups/1};
                ["pools", "default", "trustedCAs"] ->
                    {no_check, fun menelaus_web_cert:handle_get_trustedCAs/1};
                ["pools", "default", "certificate"] ->
                    {done, menelaus_web_cert:handle_cluster_certificate(Req)};
                ["pools", "default", "certificates"] ->
                    {{[admin, security], read},
                     fun menelaus_web_cert:handle_get_certificates/2, [node_cert]};
                ["pools", "default", "certificate", "node", Node] ->
                    {{[admin, security], read},
                     fun menelaus_web_cert:handle_get_certificate/3, [node_cert, Node]};
                ["pools", "default", "certificates", "client"] ->
                    {{[admin, security], read},
                     fun menelaus_web_cert:handle_get_certificates/2, [client_cert]};
                ["pools", "default", "certificate", "node", Node, "client"] ->
                    {{[admin, security], read},
                     fun menelaus_web_cert:handle_get_certificate/3, [client_cert, Node]};
                ["pools", "default", "settings", "memcached", "global"] ->
                    {{[admin, memcached], read}, fun menelaus_web_mcd_settings:handle_global_get/1};
                ["pools", "default", "settings", "memcached", "effective", Node] ->
                    {{[admin, memcached], read}, fun menelaus_web_mcd_settings:handle_effective_get/2, [Node]};
                ["pools", "default", "settings", "memcached", "node", Node] ->
                    {{[admin, memcached], read}, fun menelaus_web_mcd_settings:handle_node_get/2, [Node]};
                ["pools", "default", "settings", "memcached", "node", Node, "setting", Name] ->
                    {{[admin, memcached], read}, fun menelaus_web_mcd_settings:handle_node_setting_get/3, [Node, Name]};
                ["pools", "default", "stats", "range" | PathLeft] ->
                    {{[{collection, [any, any, any]}, stats], read},
                     fun menelaus_web_stats:handle_range_get/2, [PathLeft]};
                ["pools", "default", "services", Service, "defragmented"] ->
                    {{[pools], read},
                     fun menelaus_web_pools:handle_defragmented/2, [Service]};
                ["nodeStatuses"] ->
                    {{[nodes], read}, fun menelaus_web_node:handle_node_statuses/1};
                ["logs"] ->
                    {{[logs], read}, fun menelaus_alert:handle_logs/1};
                ["events"] ->
                    {{[logs], read}, fun menelaus_alert:handle_events/1};
                ["eventsStreaming"] ->
                    {{[logs], read}, fun menelaus_alert:handle_events_streaming/1};
                ["logs", "rebalanceReport"] ->
                    {{[admin, logs], read},
                     fun menelaus_web_cluster_logs:handle_rebalance_report/1};
                ["settings", "web"] ->
                    {{[settings], read}, fun menelaus_web_settings:handle_settings_web/1};
                ["settings", "alerts"] ->
                    {{[settings], read}, fun menelaus_alert:handle_settings_alerts/1};
                ["settings", "alerts", "limits"] ->
                    {{[settings], read},
                     fun menelaus_web_alerts_srv:handle_settings_alerts_limits_get/1};
                ["settings", "stats"] ->
                    {{[settings], read}, fun menelaus_web_settings:handle_settings_stats/1};
                ["internal", "settings", "metrics" | PathRest] ->
                    {{[admin, settings, metrics], read},
                     fun menelaus_web_stats:handle_get_internal_settings/2,
                     [PathRest]};
                ["settings", "appTelemetry"] ->
                    {{[settings, metrics], read},
                     fun menelaus_web_app_telemetry:handle_get/1, []};
                ["settings", "metrics" | PathRest] ->
                    {{[settings, metrics], read},
                     fun menelaus_web_stats:handle_get_settings/2, [PathRest]};
                ["settings", "failover"] ->
                    {{[settings], read}, fun menelaus_web_settings:handle_get/2,
                     [failover]};
                ["settings", "serverless"] ->
                    {{[admin, settings], read},
                     fun menelaus_web_settings:handle_get/2, [serverless]};
                ["settings", "serverless", "node"] ->
                    {{[admin, settings], read},
                     fun menelaus_web_node:handle_throttle_capacity_get/1};
                ["settings", "autoFailover"] ->
                    {{[settings], read}, fun menelaus_web_auto_failover:handle_settings_get/1};
                ["settings", "autoReprovision"] ->
                    {{[settings], read},
                     fun menelaus_web_settings:handle_settings_auto_reprovision/1};
                ["settings", "rebalance"] ->
                    {{[settings], read},
                     fun menelaus_web_settings:handle_settings_rebalance/1};
                ["settings", "cgroups"] ->
                    {{[settings], read},
                     fun menelaus_web_settings:handle_get_cgroup_overrides/1};
                ["settings", "retryRebalance"] ->
                    {{[settings], read},
                     fun menelaus_web_auto_rebalance:handle_get_retry/1};
                ["settings", "querySettings"] ->
                    {{[settings], read}, fun menelaus_web_queries:handle_settings_get/1};
                %% The following API will be deprecated and will be succeeded
                %% by the one below.
                ["settings", "querySettings", "curlWhitelist"] ->
                    {{[settings], read},
                     fun menelaus_web_queries:handle_curl_whitelist_get/1};
                ["settings", "querySettings", "curlAllowlist"] ->
                    {{[settings], read},
                     fun menelaus_web_queries:handle_curl_whitelist_get/1};
                ["settings", "logRedaction"] ->
                    {{[settings], read}, fun menelaus_web_cluster_logs:handle_settings_log_redaction/1};
                ["settings", "maxParallelIndexers"] ->
                    {{[settings, indexes], read},
                     fun menelaus_web_settings:handle_settings_max_parallel_indexers/1};
                ["settings", "viewUpdateDaemon"] ->
                    {{[settings, indexes], read},
                     fun menelaus_web_settings:handle_settings_view_update_daemon/1};
                ["settings", "autoCompaction"] ->
                    {{[settings, autocompaction], read},
                     fun menelaus_web_autocompaction:handle_get_global_settings/1};
                ["settings", "replications"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["settings", "replications", _XID] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["settings", "saslauthdAuth"] ->
                    {when_morpheus({[admin, security], read},
                                   {[admin, security, external], read}),
                     fun menelaus_web_rbac:handle_saslauthd_auth_settings/1};
                ["settings", "ldap"] ->
                    {when_morpheus({[admin, security], read},
                                   {[admin, security, external], read}),
                     fun menelaus_web_ldap:handle_ldap_settings/1};
                ["settings", "clientCertAuth"] ->
                    {{[admin, security], read},
                     fun menelaus_web_cert:handle_client_cert_auth_settings/1};
                ["settings", "audit"] ->
                    {{[admin, security], read},
                     fun menelaus_web_audit:handle_get/1};
                ["settings", "audit", "descriptors"] ->
                    {{[admin, security], read},
                     fun menelaus_web_audit:handle_get_descriptors/1};
                ["settings", "audit", "nonFilterableDescriptors"] ->
                    {{[admin, security], read},
                     fun menelaus_web_audit:handle_get_non_filterable_descriptors/1};
                ["settings", "rbac"] ->
                    {{[admin, users], read},
                     fun menelaus_web_rbac:handle_get/1};
                ["settings", "rbac", "roles"] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_roles/1};
                ["settings", "rbac", "users"] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_users/2, [Path]};
                ["settings", "rbac", "users", Domain] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_users/3, [Path, Domain]};
                ["settings", "rbac", "users", Domain, UserId] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_user/3, [Domain, UserId]};
                ["settings", "rbac", "groups"] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_groups/2, [Path]};
                ["settings", "rbac", "groups", GroupId] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_group/2, [GroupId]};
                ["settings", "rbac", "profiles"] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_profiles/1};
                ["settings", "rbac", "profiles", "@self"] ->
                    {no_check,
                     fun menelaus_web_rbac:handle_get_profile/2, [self]};
                ["settings", "rbac", "profiles", Domain, UserId] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_get_profile/2,
                     [{UserId, Domain}]};
                ["settings", "rbac", "lookupLDAPUser", Name] ->
                    {when_morpheus({[admin, security_info], read},
                                   {[admin, security, external], read}),
                     fun menelaus_web_rbac:handle_lookup_ldap_user/2, [Name]};
                ["settings", "rbac", "backup"] ->
                    {when_morpheus({[admin, users], read},
                                   {[admin, security], read}),
                     fun menelaus_web_rbac:handle_backup/1};
                ["settings", "passwordPolicy"] ->
                    {{[admin, security], read},
                     fun menelaus_web_rbac:handle_get_password_policy/1};
                ["settings", "security", "encryptionAtRest" | PathRest] ->
                    {{[admin, security], read},
                     fun menelaus_web_encr_at_rest:handle_get/2, [PathRest]};
                ["settings", "security", "userActivity"] ->
                    {{[admin, security], read},
                     fun menelaus_web_activity:handle_get/1, []};
                ["settings", "security" | Keys] ->
                    {{[admin, security], read},
                     fun menelaus_web_settings:handle_get/3, [security, Keys]};
                ["settings", "license"] ->
                    {{[admin, license], read},
                     fun menelaus_web_license:handle_settings_get/1};
                ["settings", "saml" | PathRest] ->
                    {when_morpheus({[admin, security], read},
                                   {[admin, security, external], read}),
                     fun menelaus_web_saml:handle_get_settings/2, [PathRest]};
                ["settings", "jwt"] ->
                    {{[admin, security], read},
                     fun menelaus_web_jwt:handle_settings/2, ['GET']};
                ["settings", "dataService"] ->
                    {{[admin, settings], read},
                     fun menelaus_web_settings:handle_settings_data_service/1};
                ["settings", "resourceManagement" | PathRest] ->
                    {{[admin, settings], read},
                     fun menelaus_web_guardrails:handle_get/2, [PathRest]};
                ["settings", "encryptionKeys"] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_get_secrets/1};
                ["settings", "encryptionKeys", SecretId] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_get_secret/2, [SecretId]};
                ["internalSettings"] ->
                    {{[admin, settings], read},
                     fun menelaus_web_settings:handle_get/2, [internal]};
                ["nodes", "self", "secretsManagement" | PathRest] ->
                    {{[admin, security], read},
                     fun menelaus_web_sm:handle_get_settings/2, [PathRest]};
                ["nodes", NodeId] ->
                    {{[nodes], read}, fun menelaus_web_node:handle_node/2, [NodeId]};
                ["nodes", "self", "xdcrSSLPorts"] ->
                    {done, menelaus_web_node:handle_node_self_xdcr_ssl_ports(Req)};
                ["indexStatus"] ->
                    {{[{collection, [any, any, any]}, n1ql, index], read},
                     fun menelaus_web_indexes:handle_index_status/1};
                ["settings", "indexes"] ->
                    {{[settings, indexes], read}, fun menelaus_web_indexes:handle_settings_get/1};
                ["settings", "analytics"] ->
                    case cluster_compat_mode:is_columnar() of
                        true ->
                            {{[settings, analytics], read},
                             fun menelaus_web_columnar:handle_settings_get/1};
                        false ->
                            {{[settings, analytics], read},
                             fun menelaus_web_analytics:handle_settings_get/1}
                    end;
                ["settings", "columnar"] ->
                    {{[settings, analytics], read},
                     fun menelaus_web_columnar:handle_settings_get/1};
                ["fusion", "activeGuestVolumes"] ->
                    {{[pools], read},
                     fun menelaus_web_fusion:handle_get_active_guest_volumes/1};
                ["diag"] ->
                    {{[admin, diag], read}, fun diag_handler:handle_diag/1, []};
                ["diag", "vbuckets"] ->
                    {{[admin, diag], read}, fun diag_handler:handle_diag_vbuckets/1};
                ["diag", "ale"] ->
                    {{[admin, diag], read}, fun diag_handler:handle_diag_ale/1};
                ["diag", "masterEvents"] ->
                    {{[admin, diag], read}, fun diag_handler:handle_diag_master_events/1};
                ["diag", "password"] ->
                    {local, fun diag_handler:handle_diag_get_password/1};
                ["diag", "encryptionAtRest"] ->
                    {{[admin, diag], read},
                     fun diag_handler:handle_diag_encryption_at_rest/1};
                ["pools", "default", "rebalanceProgress"] ->
                    {{[tasks], read}, fun menelaus_web_cluster:handle_rebalance_progress/2, ["default"]};
                ["pools", "default", "pendingRetryRebalance"] ->
                    {{[tasks], read},
                     fun menelaus_web_auto_rebalance:handle_get_pending_retry/2, ["default"]};
                ["pools", "default", "currentRebalanceReport"] ->
                    {{[tasks], read},
                     fun menelaus_web_cluster:handle_current_rebalance_report/1};
                ["pools", "default", "tasks"] ->
                    {{[tasks], read}, fun menelaus_web_misc:handle_tasks/2, ["default"]};
                ["index.html"] ->
                    {done, redirect_permanently("/ui/index.html", Req)};
                ["sasl_logs"] ->
                    {{[admin, logs], read}, fun diag_handler:handle_sasl_logs/1, []};
                ["sasl_logs", LogName] ->
                    {{[admin, logs], read}, fun diag_handler:handle_sasl_logs/2, [LogName]};
                ["images" | _] ->
                    {ui, IsSSL, fun handle_serve_file/4, [AppRoot, Path, 30000000]};
                ["couchBase" | _] -> {no_check_disallow_anonymous,
                                      fun menelaus_pluggable_ui:proxy_req/4,
                                      ["couchBase",
                                       drop_prefix(mochiweb_request:get(raw_path, Req)),
                                       Plugins]};
                ["sampleBuckets"] -> {{[samples], read}, fun menelaus_web_samples:handle_get/1};
                ["_metakv" | _] ->
                    {{[admin, metakv], all}, fun menelaus_metakv:handle_get/2, [Path]};
                ["_metakv2" | _] ->
                    {{[admin, internal, metakv2], read},
                     fun menelaus_metakv2:handle_get/2, [Path]};
                ["xdcr", "c2cCommunications" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, c2c_communications], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "connectionPreCheck" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "sourceClusters" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "internalSettings" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[admin, internal], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                [?APP_TELEMETRY_PATH] ->
                    {{[app_telemetry], write},
                     fun app_telemetry_scraper:handle_connect/1};
                ["_cbauth", "checkPermission"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_rbac:handle_check_permission_for_cbauth/1};
                ["_cbauth", "getUserUuid"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_rbac:handle_get_user_uuid_for_cbauth/1};
                ["_cbauth", "getUserBuckets"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_rbac:handle_get_user_buckets_for_cbauth/1};
                ["_prometheusMetrics"] ->
                    {{[admin, internal, stats], read},
                     fun menelaus_web_prometheus:handle_get_local_metrics/2,
                     [false]};
                ["_prometheusMetricsHigh"] ->
                    {{[admin, internal, stats], read},
                     fun menelaus_web_prometheus:handle_get_local_metrics/2,
                     [true]};
                ["_statsMapping", Section | StatTokens] ->
                    {{[admin, internal], all},
                     fun stat_names_mappings:handle_stats_mapping_get/3,
                     [Section, StatTokens]};
                [?PLUGGABLE_UI, "ui" | _] ->
                    {ui, IsSSL, fun handle_serve_file/4, [AppRoot, Path, 10]};
                [?PLUGGABLE_UI, RestPrefix | _] ->
                    {no_check_disallow_anonymous,
                     fun (PReq) ->
                             menelaus_pluggable_ui:proxy_req(
                               RestPrefix,
                               drop_rest_prefix(mochiweb_request:get(raw_path, Req)),
                               Plugins, PReq)
                     end};
                ["metrics"] ->
                    {{[admin, stats_export], read},
                     fun menelaus_web_prometheus:handle_get_metrics/1};
                %% This API is being deprecated and should not be used. Instead
                %% the prometheus_sd_config endpoint should be used.
                ["prometheus_sd_config.yaml"] ->
                    {{[admin, stats_export], read},
                     fun menelaus_web_prometheus:handle_sd_config_yaml/1};
                ["prometheus_sd_config"] ->
                    {{[admin, stats_export], read},
                     fun menelaus_web_prometheus:handle_sd_config/1};
                [?PROMETHEUS_API | _] ->
                    "/"?PROMETHEUS_API ++ RawPath =
                        mochiweb_request:get(raw_path, Req),
                    {{[admin, stats_export], read},
                     fun menelaus_web_prometheus:proxy_prometheus_api/2,
                     [RawPath]};
                _ ->
                    {ui, IsSSL, fun handle_serve_file/4, [AppRoot, Path, 10]}
            end;
        'POST' ->
            case PathTokens of
                ["saml", ?SAML_CONSUME_ENDPOINT_PATH] ->
                    {ui, IsSSL,
                     fun menelaus_web_saml:handle_post_saml_consume/1};
                ["saml", ?SAML_LOGOUT_ENDPOINT_PATH] ->
                    {ui, IsSSL,
                     fun menelaus_web_saml:handle_post_saml_logout/1};
                ["uilogin"] ->
                    {ui, IsSSL, fun menelaus_web_misc:handle_uilogin/1};
                ["uilogout"] ->
                    {no_check, fun menelaus_web_misc:handle_uilogout/1};
                ["sampleBuckets", "install"] ->
                    {{[buckets], create}, fun menelaus_web_samples:handle_post/1};
                ["nodeInit"] ->
                    {{[admin, setup], write}, fun menelaus_web_node:handle_node_init/1};
                ["clusterInit"] ->
                    {{[admin, setup], write}, fun menelaus_web_cluster:handle_cluster_init/1};
                ["engageCluster2"] ->
                    {{[admin, setup], write}, fun menelaus_web_cluster:handle_engage_cluster2/1};
                ["completeJoin"] ->
                    {{[admin, setup], write}, fun menelaus_web_cluster:handle_complete_join/1};
                ["node", "controller", "doJoinCluster"] ->
                    {{[admin, setup], write}, fun menelaus_web_cluster:handle_join/1};
                ["node", "controller", "rename"] ->
                    {{[admin, setup], write}, fun menelaus_web_node:handle_node_rename/1};
                ["nodes", NodeId, "controller", "settings"] ->
                    {{[admin, setup], write}, fun menelaus_web_node:handle_node_settings_post/2,
                     [NodeId]};
                ["node", "controller", "setupServices"] ->
                    {{[admin, setup], write}, fun menelaus_web_cluster:handle_setup_services_post/1};
                ["node", "controller", "reloadCertificate"] ->
                    {{[admin, security], write},
                     fun (R) -> menelaus_web_cert:handle_reload_certificate(node_cert, R) end};
                ["node", "controller", "reloadClientCertificate"] ->
                    {{[admin, security], write},
                     fun (R) -> menelaus_web_cert:handle_reload_certificate(client_cert, R) end};
                ["node", "controller", "loadTrustedCAs"] ->
                    {{[admin, security], write},
                     fun menelaus_web_cert:handle_load_ca_certs/1};
                ["node", "controller", "changeMasterPassword"] ->
                    {{[admin, security], write},
                     fun menelaus_web_sm:handle_change_master_password/1};
                ["node", "controller", "rotateDataKey"] ->
                    {{[admin, security], write},
                     fun menelaus_web_sm:handle_rotate_data_key/1};
                ["node", "controller", "setupNetConfig"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_setup_net_config/1};
                ["node", "controller", "enableExternalListener"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_change_external_listeners/2, [enable]};
                ["node", "controller", "disableExternalListener"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_change_external_listeners/2, [disable]};
                ["node", "controller", "disableUnusedExternalListeners"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_change_external_listeners/2, [disable_unused]};
                ["node", "controller", "rotateInternalCredentials"] ->
                    {{[admin, security], write},
                     fun menelaus_web_misc:handle_rotate_internal_creds/1};
                ["node", "controller", "secretsManagement" | PathRest] ->
                    {{[admin, security], write},
                     fun menelaus_web_sm:handle_post_settings/2,
                     [PathRest]};
                ["settings", "web"] ->
                    {{[admin, setup], write}, fun menelaus_web_settings:handle_settings_web_post/1};
                ["settings", "alerts"] ->
                    {{[settings], write}, fun menelaus_alert:handle_settings_alerts_post/1};
                ["settings", "alerts", "testEmail"] ->
                    {{[settings], write},
                     fun menelaus_alert:handle_settings_alerts_send_test_email/1};
                ["settings", "alerts", "limits"] ->
                    {{[settings], write},
                     fun menelaus_web_alerts_srv:handle_settings_alerts_limits_post/1};
                ["settings", "stats"] ->
                    {{[settings], write}, fun menelaus_web_settings:handle_settings_stats_post/1};
                ["internal", "settings", "metrics" | PathRest] ->
                    {{[admin, settings, metrics], write},
                     fun menelaus_web_stats:handle_post_internal_settings/2,
                     [PathRest]};
                ["settings", "appTelemetry"] ->
                    {{[settings, metrics], write},
                     fun menelaus_web_app_telemetry:handle_post/1, []};
                ["settings", "metrics" | PathRest] ->
                    {{[settings, metrics], write},
                     fun menelaus_web_stats:handle_post_settings/2, [PathRest]};
                ["settings", "autoFailover"] ->
                    {{[settings], write}, fun menelaus_web_auto_failover:handle_settings_post/1};
                ["settings", "failover"] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_post/2, [failover]};
                ["settings", "serverless"] ->
                    {{[admin, settings], write},
                     fun menelaus_web_settings:handle_post/2, [serverless]};
                ["settings", "serverless", "node"] ->
                    {{[admin, settings], write},
                     fun menelaus_web_settings:handle_post/2,
                     [serverless_node]};
                ["settings", "autoFailover", "resetCount"] ->
                    {{[settings], write}, fun menelaus_web_auto_failover:handle_settings_reset_count/1};
                ["settings", "autoReprovision"] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_settings_auto_reprovision_post/1};
                ["settings", "rebalance"] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_settings_rebalance_post/1};
                ["settings", "cgroups"] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_post_cgroup_overrides/1};
                ["settings", "retryRebalance"] ->
                    {{[settings], write},
                     fun menelaus_web_auto_rebalance:handle_post_retry/1};
                ["settings", "querySettings"] ->
                    {{[settings], write}, fun menelaus_web_queries:handle_settings_post/1};
                %% The following API will be deprecated and will be succeeded
                %% by the one below.
                ["settings", "querySettings", "curlWhitelist"] ->
                    {{[settings], write},
                     fun menelaus_web_queries:handle_curl_whitelist_post/1};
                ["settings", "querySettings", "curlAllowlist"] ->
                    {{[settings], write},
                     fun menelaus_web_queries:handle_curl_whitelist_post/1};
                ["settings", "logRedaction"] ->
                    {{[admin, security], write},
                     fun menelaus_web_cluster_logs:handle_settings_log_redaction_post/1};
                ["settings", "autoReprovision", "resetCount"] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_settings_auto_reprovision_reset_count/1};
                ["settings", "maxParallelIndexers"] ->
                    {{[settings, indexes], write},
                     fun menelaus_web_settings:handle_settings_max_parallel_indexers_post/1};
                ["settings", "viewUpdateDaemon"] ->
                    {{[settings, indexes], write},
                     fun menelaus_web_settings:handle_settings_view_update_daemon_post/1};
                ["settings", "replications"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["settings", "replications", _XID] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["settings", "saslauthdAuth"] ->
                    {when_morpheus({[admin, security], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_rbac:handle_saslauthd_auth_settings_post/1};
                ["settings", "ldap"] ->
                    {when_morpheus({[admin, security], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_ldap:handle_ldap_settings_post/1};
                ["settings", "ldap", "validate", Type] ->
                    {when_morpheus({[admin, security], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_ldap:handle_ldap_settings_validate_post/2,
                     [Type]};
                ["settings", "invalidateLDAPCache"] ->
                    {when_morpheus({[admin, security_info], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_ldap:handle_invalidate_ldap_cache/1};
                ["settings", "clientCertAuth"] ->
                    {{[admin, security], write},
                     fun menelaus_web_cert:handle_client_cert_auth_settings_post/1};
                ["settings", "audit"] ->
                    {{[admin, security], write},
                     fun menelaus_web_audit:handle_post/1};
                ["settings", "passwordPolicy"] ->
                    {{[admin, security], write},
                     fun menelaus_web_rbac:handle_post_password_policy/1};
                ["settings", "security", "encryptionAtRest" | PathRest] ->
                    {{[admin, security], write},
                     fun menelaus_web_encr_at_rest:handle_post/2, [PathRest]};
                ["settings", "security", "userActivity"] ->
                    {{[admin, security], write},
                     fun menelaus_web_activity:handle_post/1, []};
                ["settings", "security" | Keys] ->
                    {{[admin, security], write},
                     fun menelaus_web_settings:handle_post/3, [security, Keys]};
                ["settings", "developerPreview"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_settings:handle_post/2, [developer_preview]};
                ["settings", "license"] ->
                    {{[admin, license], write},
                     fun menelaus_web_license:handle_settings_post/1};
                ["settings", "license", "validate"] ->
                    {{[admin, license], write},
                     fun menelaus_web_license:handle_settings_validate_post/1};
                ["settings", "saml"] ->
                    {when_morpheus({[admin, security], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_saml:handle_post_settings/1};
                ["settings", "dataService"] ->
                    {{[admin, settings], write},
                     fun menelaus_web_settings:handle_settings_data_service_post/1};
                ["settings", "resourceManagement" | PathRest] ->
                    {{[admin, settings], write},
                     fun menelaus_web_guardrails:handle_post/2, [PathRest]};
                ["settings", "encryptionKeys"] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_post_secret/1};
                ["settings", "encryptionKeys", "test"] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_test_post_secret/1};
                ["internalSettings"] ->
                    {{[admin, settings], write},
                     fun menelaus_web_settings:handle_post/2, [internal]};
                ["pools", "default"] ->
                    {{[pools], write}, fun menelaus_web_pools:handle_pool_settings_post/1};
                ["controller", "ejectNode"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_eject_post/1};
                ["controller", "addNode"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_add_node/1};
                ["controller", "addNodeV2"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_add_node/1};
                ["controller", "hardResetNode"] ->
                    {{[admin, reset], write},
                     fun menelaus_web_cluster:handle_hard_reset_node/1};
                ["pools", "default", "serverGroups", UUID, "addNode"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_add_node_to_group/2, [UUID]};
                ["pools", "default", "serverGroups", UUID, "addNodeV2"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_add_node_to_group/2, [UUID]};
                ["controller", "failOver"] ->
                    {{[pools], write},
                     fun menelaus_web_cluster:handle_start_hard_failover/2,
                     [false]};
                ["controller", "startFailover"] ->
                    {{[pools], write},
                     fun menelaus_web_cluster:handle_start_hard_failover/2,
                     [true]};
                ["controller", "pause"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_buckets:handle_start_pause/1};
                ["controller", "resume"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_buckets:handle_start_resume/1};
                ["controller", "stopPause"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_buckets:handle_stop_pause/1};
                ["controller", "stopResume"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_buckets:handle_stop_resume/1};
                ["controller", "startGracefulFailover"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_start_graceful_failover/1};
                ["controller", "fusion", "prepareRebalance"] ->
                    {{[pools], write},
                     fun menelaus_web_fusion:handle_prepare_rebalance/1};
                ["controller", "fusion", "uploadMountedVolumes"] ->
                    {{[pools], write},
                     fun menelaus_web_fusion:handle_upload_mounted_volumes/1};
                ["controller", "fusion", "syncLogStore"] ->
                    {{[admin, internal], all},
                     fun menelaus_web_fusion:handle_sync_log_store/1};
                ["controller", "rebalance"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_rebalance/1};
                ["controller", "reAddNode"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_re_add_node/1};
                ["controller", "reFailOver"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_re_failover/1};
                ["controller", "stopRebalance"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_stop_rebalance/1};
                ["controller", "cancelRebalanceRetry", RebId] ->
                    {{[pools], write},
                     fun menelaus_web_auto_rebalance:handle_cancel_pending_retry/2, [RebId]};
                ["controller", "setRecoveryType"] ->
                    {{[pools], write}, fun menelaus_web_cluster:handle_set_recovery_type/1};
                ["controller", "setAutoCompaction"] ->
                    {{[settings, autocompaction], write},
                     fun menelaus_web_autocompaction:handle_set_global_settings/1};
                ["controller", "createReplication"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["controller", "cancelXDCR", _XID] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["controller", "cancelXCDR", XID] ->
                    {no_check, fun goxdcr_rest:proxy/2,
                     [menelaus_util:concat_url_path(
                        ["controller", "cancelXDCR", XID])]};
                ["controller", "resetAlerts"] ->
                    {{[settings], write}, fun menelaus_web_settings:handle_reset_alerts/1};
                ["controller", "regenerateCertificate"] ->
                    {{[admin, security], write},
                     fun menelaus_web_cert:handle_regenerate_certificate/1};
                ["controller", "uploadClusterCA"] ->
                    {{[admin, security], write},
                     fun menelaus_web_cert:handle_upload_cluster_ca/1};
                ["controller", "startLogsCollection"] ->
                    {{[admin, logs], read},
                     fun menelaus_web_cluster_logs:handle_start_collect_logs/1};
                ["controller", "cancelLogsCollection"] ->
                    {{[admin, logs], read},
                     fun menelaus_web_cluster_logs:handle_cancel_collect_logs/1};
                ["controller", "resetAdminPassword"] ->
                    {local, fun menelaus_web_rbac:handle_reset_admin_password/1};
                ["controller", "lockAdmin"] ->
                    {local, fun menelaus_web_rbac:handle_lock_admin/1};
                ["controller", "unlockAdmin"] ->
                    {local, fun menelaus_web_rbac:handle_unlock_admin/1};
                ["controller", "resetCipherSuites"] ->
                    {local, fun menelaus_web_settings:handle_reset_ciphers_suites/1};
                ["controller", "changePassword"] ->
                    {no_check, fun menelaus_web_rbac:handle_change_password/1};
                ["controller", "rotateEncryptionKey", SecretId] ->
                    {{[admin, security], write},
                     fun menelaus_web_secrets:handle_rotate/2, [SecretId]};
                ["controller", "dropEncryptionAtRestDeks", "bucket", Id] ->
                    {{[{bucket, Id}, settings], write},
                     fun menelaus_web_encr_at_rest:handle_bucket_drop_keys/2,
                     [Id]};
                ["controller", "dropEncryptionAtRestDeks", Type] ->
                    {{[admin, security], write},
                     fun menelaus_web_encr_at_rest:handle_drop_keys/2, [Type]};
                ["controller", "forceEncryptionAtRest", "bucket", Id] ->
                    {{[{bucket, Id}, settings], write},
                     fun menelaus_web_encr_at_rest:handle_bucket_force_encr/2,
                     [Id]};
                ["controller", "forceEncryptionAtRest", Type] ->
                    {{[admin, security], write},
                     fun menelaus_web_encr_at_rest:handle_force_encr/2, [Type]};
                ["pools", "default", "buckets", Id] ->
                    {{[{bucket, Id}, settings], write},
                     fun menelaus_web_buckets:handle_bucket_update/3,
                     ["default", Id]};
                ["pools", "default", "buckets"] ->
                    {{[buckets], create},
                     fun menelaus_web_buckets:handle_bucket_create/2,
                     ["default"]};
                ["pools", "default", "buckets", Id, "docs", DocId] ->
                    {{[{collection, [Id, "_default", "_default"]},
                       data, docs], upsert},
                     fun menelaus_web_crud:handle_post/3, [Id, DocId]};
                ["pools", "default", "buckets", BucketId, "scopes", ScopeId,
                 "collections", CollectionId, "docs", DocId] ->
                    {{[{collection, [BucketId, ScopeId, CollectionId]},
                       data, docs], upsert},
                     fun menelaus_web_crud:handle_post/5,
                     [BucketId, ScopeId, CollectionId, DocId]};
                ["pools", "default", "buckets", Id, "controller", "doFlush"] ->
                    {{[{bucket, Id}], flush},
                     fun menelaus_web_buckets:handle_bucket_flush/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "compactBucket"] ->
                    {{[{bucket, Id}], compact},
                     fun menelaus_web_buckets:handle_compact_bucket/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "unsafePurgeBucket"] ->
                    {{[{bucket, Id}], delete},
                     fun menelaus_web_buckets:handle_purge_compact_bucket/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "cancelBucketCompaction"] ->
                    {{[{bucket, Id}], compact},
                     fun menelaus_web_buckets:handle_cancel_bucket_compaction/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "compactDatabases"] ->
                    {{[{bucket, Id}], compact},
                     fun menelaus_web_buckets:handle_compact_databases/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "cancelDatabasesCompaction"] ->
                    {{[{bucket, Id}], compact},
                     fun menelaus_web_buckets:handle_cancel_databases_compaction/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "startRecovery"] ->
                    {{[{bucket, Id}, recovery], write},
                     fun menelaus_web_recovery:handle_start_recovery/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "stopRecovery"] ->
                    {{[{bucket, Id}, recovery], write},
                     fun menelaus_web_recovery:handle_stop_recovery/3, ["default", Id]};
                ["pools", "default", "buckets", Id, "controller", "commitVBucket"] ->
                    {{[{bucket, Id}, recovery], write},
                     fun menelaus_web_recovery:handle_commit_vbucket/3, ["default", Id]};
                ["pools", "default", "buckets", Id,
                 "ddocs", DDocId, "controller", "compactView"] ->
                    {{[{bucket, Id}, views], compact},
                     fun menelaus_web_buckets:handle_compact_view/4, ["default", Id, DDocId]};
                ["pools", "default", "buckets", Id,
                 "ddocs", DDocId, "controller", "cancelViewCompaction"] ->
                    {{[{bucket, Id}, views], compact},
                     fun menelaus_web_buckets:handle_cancel_view_compaction/4,
                     ["default", Id, DDocId]};
                ["pools", "default", "buckets", Id,
                 "ddocs", DDocId, "controller", "setUpdateMinChanges"] ->
                    {{[{bucket, Id}, views], compact},
                     fun menelaus_web_buckets:handle_set_ddoc_update_min_changes/4,
                     ["default", Id, DDocId]};
                ["pools", "default", "buckets", Id, "scopes",
                 "@ensureManifest", ManifestId] ->
                    {{[{collection, [Id, any, any]}, collections], read},
                     fun menelaus_web_collections:handle_ensure_manifest/3,
                     [Id, ManifestId]};
                ["pools", "default", "buckets", Id, "scopes", Scope,
                 "collections"] ->
                    {{[{collection, [Id, Scope, all]}, collections], write},
                     fun menelaus_web_collections:handle_post_collection/3,
                     [Id, Scope]};
                ["pools", "default", "buckets", Id, "scopes"] ->
                    {{[{bucket, Id}, collections], write},
                     fun menelaus_web_collections:handle_post_scope/2, [Id]};
                ["pools", "default", "remoteClusters"] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "remoteClusters", _Id] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "serverGroups"] ->
                    {{[server_groups], write},
                     fun menelaus_web_groups:handle_server_groups_post/1};
                ["pools", "default", "settings", "memcached", "global"] ->
                    {{[admin, memcached], write},
                     fun menelaus_web_mcd_settings:handle_global_post/1};
                ["pools", "default", "settings", "memcached", "node", Node] ->
                    {{[admin, memcached], write},
                     fun menelaus_web_mcd_settings:handle_node_post/2, [Node]};
                ["pools", "default", "checkPermissions"] ->
                    {no_check,
                     fun menelaus_web_rbac:handle_check_permissions_post/1};
                ["pools", "default", "stats", "range"] ->
                    {{[{collection, [any, any, any]}, stats], read},
                     fun menelaus_web_stats:handle_range_post/1, []};
                ["settings", "indexes"] ->
                    {{[settings, indexes], write}, fun menelaus_web_indexes:handle_settings_post/1};
                ["settings", "analytics"] ->
                    case cluster_compat_mode:is_columnar() of
                        true ->
                            {{[settings, analytics], write},
                             fun menelaus_web_columnar:handle_settings_post/1};
                        false ->
                            {{[settings, analytics], write},
                             fun menelaus_web_analytics:handle_settings_post/1}
                    end;
                ["settings", "columnar"] ->
                    {{[settings, analytics], write},
                     fun menelaus_web_columnar:handle_settings_post/1};
                ["_cbauth"] ->
                    {no_check, fun menelaus_cbauth:handle_cbauth_post/1};
                ["_cbauth", "extractUserFromCert"] ->
                    {{[admin, internal], all},
                     fun menelaus_cbauth:handle_extract_user_from_cert_post/1};
                ["_log"] ->
                    {{[admin, internal], all}, fun menelaus_web_misc:handle_log_post/1};
                ["_event"] ->
                    {{[admin, event], all}, fun menelaus_web_misc:handle_event_log_post/1};
                ["_goxdcr", "regexpValidation"] ->
                    {no_check, fun goxdcr_rest:proxy/2,
                     [menelaus_util:concat_url_path(
                        ["controller", "regexpValidation"])]};
                ["_goxdcr", "_pre_replicate", Bucket] ->
                    {{[{bucket, Bucket}, data, docs], read},
                     fun menelaus_web_xdcr_target:handle_pre_replicate/2,
                     [Bucket]};
                ["_metakv2", "_controller", "getSnapshot"] ->
                    {{[admin, internal, metakv2], read},
                     fun menelaus_metakv2:handle_post_get_snapshot/1, []};
                ["_metakv2", "_controller", "setMultiple"] ->
                    {{[admin, internal, metakv2], write},
                     fun menelaus_metakv2:handle_post_set_multiple/1, []};
                ["_metakv2", "_controller", "syncQuorum"] ->
                    {{[admin, internal, metakv2], read},
                     fun menelaus_metakv2:handle_post_sync_quorum/1, []};
                ["xdcr", "c2cCommunications" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, c2c_communications], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "connectionPreCheck" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "sourceClusters" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "internalSettings" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[admin, internal], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["logClientError"] ->
                    {no_check, fun log_client_error/1};
                ["diag", "eval"] ->
                    {{[admin, diag], write}, fun diag_handler:handle_diag_eval/1};
                ["couchBase" | _] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_pluggable_ui:proxy_req/4,
                     ["couchBase",
                      drop_prefix(mochiweb_request:get(raw_path, Req)),
                      Plugins]};
                ["_createStatsSnapshot"] ->
                    {local, fun menelaus_web_prometheus:handle_create_snapshot/1};
                ["_exportChronicleSnapshot"] ->
                    {local,
                     fun menelaus_web_node:handle_export_chronicle_snapshot/1};
                [?PLUGGABLE_UI, RestPrefix | _] ->
                    {no_check_disallow_anonymous,
                     fun (PReq) ->
                             menelaus_pluggable_ui:proxy_req(
                               RestPrefix,
                               drop_rest_prefix(mochiweb_request:get(raw_path, Req)),
                               Plugins, PReq)
                     end};
                [?PROMETHEUS_API | _] ->
                    "/"?PROMETHEUS_API ++ RawPath =
                        mochiweb_request:get(raw_path, Req),
                    {{[admin, stats_export], read},
                     fun menelaus_web_prometheus:proxy_prometheus_api/2,
                     [RawPath]};
                _ ->
                    {done, reply_not_found(Req)}
            end;
        'DELETE' ->
            case PathTokens of
                ["pools", "default", "buckets", Id] ->
                    {{[{bucket, Id}], delete},
                     fun menelaus_web_buckets:handle_bucket_delete/3, ["default", Id]};
                ["pools", "default", "remoteClusters", _Id] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "buckets", Id, "scopes", Name] ->
                    {{[{collection, [Id, Name, all]}, collections], write},
                     fun menelaus_web_collections:handle_delete_scope/3,
                     [Id, Name]};
                ["pools", "default", "buckets", Id, "scopes", Scope,
                 "collections", Name] ->
                    {{[{collection, [Id, Scope, all]}, collections], write},
                     fun menelaus_web_collections:handle_delete_collection/4,
                     [Id, Scope, Name]};
                ["pools", "default", "buckets", Id, "docs", DocId] ->
                    {{[{collection, [Id, "_default", "_default"]},
                       data, docs], delete},
                     fun menelaus_web_crud:handle_delete/3, [Id, DocId]};
                ["pools", "default", "buckets", BucketId, "scopes", ScopeId,
                 "collections", CollectionId, "docs", DocId] ->
                    {{[{collection, [BucketId, ScopeId, CollectionId]},
                       data, docs], delete},
                     fun menelaus_web_crud:handle_delete/5,
                     [BucketId, ScopeId, CollectionId, DocId]};
                ["pools", "default", "trustedCAs", Id] ->
                    {{[admin, security], write},
                     fun menelaus_web_cert:handle_delete_trustedCA/2, [Id]};
                ["controller", "cancelXCDR", XID] ->
                    {no_check, fun goxdcr_rest:proxy/2,
                     [menelaus_util:concat_url_path(
                        ["controller", "cancelXDCR", XID])]};
                ["controller", "cancelXDCR", _XID] ->
                    {no_check, fun goxdcr_rest:proxy/1};
                ["pools", "default", "serverGroups", GroupUUID] ->
                    {{[server_groups], write},
                     fun menelaus_web_groups:handle_server_group_delete/2, [GroupUUID]};
                ["pools", "default", "settings", "memcached", "global",
                 "setting", Name] ->
                    {{[admin, memcached], write},
                     fun menelaus_web_mcd_settings:handle_global_delete/2,
                     [Name]};
                ["pools", "default", "settings", "memcached", "node", Node, "setting", Name] ->
                    {{[admin, memcached], write},
                     fun menelaus_web_mcd_settings:handle_node_setting_delete/3, [Node, Name]};
                ["settings", "rbac", "users", UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_delete_user/3, ["external", UserId]};
                ["settings", "rbac", "users", Domain, UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_delete_user/3, [Domain, UserId]};
                ["settings", "rbac", "groups", GroupId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_delete_group/2, [GroupId]};
                ["settings", "rbac", "profiles", "@self"] ->
                    {no_check,
                     fun menelaus_web_rbac:handle_delete_profile/2, [self]};
                ["settings", "rbac", "profiles", Domain, UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_delete_profile/2,
                     [{UserId, Domain}]};
                ["settings", "security" | Keys] ->
                    {{[admin, security], write},
                     fun menelaus_web_settings:handle_delete/3,
                     [security, Keys]};
                ["settings", "saml"] ->
                    {when_morpheus({[admin, security], write},
                                   {[admin, security, external], write}),
                     fun menelaus_web_saml:handle_delete_settings/1};
                ["settings", "cgroups", ServiceName] ->
                    {{[settings], write},
                     fun menelaus_web_settings:handle_delete_cgroup_override/2,
                     [ServiceName]};
                ["settings", "encryptionKeys", SecretId] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_delete_secret/2,
                     [SecretId]};
                ["settings", "encryptionKeys", SecretId, "historicalKeys", Id] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_delete_historical_key/3,
                     [SecretId, Id]};
                ["settings", "jwt"] ->
                    {{[admin, security], write},
                     fun menelaus_web_jwt:handle_settings/2, ['DELETE']};
                ["couchBase" | _] -> {no_check_disallow_anonymous,
                                      fun menelaus_pluggable_ui:proxy_req/4,
                                      ["couchBase",
                                       drop_prefix(mochiweb_request:get(raw_path, Req)),
                                       Plugins]};
                ["xdcr", "c2cCommunications" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, c2c_communications], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "connectionPreCheck" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "sourceClusters" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "internalSettings" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr" | _RestPath] ->
                    %% Pass the raw path so all information, e.g. query
                    %% parameters, etc, are included.
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[admin, internal], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["_metakv" | _] ->
                    {{[admin, metakv], all}, fun menelaus_metakv:handle_delete/2, [Path]};
                ["_metakv2" | _] ->
                    {{[admin, internal, metakv2], write},
                     fun menelaus_metakv2:handle_delete/2, [Path]};
                [?PLUGGABLE_UI, RestPrefix | _] ->
                    {no_check_disallow_anonymous,
                     fun (PReq) ->
                             menelaus_pluggable_ui:proxy_req(
                               RestPrefix,
                               drop_rest_prefix(mochiweb_request:get(raw_path, Req)),
                               Plugins, PReq)
                     end};
                ["node", "controller", "setupAlternateAddresses", "external"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_node_altaddr_external_delete/1};
                _ ->
                    {done, reply_text(Req, "Object Not Found", 404)}
            end;
        'PUT' ->
            case PathTokens of
                ["pools", "default", "serverGroups"] ->
                    {{[server_groups], write},
                     fun menelaus_web_groups:handle_server_groups_put/1};
                ["pools", "default", "serverGroups", GroupUUID] ->
                    {{[server_groups], write},
                     fun menelaus_web_groups:handle_server_group_update/2, [GroupUUID]};
                ["settings", "rbac", "users", UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_put_user/3, ["external", UserId]};
                ["settings", "rbac", "users", Domain, UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_put_user/3, [Domain, UserId]};
                ["settings", "rbac", "groups", GroupId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_put_group/2, [GroupId]};
                ["settings", "rbac", "profiles", "@self"] ->
                    {no_check,
                     fun menelaus_web_rbac:handle_put_profile/2, [self]};
                ["settings", "rbac", "profiles", Domain, UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_put_profile/2,
                     [{UserId, Domain}]};
                ["settings", "rbac", "backup"] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_backup_restore/1};
                ["settings", "encryptionKeys", SecretId] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_put_secret/2, [SecretId]};
                ["settings", "encryptionKeys", SecretId, "test"] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_web_secrets:handle_test_put_secret/2,
                     [SecretId]};
                ["pools", "default", "buckets", Id, "scopes"] ->
                    {{[{collection, [Id, any, any]}, collections], write},
                     fun menelaus_web_collections:handle_set_manifest/2, [Id]};
                ["couchBase" | _] ->
                    {no_check_disallow_anonymous,
                     fun menelaus_pluggable_ui:proxy_req/4,
                     ["couchBase",
                      drop_prefix(mochiweb_request:get(raw_path, Req)),
                      Plugins]};
                ["xdcr", "c2cCommunications" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, c2c_communications], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "connectionPreCheck" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "sourceClusters" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr", "internalSettings" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[xdcr, admin], all},
                     fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["xdcr" | _RestPath] ->
                    XdcrPath = mochiweb_request:get(raw_path, Req),
                    {{[admin, internal], all}, fun goxdcr_rest:proxy/2, [XdcrPath]};
                ["_metakv" | _] ->
                    {{[admin, metakv], all}, fun menelaus_metakv:handle_put/2, [Path]};
                ["_metakv2" | _] ->
                    {{[admin, internal, metakv2], write},
                     fun menelaus_metakv2:handle_put/2, [Path]};
                [?PLUGGABLE_UI, RestPrefix | _] ->
                    {no_check_disallow_anonymous,
                     fun (PReq) ->
                             menelaus_pluggable_ui:proxy_req(
                               RestPrefix,
                               drop_rest_prefix(mochiweb_request:get(raw_path, Req)),
                               Plugins, PReq)
                     end};
                ["node", "controller", "setupAlternateAddresses", "external"] ->
                    {{[admin, setup], write},
                     fun menelaus_web_node:handle_node_altaddr_external/1};
                ["settings", "jwt"] ->
                    {{[admin, security], write},
                     fun menelaus_web_jwt:handle_settings/2, ['PUT']};
                _ ->
                    {done, reply_text(Req, "Object Not Found", 404)}
            end;
        "PATCH" ->
            case PathTokens of
                ["settings", "rbac", "users", "local", UserId] ->
                    {when_morpheus({[admin, users], write},
                                   {[admin, security], write}),
                     fun menelaus_web_rbac:handle_patch_user/2,
                     [UserId]};
                ["pools", "default", "buckets", Id, "scopes", Scope,
                 "collections", CollectionId] ->
                    {{[{collection, [Id, Scope, CollectionId]}, collections],
                      write},
                     fun menelaus_web_collections:handle_patch_collection/4,
                     [Id, Scope, CollectionId]};
                _ ->
                    {done, reply_text(Req, "Object Not Found", 404)}
            end;
        "RPCCONNECT" ->
            case PathTokens of
                ["auth", Version, Label] ->
                    {{[admin, internal], all},
                     fun menelaus_cbauth:handle_rpc_connect/3,
                     [Version, Label]};
                _ ->
                    {{[admin, internal], all},
                     fun json_rpc_connection_sup:handle_rpc_connect/1}
            end;
        _ ->
            {done, reply_text(Req, "Method Not Allowed", 405)}
    end.

log_client_error(Req) ->
    Body = case mochiweb_request:recv_body(Req) of
               undefined ->
                   "(nothing)";
               B ->
                   binary_to_list(B)
           end,

    User = case menelaus_auth:get_user_id(Req) of
               [] ->
                   "(anonymous)";
               UserName ->
                   UserName
           end,

    ?MENELAUS_WEB_LOG(
       ?UI_SIDE_ERROR_REPORT,
       "Client-side error-report for user ~p on node ~p:~nUser-Agent:~s~n~s",
       [ns_config_log:tag_user_name(User),
        node(), mochiweb_request:get_header_value("user-agent", Req), Body]),
    reply_ok(Req, "text/plain", []).

serve_ui(Req, IsSSL, F, Args) ->
    IsDisabledKey = case IsSSL of
                        true ->
                            disable_ui_over_https;
                        false ->
                            disable_ui_over_http
                    end,
    case ns_config:read_key_fast(IsDisabledKey, false) of
        true ->
            reply(Req, 404);
        false ->
            apply(F, Args ++ [Req])
    end.

serve_ui_env(Req) ->
    %% UI env values are expected to be unfolded proplists
    UIEnvDefault = lists:ukeysort(1, misc:get_env_default(ui_env, [])),
    GlobalUIEnv = lists:ukeysort(1, ns_config:read_key_fast(ui_env, [])),
    NodeSpecificUIEnv = lists:ukeysort(1, ns_config:read_key_fast({node, node(), ui_env}, [])),
    menelaus_util:reply_json(Req,
                             {lists:ukeymerge(1, NodeSpecificUIEnv,
                                              lists:ukeymerge(1, GlobalUIEnv, UIEnvDefault))}).

handle_serve_file(AppRoot, Path, MaxAge, Req) ->
    menelaus_util:serve_file(
        Req, Path, AppRoot,
        [{"Cache-Control", lists:concat(["max-age=", MaxAge])}]).

loop_inner(Req, Info, Path, PathTokens) ->
    perform_action(Req, get_action(Req, Info, Path, PathTokens)).

-spec get_bucket_id(rbac_permission() | no_check) -> bucket_name() | false.
get_bucket_id(no_check) ->
    false;
get_bucket_id({[{bucket, Bucket} | _], _}) when Bucket =/= any ->
    Bucket;
get_bucket_id({[{collection, [Bucket, _, _]} | _], _}) when Bucket =/= any ->
    Bucket;
get_bucket_id(_) ->
    false.

-spec perform_action(mochiweb_request(), action()) -> term().
perform_action(_Req, {done, RV}) ->
    RV;
perform_action(Req, {ui, IsSSL, Fun}) ->
    perform_action(Req, {ui, IsSSL, Fun, []});
perform_action(Req, {ui, IsSSL, Fun, Args}) ->
    serve_ui(Req, IsSSL, Fun, Args);
perform_action(Req, {Permission, Fun}) ->
    perform_action(Req, {Permission, Fun, []});
perform_action(Req, {Permission, Fun, Args}) ->
    check_uuid(Req),
    {RV, NewReq} = menelaus_auth:verify_rest_auth(Req, Permission),
    case RV of
        allowed ->
            check_bucket_uuid(get_bucket_id(Permission), NewReq),
            erlang:apply(Fun, Args ++ [NewReq]);
        auth_failure ->
            ns_audit:auth_failure(NewReq),
            ns_server_stats:notify_counter(<<"rest_request_auth_failure">>),
            menelaus_util:require_auth(NewReq);
        forbidden when Permission == local ->
            ns_audit:access_forbidden(NewReq),
            ns_server_stats:notify_counter(<<"rest_request_access_forbidden">>),
            menelaus_util:reply_json(NewReq, <<"Forbidden">>, 403);
        forbidden ->
            ns_audit:access_forbidden(NewReq),
            ns_server_stats:notify_counter(<<"rest_request_access_forbidden">>),
            menelaus_util:reply_json(
              NewReq, menelaus_web_rbac:forbidden_response([Permission]), 403);
        password_expired ->
            menelaus_util:reply_password_expired(NewReq);
        temporary_failure ->
            Msg = <<"Temporary error occurred. Please try again later.">>,
            menelaus_util:reply_json(NewReq, Msg, 503)
    end.

check_uuid(Req) ->
    ReqUUID0 = proplists:get_value("uuid", mochiweb_request:parse_qs(Req)),
    case ReqUUID0 =/= undefined of
        true ->
            ReqUUID = list_to_binary(ReqUUID0),
            UUID = get_uuid(),
            %%
            %% get_uuid() will return empty UUID if the system is not
            %% provisioned yet. If ReqUUID is also empty then we let
            %% the request go through. But, if ReqUUID is not-empty
            %% and UUID is empty then we will retrun 404 error.
            %%
            ReqUUID =:= UUID orelse
                menelaus_util:web_exception(
                  404, "Cluster uuid does not match the requested.\r\n");
        false ->
            ok
    end.

check_bucket_uuid(false, _Req) ->
    ok;
check_bucket_uuid(Bucket, Req) ->
    case ns_bucket:uuid(Bucket, direct) of
        not_present ->
            ?log_debug("Attempt to access non existent bucket ~p", [Bucket]),
            ns_server_stats:notify_counter({<<"rest_request_failure">>,
                                            [{type, bucket_access},
                                             {code, 404}]}),
            menelaus_util:web_exception(404, menelaus_util:reply_text_404());
        UUID ->
            ReqUUID = proplists:get_value("bucket_uuid",
                                          mochiweb_request:parse_qs(Req)),
            case ReqUUID =:= undefined orelse
                list_to_binary(ReqUUID) =:= UUID of
                true ->
                    ok;
                false ->
                    ns_server_stats:notify_counter({<<"rest_request_failure">>,
                                                    [{type, bucket_access},
                                                     {code, 404}]}),
                    menelaus_util:web_exception(
                      404, "Bucket uuid does not match the requested.\r\n")
            end
    end.

%% Returns an UUID from the ns_config
%% cluster UUID is set in ns_config only when the system is provisioned.
get_uuid() ->
    case ns_config:search(uuid) of
        false ->
            <<>>;
        {value, Uuid2} ->
            Uuid2
    end.

%% log categorizing, every logging line should be unique, and most
%% should be categorized

ns_log_cat(0013) ->
    crit;
ns_log_cat(0019) ->
    warn;
ns_log_cat(?START_FAIL) ->
    crit;
ns_log_cat(?NODE_EJECTED) ->
    info;
ns_log_cat(?UI_SIDE_ERROR_REPORT) ->
    warn.

ns_log_code_string(0013) ->
    "node join failure";
ns_log_code_string(0019) ->
    "server error during request processing";
ns_log_code_string(?START_FAIL) ->
    "failed to start service";
ns_log_code_string(?NODE_EJECTED) ->
    "node was ejected";
ns_log_code_string(?UI_SIDE_ERROR_REPORT) ->
    "client-side error report".

ns_log_prepare_message(?UI_SIDE_ERROR_REPORT, Msg) ->
    Key = {?MODULE, ns_log_re},
    Re =
        case erlang:get(Key) of
            undefined ->
                {ok, R} = re:compile("</?ud>"),
                erlang:put(Key, R),
                R;
            R ->
                R
        end,
    re:replace(Msg, Re, "", [global, {return, list}]);
ns_log_prepare_message(_, Msg) ->
    Msg.

nth_path_tail(Path, N) when N > 0 ->
    nth_path_tail(path_tail(Path), N-1);
nth_path_tail(Path, 0) ->
    Path.

path_tail([$/|[$/|_] = Path]) ->
    path_tail(Path);
path_tail([$/|Path]) ->
    Path;
path_tail([_|Rest]) ->
    path_tail(Rest);
path_tail([]) ->
    [].

drop_rest_prefix("/" ++ Path) ->
    [$/ | nth_path_tail(Path, 2)].

drop_prefix("/" ++ Path) ->
    [$/ | nth_path_tail(Path, 1)].

response_time_ms(Req) ->
    Now = erlang:monotonic_time(millisecond),
    Time = mochiweb_request:get_meta(menelaus_start_time, undefined, Req),
    Now - Time.

-ifdef(TEST).
parse_http_path_uri_test() ->
    ?assertEqual("fakePrefix/diag/eval/",
                 parse_path("//fakePrefix/diag/eval/")),
    ?assertEqual("fakePrefix/diag/eval/",
                 parse_path("///////fakePrefix/diag/eval/")),
    ?assertEqual("fake/path", parse_path("/fake/path")),
    ?assertEqual({web_exception, 400, "Bad Request", []},
                 catch(parse_path(""))),
    ?assertEqual({web_exception, 400, "Bad Request", []},
                 catch(parse_path("\\/\/"))).
-endif.
