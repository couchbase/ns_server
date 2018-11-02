%% @author Couchbase <info@couchbase.com>
%% @copyright 2013-2018 Couchbase, Inc.
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
-module(ns_ports_setup).

-include("ns_common.hrl").

-export([start/0, setup_body_tramp/0,
         restart_port_by_name/1, restart_memcached/0,
         restart_xdcr_proxy/0, sync/0, create_erl_node_spec/4,
         shutdown_ports/0]).

start() ->
    proc_lib:start_link(?MODULE, setup_body_tramp, []).

sync() ->
    gen_server:call(?MODULE, sync, infinity).

shutdown_ports() ->
    gen_server:call(?MODULE, shutdown_ports, infinity).

%% ns_config announces full list as well which we don't need
is_useless_event(List) when is_list(List) ->
    true;
%% config changes for other nodes is quite obviously irrelevant
is_useless_event({{node, N, _}, _}) when N =/= node() ->
    true;
is_useless_event(_) ->
    false.

setup_body_tramp() ->
    misc:delaying_crash(1000, fun setup_body/0).

setup_body() ->
    Self = self(),
    erlang:register(?MODULE, Self),
    proc_lib:init_ack({ok, Self}),
    ns_pubsub:subscribe_link(ns_config_events,
                             fun (Event) ->
                                     case is_useless_event(Event) of
                                         false ->
                                             Self ! check_children_update;
                                         _ ->
                                             []
                                     end
                             end),
    ns_pubsub:subscribe_link(user_storage_events,
                             fun (_) ->
                                     Self ! check_children_update
                             end),
    Children = dynamic_children(normal),
    set_children_and_loop(Children, undefined, normal).

restart_memcached() ->
    {ok, _} = restart_port_by_name(memcached),
    ok.

restart_xdcr_proxy() ->
    case restart_port_by_name(xdcr_proxy) of
        {ok, _} ->
            ok;
        Error ->
            Error
    end.

restart_port_by_name(Name) ->
    ns_ports_manager:restart_port_by_name(ns_server:get_babysitter_node(), Name).

set_children(Children, Sup) ->
    Pid = ns_ports_manager:set_dynamic_children(ns_server:get_babysitter_node(), Children),
    case Sup of
        undefined ->
            {is_pid, true, Pid} = {is_pid, erlang:is_pid(Pid), Pid},
            ?log_debug("Monitor ns_child_ports_sup ~p", [Pid]),
            remote_monitors:monitor(Pid);
        Pid ->
            ok;
        _ ->
            ?log_debug("ns_child_ports_sup was restarted on babysitter node. Exit. Old pid = ~p, new pid = ~p",
                       [Sup, Pid]),
            erlang:error(child_ports_sup_died)
    end,
    Pid.

set_children_and_loop(Children, Sup, Status) ->
    NewSup = set_children(Children, Sup),
    children_loop(Children, NewSup, Status).

children_loop(Children, Sup, Status) ->
    proc_lib:hibernate(erlang, apply, [fun children_loop_continue/3, [Children, Sup, Status]]).

children_loop_continue(Children, Sup, Status) ->
    receive
        {'$gen_call', From, shutdown_ports} ->
            ?log_debug("Send shutdown to all go ports"),
            NewStatus = shutdown,
            NewChildren = dynamic_children(NewStatus),
            NewSup = set_children(NewChildren, Sup),
            gen_server:reply(From, ok),
            children_loop(NewChildren, NewSup, NewStatus);
        check_children_update ->
            do_children_loop_continue(Children, Sup, Status);
        {'$gen_call', From, sync} ->
            gen_server:reply(From, ok),
            children_loop(Children, Sup, Status);
        {remote_monitor_down, Sup, unpaused} ->
            ?log_debug("Remote monitor ~p was unpaused after node name change. Restart loop.", [Sup]),
            set_children_and_loop(dynamic_children(Status), undefined, Status);
        {remote_monitor_down, Sup, Reason} ->
            ?log_debug("ns_child_ports_sup ~p died on babysitter node with ~p. Restart.", [Sup, Reason]),
            erlang:error({child_ports_sup_died, Sup, Reason});
        X ->
            erlang:error({unexpected_message, X})
    after 0 ->
            erlang:error(expected_some_message)
    end.

do_children_loop_continue(Children, Sup, Status) ->
    %% this sets bound on frequency of checking of port_servers
    %% configuration updates. NOTE: this thing also depends on other
    %% config variables. So we're forced to react on any config
    %% change
    timer:sleep(50),
    misc:flush(check_children_update),
    case dynamic_children(Status) of
        Children ->
            children_loop(Children, Sup, Status);
        NewChildren ->
            set_children_and_loop(NewChildren, Sup, Status)
    end.

create_erl_node_spec(Type, Args, EnvArgsVar, ErlangArgs) ->
    PathArgs = ["-pa"] ++ lists:reverse(code:get_path()),
    EnvArgsTail = [{K, V}
                   || {K, V} <- application:get_all_env(ns_server),
                      case atom_to_list(K) of
                          "error_logger" ++ _ -> true;
                          "path_config" ++ _ -> true;
                          "dont_suppress_stderr_logger" -> true;
                          "loglevel_" ++ _ -> true;
                          "disk_sink_opts" -> true;
                          "ssl_ciphers" -> true;
                          "net_kernel_verbosity" -> true;
                          "ipv6" -> true;
                          _ -> false
                      end],
    EnvArgs = Args ++ EnvArgsTail,

    AllArgs = PathArgs ++ ErlangArgs,

    ErlPath = filename:join([hd(proplists:get_value(root, init:get_arguments())),
                             "bin", "erl"]),

    Env0 = case os:getenv("ERL_CRASH_DUMP_BASE") of
               false ->
                   [];
               Base ->
                   [{"ERL_CRASH_DUMP", Base ++ "." ++ atom_to_list(Type)}]
           end,

    Env = [{EnvArgsVar, misc:inspect_term(EnvArgs)} | Env0],

    Options0 = [use_stdio, {env, Env}],
    Options =
        case misc:get_env_default(dont_suppress_stderr_logger, false) of
            true ->
                [ns_server_no_stderr_to_stdout | Options0];
            false ->
                Options0
        end,

    {Type, ErlPath, AllArgs, Options}.

dynamic_children(Mode) ->
    Config = ns_config:get(),

    Specs = do_dynamic_children(Mode, Config),
    expand_specs(lists:flatten(Specs), Config).

do_dynamic_children(shutdown, Config) ->
    [memcached_spec(),
     saslauthd_port_spec(Config)];
do_dynamic_children(normal, Config) ->
    [memcached_spec(),
     saslauthd_port_spec(Config)] ++
        build_goport_specs(Config).

expand_specs(Specs, Config) ->
    [expand_args(S, Config) || S <- Specs].

find_executable(Name) ->
    K = list_to_atom("ns_ports_setup-" ++ Name ++ "-available"),
    case erlang:get(K) of
        undefined ->
            Cmd = path_config:component_path(bin, Name),
            RV = os:find_executable(Cmd),
            erlang:put(K, RV),
            RV;
        V ->
            V
    end.

build_go_env_vars(Config, RPCService) ->
    GoTraceBack0 = ns_config:search(ns_config:latest(), gotraceback, <<"single">>),
    GoTraceBack = binary_to_list(GoTraceBack0),
    [{"GOTRACEBACK", GoTraceBack} | build_cbauth_env_vars(Config, RPCService)].

build_tls_config_env_var(Config) ->
    Ciphers =
        lists:map(fun (Strength) when is_atom(Strength) -> Strength;
                      (Code) -> iolist_to_binary(["0x", misc:hexify(Code)])
                  end, ns_ssl_services_setup:supported_ciphers(cbauth, Config)),
    [{"CBAUTH_TLS_CONFIG",
      binary_to_list(
        ejson:encode(
          {[{minTLSVersion, ns_ssl_services_setup:ssl_minimum_protocol(Config)},
            {ciphers, Ciphers}]}))}].

build_cbauth_env_vars(Config, RPCService) ->
    true = (RPCService =/= undefined),
    RestPort = service_ports:get_port(rest_port, Config),
    User = mochiweb_util:quote_plus(ns_config_auth:get_user(special)),
    Password = mochiweb_util:quote_plus(ns_config_auth:get_password(special)),
    URL = misc:local_url(RestPort, atom_to_list(RPCService), [{user_info, {User, Password}}]),
    [{"CBAUTH_REVRPC_URL", URL}].

expand_args({Name, Cmd, ArgsIn, OptsIn}, Config) ->
    %% Expand arguments
    Args0 = lists:map(fun ({Format, Keys}) ->
                              format(Config, Name, Format, Keys);
                          (X) -> X
                      end,
                      ArgsIn),
    Args = Args0 ++ ns_config:search(Config, {node, node(), {Name, extra_args}}, []),
    %% Expand environment variables within OptsIn
    Opts = lists:map(
             fun ({env, Env}) ->
                     {env, lists:map(
                             fun ({Var, {Format, Keys}}) ->
                                     {Var, format(Config, Name, Format, Keys)};
                                 (X) -> X
                             end, Env)};
                 (X) -> X
             end, OptsIn),
    {Name, Cmd, Args, Opts}.

format(Config, Name, Format, Keys) ->
    Values = lists:map(fun ({Module, FuncName, Args}) -> erlang:apply(Module, FuncName, Args);
                           ({Key, SubKey}) -> ns_config:search_node_prop(Config, Key, SubKey);
                           (Key) -> ns_config:search_node_prop(Config, Name, Key)
                       end, Keys),
    lists:flatten(io_lib:format(Format, Values)).

build_https_args(PortName, PortArg, CertArg, KeyArg, Config) ->
    build_https_args(PortName, PortArg, "", CertArg, KeyArg, Config).

build_https_args(PortName, PortArg, PortPrefix, CertArg, KeyArg, Config) ->
    case service_ports:get_port(PortName, Config) of
        undefined ->
            [];
        Port ->
            [PortArg ++ "=" ++ PortPrefix ++ integer_to_list(Port),
             CertArg ++ "=" ++ ns_ssl_services_setup:memcached_cert_path(),
             KeyArg ++ "=" ++ ns_ssl_services_setup:memcached_key_path()]
    end.

-record(def, {id, exe, service, rpc, log, tls = false}).

goport_defs() ->
    [#def{id = indexer,
          exe = "indexer",
          service = index,
          rpc = index,
          log = ?INDEXER_LOG_FILENAME},
     #def{id = projector,
          exe = "projector",
          service = kv,
          rpc = projector,
          log = ?PROJECTOR_LOG_FILENAME},
     #def{id = goxdcr,
          exe = "goxdcr",
          rpc = goxdcr,
          log = ?GOXDCR_LOG_FILENAME},
     #def{id = 'query',
          exe = "cbq-engine",
          service = n1ql,
          rpc = 'cbq-engine',
          log = ?QUERY_LOG_FILENAME,
          tls = true},
     #def{id = fts,
          exe = "cbft",
          service = fts,
          rpc = fts,
          log = ?FTS_LOG_FILENAME,
          tls = true},
     #def{id = cbas,
          exe = "cbas",
          service = cbas,
          rpc = cbas,
          log = ?CBAS_LOG_FILENAME},
     #def{id = eventing,
          exe = "eventing-producer",
          service = eventing,
          rpc = eventing,
          log = ?EVENTING_LOG_FILENAME,
          tls = true},
     #def{id = example,
          exe = "cache-service",
          service = example,
          rpc = example}].

build_goport_spec(#def{id = SpecId,
                       exe = Executable,
                       service = Service,
                       rpc = RPCService,
                       log = Log,
                       tls = Tls}, Config) ->
    Cmd = find_executable(Executable),
    NodeUUID = ns_config:search(Config, {node, node(), uuid}, false),
    case Cmd =/= false andalso
        NodeUUID =/= false andalso
        (Service =:= undefined orelse
         ns_cluster_membership:should_run_service(Config, Service, node())) of
        false ->
            [];
        _ ->
            EnvVars = build_go_env_vars(Config, RPCService),
            EnvVars1 = case Tls of
                           true ->
                               EnvVars ++ build_tls_config_env_var(Config);
                           false ->
                               EnvVars
                       end,
            Args = goport_args(SpecId, Config, Cmd, NodeUUID),
            [{SpecId, Cmd, Args,
              [via_goport, exit_status, stderr_to_stdout, {env, EnvVars1}] ++
                  [{log, Log} || Log =/= undefined]}]
    end.

build_goport_specs(Config) ->
    [build_goport_spec(Def, Config) || Def <- goport_defs()].

goport_args('query', Config, _Cmd, _NodeUUID) ->
    RestPort = service_ports:get_port(rest_port, Config),
    DataStoreArg = "--datastore=" ++ misc:local_url(RestPort, []),
    CnfgStoreArg = "--configstore=" ++ misc:local_url(RestPort, []),
    HttpArg = "--http=:" ++
        integer_to_list(service_ports:get_port(query_port, Config, node())),
    EntArg = "--enterprise=" ++
        atom_to_list(cluster_compat_mode:is_enterprise()),
    Ipv6 = "--ipv6=" ++ atom_to_list(misc:is_ipv6()),

    HttpsArgs = build_https_args(ssl_query_port, "--https", ":",
                                 "--certfile", "--keyfile", Config),
    [DataStoreArg, HttpArg, CnfgStoreArg, EntArg, Ipv6] ++ HttpsArgs;

goport_args(projector, Config, _Cmd, _NodeUUID) ->
    %% Projector is a component that is required by 2i
    ProjectorPort = service_ports:get_port(projector_port, Config),
    RestPort = service_ports:get_port(rest_port, Config),
    LocalMemcachedPort = service_ports:get_port(memcached_port, Config),
    MinidumpDir = path_config:minidump_dir(),

    ["-kvaddrs=" ++ misc:local_url(LocalMemcachedPort, [no_scheme]),
     "-adminport=:" ++ integer_to_list(ProjectorPort),
     "-diagDir=" ++ MinidumpDir,
     "-ipv6=" ++ atom_to_list(misc:is_ipv6()),
     misc:local_url(RestPort, [no_scheme])];

goport_args(goxdcr, Config, _Cmd, _NodeUUID) ->
    AdminPort = "-sourceKVAdminPort=" ++
        integer_to_list(service_ports:get_port(rest_port, Config)),
    XdcrRestPort = "-xdcrRestPort=" ++
        integer_to_list(
          ns_config:search(Config, {node, node(), xdcr_rest_port}, 9998)),
    IsEnterprise = "-isEnterprise=" ++
        atom_to_list(cluster_compat_mode:is_enterprise()),
    IsIpv6 = "-ipv6=" ++ atom_to_list(misc:is_ipv6()),
    [AdminPort, XdcrRestPort, IsEnterprise, IsIpv6];

goport_args(indexer, Config, _Cmd, NodeUUID) ->
    RestPort = service_ports:get_port(rest_port, Config),
    AdminPort = service_ports:get_port(indexer_admin_port, Config),
    ScanPort = service_ports:get_port(indexer_scan_port, Config),
    HttpPort = service_ports:get_port(indexer_http_port, Config),
    StInitPort = service_ports:get_port(indexer_stinit_port, Config),
    StCatchupPort = service_ports:get_port(indexer_stcatchup_port,
                                                   Config),
    StMaintPort = service_ports:get_port(indexer_stmaint_port, Config),
    {ok, IdxDir} = ns_storage_conf:this_node_ixdir(),
    IdxDir2 = filename:join(IdxDir, "@2i"),
    MinidumpDir = path_config:minidump_dir(),
    HttpsArgs = build_https_args(indexer_https_port, "--httpsPort",
                                 "--certFile", "--keyFile", Config),

    ["-vbuckets=" ++ integer_to_list(ns_bucket:get_num_vbuckets()),
     "-cluster=" ++ misc:local_url(RestPort, [no_scheme]),
     "-adminPort=" ++ integer_to_list(AdminPort),
     "-scanPort=" ++ integer_to_list(ScanPort),
     "-httpPort=" ++ integer_to_list(HttpPort),
     "-streamInitPort=" ++ integer_to_list(StInitPort),
     "-streamCatchupPort=" ++ integer_to_list(StCatchupPort),
     "-streamMaintPort=" ++ integer_to_list(StMaintPort),
     "-storageDir=" ++ IdxDir2,
     "-diagDir=" ++ MinidumpDir,
     "-nodeUUID=" ++ NodeUUID,
     "-ipv6=" ++ atom_to_list(misc:is_ipv6()),
     "-isEnterprise=" ++ atom_to_list(cluster_compat_mode:is_enterprise())] ++ HttpsArgs;

goport_args(fts, Config, _Cmd, NodeUUID) ->
    NsRestPort = service_ports:get_port(rest_port, Config),
    FtRestPort = service_ports:get_port(fts_http_port, Config),
    {ok, IdxDir} = ns_storage_conf:this_node_ixdir(),
    FTSIdxDir = filename:join(IdxDir, "@fts"),
    case misc:ensure_writable_dir(FTSIdxDir) of
        ok ->
            ok;
        _ ->
            ?log_debug("Service fts's directory (~p) is not writable "
                       "on node ~p", [FTSIdxDir, node()])
    end,

    {_, Host} = misc:node_name_host(node()),
    BindHttp = io_lib:format("~s:~b,~s:~b",
                             [misc:maybe_add_brackets(Host), FtRestPort,
                              misc:inaddr_any([url]),
                              FtRestPort]),
    BindHttps =
        build_https_args(fts_ssl_port, "-bindHttps", ":",
                         "-tlsCertFile", "-tlsKeyFile", Config),
    {ok, FTSMemoryQuota} = memory_quota:get_quota(Config, fts),
    MaxReplicasAllowed = case cluster_compat_mode:is_enterprise() of
                             true -> 3;
                             false -> 0
                         end,
    BucketTypesAllowed = case cluster_compat_mode:is_enterprise() of
                             true -> "membase:ephemeral";
                             false -> "membase"
                         end,
    Options = "startCheckServer=skip," ++
        "slowQueryLogTimeout=5s," ++
        "defaultMaxPartitionsPerPIndex=171," ++
        "bleveMaxResultWindow=10000," ++
        "failoverAssignAllPrimaries=false," ++
        "hideUI=true," ++
        "cbaudit=" ++ atom_to_list(cluster_compat_mode:is_enterprise()) ++ "," ++
        "ipv6=" ++ atom_to_list(misc:is_ipv6()) ++ "," ++
        "ftsMemoryQuota=" ++ integer_to_list(FTSMemoryQuota * 1024000) ++ "," ++
        "maxReplicasAllowed=" ++ integer_to_list(MaxReplicasAllowed) ++ "," ++
        "bucketTypesAllowed=" ++ BucketTypesAllowed ++ "," ++
        "http2=" ++ atom_to_list(cluster_compat_mode:is_enterprise()) ++ "," ++
        "vbuckets=" ++ integer_to_list(ns_bucket:get_num_vbuckets()),
    [
     "-cfg=metakv",
     "-uuid=" ++ NodeUUID,
     "-server=" ++ misc:local_url(NsRestPort, []),
     "-bindHttp=" ++ BindHttp,
     "-dataDir=" ++ FTSIdxDir,
     "-tags=feed,janitor,pindex,queryer,cbauth_service",
     "-auth=cbauth",
     "-extra=" ++ io_lib:format("~s:~b", [Host, NsRestPort]),
     "-options=" ++ Options
    ] ++ BindHttps;

goport_args(eventing, Config, _Cmd, NodeUUID) ->
    EventingAdminPort = service_ports:get_port(eventing_http_port,
                                               Config),
    LocalMemcachedPort = service_ports:get_port(memcached_port, Config),
    RestPort = service_ports:get_port(rest_port, Config),
    DebugPort = service_ports:get_port(eventing_debug_port, Config),

    {ok, IdxDir} = ns_storage_conf:this_node_ixdir(),
    EventingDir = filename:join(IdxDir, "@eventing"),

    MinidumpDir = path_config:minidump_dir(),

    BindHttps = build_https_args(eventing_https_port, "-adminsslport",
                                 "-certfile", "-keyfile", Config),

    ["-adminport=" ++ integer_to_list(EventingAdminPort),
     "-dir=" ++ EventingDir,
     "-kvport=" ++ integer_to_list(LocalMemcachedPort),
     "-restport=" ++ integer_to_list(RestPort),
     "-uuid=" ++ binary_to_list(NodeUUID),
     "-diagdir=" ++ MinidumpDir,
     "-ipv6=" ++ atom_to_list(misc:is_ipv6()),
     "-debugPort=" ++ integer_to_list(DebugPort),
     "-vbuckets=" ++ integer_to_list(ns_bucket:get_num_vbuckets())] ++ BindHttps;

goport_args(cbas, Config, Cmd, NodeUUID) ->
    NsRestPort = service_ports:get_port(rest_port, Config),
    HttpPort = service_ports:get_port(cbas_http_port, Config),
    AdminPort = service_ports:get_port(cbas_admin_port, Config),
    CCHttpPort = service_ports:get_port(cbas_cc_http_port, Config),
    CCClusterPort = service_ports:get_port(cbas_cc_cluster_port,
                                           Config),
    CCClientPort = service_ports:get_port(cbas_cc_client_port, Config),
    ConsolePort = service_ports:get_port(cbas_console_port, Config),
    ClusterPort = service_ports:get_port(cbas_cluster_port, Config),
    DataPort = service_ports:get_port(cbas_data_port, Config),
    ResultPort = service_ports:get_port(cbas_result_port, Config),
    MessagingPort = service_ports:get_port(cbas_messaging_port, Config),
    MetadataCallbackPort = service_ports:get_port(
                             cbas_metadata_callback_port, Config),
    ReplicationPort = service_ports:get_port(cbas_replication_port,
                                             Config),
    MetadataPort = service_ports:get_port(cbas_metadata_port, Config),
    ParentPort = service_ports:get_port(cbas_parent_port, Config),
    DebugPort = service_ports:get_port(cbas_debug_port, Config),

    CBASDirs = [filename:join([Token], "@analytics") ||
                   Token <- ns_storage_conf:this_node_cbas_dirs()],
    case misc:ensure_writable_dirs(CBASDirs) of
        ok ->
            ok;
        _ ->
            ?log_debug("Service cbas's directories (~p) are not "
                       "writable on node ~p", [CBASDirs, node()])
    end,

    JavaHome = ns_storage_conf:this_node_java_home(),

    {ok, LogDir} = application:get_env(ns_server, error_logger_mf_dir),
    {_, Host} = misc:node_name_host(node()),
    HttpsOptions = build_https_args(cbas_ssl_port, "-bindHttpsPort",
                                    "-tlsCertFile", "-tlsKeyFile", Config),
    {ok, MemoryQuota} = memory_quota:get_quota(Config, cbas),
    [
     "-uuid=" ++ binary_to_list(NodeUUID),
     "-serverAddress=" ++ misc:localhost(),
     "-serverPort=" ++ integer_to_list(NsRestPort),
     "-bindHttpAddress=" ++ Host,
     "-bindHttpPort=" ++ integer_to_list(HttpPort),
     "-bindAdminPort=" ++ integer_to_list(AdminPort),
     "-cbasExecutable=" ++ Cmd,
     "-debugPort=" ++ integer_to_list(DebugPort),
     "-ccHttpPort=" ++ integer_to_list(CCHttpPort),
     "-ccClusterPort=" ++ integer_to_list(CCClusterPort),
     "-ccClientPort=" ++ integer_to_list(CCClientPort),
     "-consolePort=" ++ integer_to_list(ConsolePort),
     "-clusterPort=" ++ integer_to_list(ClusterPort),
     "-dataPort=" ++ integer_to_list(DataPort),
     "-resultPort=" ++ integer_to_list(ResultPort),
     "-messagingPort=" ++ integer_to_list(MessagingPort),
     "-metadataPort=" ++ integer_to_list(MetadataPort),
     "-metadataCallbackPort=" ++ integer_to_list(MetadataCallbackPort),
     "-memoryQuotaMb=" ++ integer_to_list(MemoryQuota),
     "-parentPort=" ++ integer_to_list(ParentPort),
     "-bindReplicationPort=" ++ integer_to_list(ReplicationPort),
     "-ipv6=" ++ atom_to_list(misc:is_ipv6()),
     "-logDir=" ++ LogDir
    ] ++
        ["-dataDir=" ++ Dir || Dir <- CBASDirs] ++
        ["-javaHome=" ++ JavaHome || JavaHome =/= undefined] ++
        HttpsOptions;

goport_args(example, Config, _Cmd, NodeUUID) ->
    Port = service_ports:get_port(rest_port, Config) + 20000,
    {_, Host} = misc:node_name_host(node()),
    ["-node-id", binary_to_list(NodeUUID),
     "-host", misc:join_host_port(Host, Port)].

saslauthd_port_spec(Config) ->
    Cmd = find_executable("saslauthd-port"),
    case Cmd =/= false of
        true ->
            [{saslauthd_port, Cmd, [],
              [use_stdio, exit_status, stderr_to_stdout,
               {env, build_go_env_vars(Config, saslauthd)}]}];
        _ ->
            []
    end.

memcached_spec() ->
    {memcached, path_config:component_path(bin, "memcached"),
     ["-C", {"~s", [{memcached, config_path}]}],
     [{env, [{"EVENT_NOSELECT", "1"},
             %% NOTE: bucket engine keeps this number of top keys
             %% per top-keys-shard. And number of shards is hard-coded to 8
             %%
             %% So with previous setting of 100 we actually got 800
             %% top keys every time. Even if we need just 10.
             %%
             %% See hot_keys_keeper.erl TOP_KEYS_NUMBER constant
             %%
             %% Because of that heavy sharding we cannot ask for
             %% very small number, which would defeat usefulness
             %% LRU-based top-key maintenance in memcached. 5 seems
             %% not too small number which means that we'll deal
             %% with 40 top keys.
             {"MEMCACHED_TOP_KEYS", "5"},
             {"CBSASL_PWFILE", {"~s", [{isasl, path}]}}]},
      use_stdio,
      stderr_to_stdout, exit_status,
      port_server_dont_start,
      stream]
    }.
