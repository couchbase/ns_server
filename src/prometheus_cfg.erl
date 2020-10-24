%% @author Couchbase <info@couchbase.com>
%% @copyright 2020 Couchbase, Inc.
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
-module(prometheus_cfg).

-behaviour(gen_server).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([start_link/0, authenticate/2, settings/0, wipe/0, storage_path/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-record(s, {cur_settings = [],
            specs = undefined,
            prometheus_port = undefined,
            reload_timer_ref = undefined,
            intervals_calc_timer_ref = undefined}).

-define(RELOAD_RETRY_PERIOD, 10000). %% in milliseconds
-define(DEFAULT_PROMETHEUS_TIMEOUT, 5000). %% in milliseconds
-define(USERNAME, "@prometheus").
-define(NS_TO_PROMETHEUS_USERNAME, "ns_server").
-define(DEFAULT_HIGH_CARD_SERVICES, [index, fts, kv, cbas, eventing]).
-define(MAX_SCRAPE_INTERVAL, 6*60*60). %% 6h, in seconds
-define(PROMETHEUS_SHUTDOWN_TIMEOUT, 20000). %% 20s, in milliseconds

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, Pid :: pid()} | ignore | {error, Error :: term()}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

settings() ->
    gen_server:call(?MODULE, settings).

default_settings() ->
    [{enabled, true},
     {retention_size, 1024}, %% in MB
     {retention_time, 365}, %% in days
     {wal_compression, false},
     {storage_path, "./stats_data"},
     {config_file, "prometheus.yml"},
     {log_file_name, "prometheus.log"},
     {prometheus_auth_enabled, true},
     {prometheus_auth_filename, ns_to_prometheus_filename()},
     {log_level, "debug"},
     {max_block_duration, 25}, %% in hours
     {scrape_interval, 10}, %% in seconds
     {scrape_timeout, 10}, %% in seconds
     {snapshot_timeout_msecs, 30000}, %% in milliseconds
     {token_file, "prometheus_token"},
     {query_max_samples, 200000},
     {intervals_calculation_period, 10*60*1000}, %% 10m
     {cbcollect_stats_dump_max_size, 1024*1024*1024}, %% 1GB, in bytes
     {cbcollect_stats_min_period, 14}, %% in days
     {average_sample_size, 3}, %% in bytes
     {services, [{S, [{high_cardinality_enabled, true}]}
                        || S <- ?DEFAULT_HIGH_CARD_SERVICES]},
     {external_prometheus_services, [{S, [{high_cardinality_enabled, true}]}
                                        || S <- ?DEFAULT_HIGH_CARD_SERVICES]},
     {prometheus_metrics_enabled, false},
     {prometheus_metrics_scrape_interval, 60}, %% in seconds
     {listen_addr_type, loopback}].

build_settings() -> build_settings(ns_config:get()).
build_settings(Config) ->
    AFamily = ns_config:search_node_with_default(Config, address_family, inet),
    Port = service_ports:get_port(prometheus_http_port, Config),
    LocalAddr = misc:localhost(AFamily, [url]),
    Services = ns_cluster_membership:node_services(Config, node()),
    Targets = lists:filtermap(
                fun (S) ->
                        case service_ports:get_port(get_service_port(S)) of
                            undefined -> false;
                            P -> {true, {S, misc:join_host_port(LocalAddr, P)}}
                        end
                end, [ns_server, xdcr | Services]),

    NsToPrometheusAuthInfo = ns_config:search_node_with_default(
                               Config, ns_to_prometheus_auth_info, []),
    {pass, Creds} = proplists:get_value(creds, NsToPrometheusAuthInfo,
                                        {pass, undefined}),

    %% Dynamic scrape intervals are used for high cardinality metrics endpoints
    %% where scrape intervals are not set explicitly.
    %% They are recalculated periodically based on the number of samples
    %% reported by each endpoint. The more samples are reported by a particular
    %% endpoint, the greater scrape interval is set for that endpoint.
    %% The goal is to maintain the sane size of cbcollect dump, which can grow
    %% quickly when too many stats are reported.
    %% Note that dynamic scrape intervals are "per-node" and "per-service".
    %% If services don't report thousands of metrics it's ok for this list to be
    %% empty, which means "use the default scrape interval".
    %% Example of non empty value is [{kv, 25}, {index, 30}], which means
    %% prometheus should use 25 second scrape interval for kv's high cardinality
    %% metrics collection, and 30 second scrape interval for index service
    %% high cardinality metrics collection.
    DynamicScrapeIntervals = ns_config:search_node_with_default(
                         Config, stats_scrape_dynamic_intervals, []),

    Settings =
        case Port == undefined orelse Creds == undefined of
            true ->
                ?log_debug("Prometheus is disabled because of insufficient "
                           "information in ns_config (may happen during node "
                           "rename)"),
                [{enabled, false},
                 {targets, Targets}]; %% Can be used to report metrics to
                                      %% external Prometheus even if local one
                                      %% is disabled
            false ->
                ns_config:search(Config, stats_settings, []) ++
                [{listen_port, Port},
                 {addr, misc:join_host_port(LocalAddr, Port)},
                 {prometheus_creds, Creds},
                 {targets, Targets},
                 {afamily, AFamily},
                 {dynamic_scrape_intervals, DynamicScrapeIntervals}]
        end,

    misc:update_proplist(default_settings(), Settings).

specs(Settings) ->
    Args = generate_prometheus_args(Settings),
    LogFile = proplists:get_value(log_file_name, Settings),
    {prometheus, path_config:component_path(bin, "prometheus"), Args,
     [via_goport, exit_status, stderr_to_stdout, {env, []},
      {log, LogFile}]}.

generate_prometheus_args(Settings) ->
    ConfigFile = prometheus_config_file(Settings),
    RetentionSize = integer_to_list(proplists:get_value(retention_size,
                                                        Settings)) ++ "MB",
    RetentionTime = integer_to_list(proplists:get_value(retention_time,
                                                        Settings)) ++ "d",
    Port = proplists:get_value(listen_port, Settings),
    AFamily = proplists:get_value(afamily, Settings),
    ListenAddress = case proplists:get_value(listen_addr_type, Settings) of
                        loopback -> misc:localhost(AFamily, [url]);
                        any -> misc:inaddr_any(AFamily, [url])
                    end,
    StoragePath = storage_path(Settings),
    MaxBlockDuration = integer_to_list(proplists:get_value(max_block_duration,
                                                           Settings)) ++ "h",
    LogLevel = proplists:get_value(log_level, Settings),
    QueryMaxSamples = integer_to_list(proplists:get_value(query_max_samples,
                                                          Settings)),
    AuthFile = proplists:get_value(prometheus_auth_filename, Settings),
    PromAuthArgs =
        case proplists:get_value(prometheus_auth_enabled, Settings) of
            true -> ["--web.basicauth.config", AuthFile];
            false -> []
        end,
    WalCompression = case proplists:get_bool(wal_compression, Settings) of
                         true ->
                             ["--storage.tsdb.wal-compression"];
                         false ->
                             []
                     end,

    ["--config.file", ConfigFile,
     "--web.enable-admin-api",
     "--web.enable-lifecycle", %% needed for hot cfg reload
     "--storage.tsdb.retention.size", RetentionSize,
     "--storage.tsdb.retention.time", RetentionTime,
     "--web.listen-address", misc:join_host_port(ListenAddress, Port),
     "--storage.tsdb.max-block-duration", MaxBlockDuration,
     "--storage.tsdb.path", StoragePath,
     "--log.level", LogLevel,
     "--query.max-samples", QueryMaxSamples,
     "--storage.tsdb.no-lockfile"] ++ PromAuthArgs ++ WalCompression.

authenticate(User, Pass) ->
    case ns_config:search_node(prometheus_auth_info) of
        {value, {User, {auth, AuthInfo}}} ->
            case menelaus_users:authenticate_with_info(AuthInfo, Pass) of
                true -> {ok, {User, stats_reader}};
                false -> false
            end;
        {value, {_, {auth, _}}} ->
            false;
        false ->
            false
    end.

%% This function should work even when prometheus_cfg is down
wipe() ->
    Settings = build_settings(),
    StoragePath = storage_path(Settings),
    Result = misc:rm_rf(StoragePath),
    case Result of
        ok ->
            ?log_info("Deleted stats directory (~s)", [StoragePath]);
        _ ->
            ?log_error("Failed to delete stats directory ~s: ~p",
                       [StoragePath, Result])
    end,
    Result.

storage_path(Settings) ->
    StoragePath = proplists:get_value(storage_path, Settings),
    path_config:component_path(data, StoragePath).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    EventHandler =
        fun ({stats_settings, _}) ->
                gen_server:cast(?MODULE, settings_updated);
            ({{node, Node, prometheus_http_port}, _}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({{node, Node, address_family}, _}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({{node, Node, services}, _}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({{node, Node, rest}, _}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            %% ns_to_prometheus_auth_info doesn't change normally.
            %% Nevertheless we need to subscribe to this key to correctly
            %% recover after node rename
            ({{node, Node, ns_to_prometheus_auth_info}, _})
                                                    when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({{node, Node, stats_scrape_dynamic_intervals}, _})
                                                    when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({rest, _}) ->
                gen_server:cast(?MODULE, settings_updated);
            (_) -> ok
        end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),
    process_flag(trap_exit,true),
    generate_ns_to_prometheus_auth_info(),
    Settings = build_settings(),
    ensure_prometheus_config(Settings),
    generate_prometheus_auth_info(Settings),
    State = apply_config(#s{cur_settings = Settings}),
    {ok, restart_intervals_calculation_timer(State)}.

handle_call(settings, _From, #s{cur_settings = Settings} = State) ->
    {reply, Settings, State};

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(settings_updated, State) ->
    {noreply, maybe_apply_new_settings(State)};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(reload_timer, State) ->
    {noreply, apply_config(State#s{reload_timer_ref = undefined})};

handle_info(intervals_calculation_timer, #s{cur_settings = Settings} = State) ->
    maybe_update_scrape_dynamic_intervals(Settings),
    {noreply, restart_intervals_calculation_timer(State)};

handle_info({'EXIT', PortServer, Reason},
            #s{prometheus_port = PortServer} = State) ->
    ?log_error("Received exit from Prometheus port server - ~p: ~p. "
               "Restarting Prometheus...", [PortServer, Reason]),
    %% Restart prometheus but wait a bit before trying in order to avoid
    %% cpu burning if it crashes again and again.
    {noreply, start_reload_timer(State#s{prometheus_port = undefined,
                                         specs = undefined})};

handle_info({'EXIT', Pid, normal}, State) ->
    ?log_debug("Received exit from ~p with reason normal. Ignoring... ", [Pid]),
    {noreply, State};

handle_info({'EXIT', Pid, Reason}, State) ->
    ?log_error("Received exit from ~p with reason ~p. Stopping... ",
               [Pid, Reason]),
    {stop, Reason, State};

handle_info(Info, State) ->
    ?log_error("Unhandled info: ~p", [Info]),
    {noreply, State}.

terminate(Reason, State) ->
    ?log_error("Terminate: ~p", [Reason]),
    terminate_prometheus(State),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

format_status(_Opt, [_PDict, #s{cur_settings = Settings} = State]) ->
    State#s{cur_settings = sanitize_settings(Settings)}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

generate_ns_to_prometheus_auth_info() ->
    Config = ns_config:get(),
    case ns_config:search_node(Config, ns_to_prometheus_auth_info) of
        false ->
            Password = menelaus_web_rbac:gen_password({32,
                                                       [uppercase, lowercase,
                                                        digits]}),
            {Salt0, Hash0, Iterations} = scram_sha:hash_password(sha512,
                                                                 Password),
            Salt = base64:encode_to_string(Salt0),
            Hash = base64:encode_to_string(Hash0),

            AuthInfo= {[{username, list_to_binary(?NS_TO_PROMETHEUS_USERNAME)},
                        {salt, list_to_binary(Salt)},
                        {hash, list_to_binary(Hash)},
                        {iterations, Iterations}]},
            AuthInfoJson = menelaus_util:encode_json(AuthInfo),

            AuthFile = ns_to_prometheus_filename(),
            ok = misc:atomic_write_file(AuthFile, AuthInfoJson),

            ns_config:set({node, node(), ns_to_prometheus_auth_info},
                          [{creds, {pass, {?NS_TO_PROMETHEUS_USERNAME,
                                           Password}}}]);
        _ ->
            ok
    end.

ns_to_prometheus_filename() ->
    filename:join(path_config:component_path(data, "config"),
                  "prometheus_auth").

generate_prometheus_auth_info(Settings) ->
    Token = menelaus_web_rbac:gen_password({256, [uppercase, lowercase,
                                                  digits]}),
    AuthInfo = menelaus_users:build_scram_auth(Token),
    ns_config:set({node, node(), prometheus_auth_info},
                  {?USERNAME, {auth, AuthInfo}}),
    TokenFile = token_file(Settings),
    ok = misc:atomic_write_file(TokenFile, Token ++ "\n").

token_file(Settings) ->
    filename:join(path_config:component_path(data, "config"),
                  proplists:get_value(token_file, Settings)).

maybe_apply_new_settings(#s{cur_settings = OldSettings} = State) ->
    case build_settings() of
        OldSettings ->
            ?log_debug("Settings didn't change, ignoring update"),
            State;
        NewSettings ->
            ?log_debug("New settings received: ~p~nOld settings: ~p",
                       [sanitize_settings(NewSettings),
                        sanitize_settings(OldSettings)]),
            ensure_prometheus_config(NewSettings),
            NewState = apply_config(State#s{cur_settings = NewSettings}),
            restart_intervals_calculation_timer(NewState)
    end.

apply_config(#s{cur_settings = Settings, specs = OldSpecs} = State) ->
    case proplists:get_bool(enabled, Settings) of
        true ->
            case specs(Settings) of
                OldSpecs ->
                    try_config_reload(State);
                NewSpecs ->
                    ?log_debug("Restarting Prometheus as the start specs have "
                               "changed"),
                    restart_prometheus(NewSpecs, State)
            end;
        false ->
            NewState = terminate_prometheus(State),
            ?log_warning("Skipping prometheus start, since it's disabled"),
            NewState
    end.

restart_prometheus(Specs, State) ->
    NewState = terminate_prometheus(State),
    take_out_the_garbage(State),
    SpecsFun = fun () -> Specs end,
    {ok, NewPortServer} = ns_port_server:start_link(SpecsFun),
    NewState#s{prometheus_port = NewPortServer, specs = Specs}.

%% If prometheus is happened to be killed during compaction, it can leave
%% huge garbage files on disk. Those files are never removed by prometheus and
%% can eat up the whole disk eventually. To prevent that we search for ".tmp"
%% files in prometheus data dir and delete them.
take_out_the_garbage(#s{cur_settings = Settings}) ->
    StoragePath = storage_path(Settings),
    case file:list_dir(StoragePath) of
        {ok, FileList} ->
            lists:foreach(
              fun (Name) ->
                  FullPath = filename:join(StoragePath, Name),
                  case filelib:is_dir(FullPath) andalso
                       lists:suffix(".tmp", Name) of
                      true ->
                          ?log_warning("Removing .tmp dir in stats_dir: ~s",
                                       [FullPath]),
                          misc:rm_rf(FullPath);
                      false ->
                          ok
                  end
              end, FileList);
        {error, enoent} ->
            ok;
        {error, Reason} ->
            ?log_warning("Can't list files in stats data dir - ~s: ~p",
                         [StoragePath, Reason]),
            ok
    end.

terminate_prometheus(#s{prometheus_port = undefined} = State) -> State;
terminate_prometheus(#s{prometheus_port = PortServer,
                        cur_settings = Settings} = State) ->
    ?log_debug("Terminating Prometheus gracefully"),
    case prometheus:quit(?DEFAULT_PROMETHEUS_TIMEOUT, Settings) of
        ok ->
            case misc:wait_for_process(PortServer,
                                       ?PROMETHEUS_SHUTDOWN_TIMEOUT) of
                ok ->
                    ?flush({'EXIT', PortServer, _}),
                    ok;
                {error, timeout} ->
                    ?log_error("Prometheus graceful shutdown timed out, "
                               "trying to kill it..."),
                    misc:unlink_terminate(PortServer, normal),
                    ok = misc:wait_for_process(PortServer,
                                               ?PROMETHEUS_SHUTDOWN_TIMEOUT)
            end;
        {error, _} ->
            ?log_error("Failed to terminate Prometheus gracefully, "
                       "trying to kill it..."),
            misc:unlink_terminate(PortServer, normal),
            ok = misc:wait_for_process(PortServer, ?PROMETHEUS_SHUTDOWN_TIMEOUT)
    end,
    ?log_debug("Prometheus port server stopped successfully"),
    State#s{prometheus_port = undefined, specs = undefined}.

try_config_reload(#s{cur_settings = Settings} = State) ->
    ?log_debug("Reloading prometheus config"),
    case prometheus:reload(?DEFAULT_PROMETHEUS_TIMEOUT, Settings) of
        ok ->
            ?log_debug("Config successfully reloaded"),
            cancel_reload_timer(State);
        {error, Reason} ->
            ?log_error("Failed to reload config: ~p", [Reason]),
            start_reload_timer(State)
    end.

start_reload_timer(#s{reload_timer_ref = undefined} = State) ->
    Ref = erlang:send_after(?RELOAD_RETRY_PERIOD, self(), reload_timer),
    State#s{reload_timer_ref = Ref};
start_reload_timer(State) ->
    State.

cancel_reload_timer(#s{reload_timer_ref = undefined} = State) ->
    State;
cancel_reload_timer(#s{reload_timer_ref = Ref} = State) ->
    erlang:cancel_timer(Ref),
    misc:flush(reload_timer),
    State#s{reload_timer_ref = undefined}.

prometheus_config_file(Settings) ->
    File = proplists:get_value(config_file, Settings),
    filename:join(path_config:component_path(data, "config"), File).

high_cardinality_jobs_config(Settings) ->
    Targets = proplists:get_value(targets, Settings, []),
    Services = [{Name, Props} ||
                    {Name, Props} <- proplists:get_value(services, Settings),
                    proplists:get_value(high_cardinality_enabled, Props, false),
                    proplists:is_defined(Name, Targets)],
    TokenFile = token_file(Settings),
    DefaultInterval = proplists:get_value(scrape_interval, Settings),
    DefaultTimeout = proplists:get_value(scrape_timeout, Settings),
    DynamicScrapeIntervals = proplists:get_value(dynamic_scrape_intervals,
                                                 Settings, []),
    lists:map(
      fun ({Name, Props}) ->
          Addr = proplists:get_value(Name, Targets),
          Interval =
              case proplists:get_value(high_cardinality_scrape_interval, Props,
                                       auto) of
                  auto ->
                      proplists:get_value(Name, DynamicScrapeIntervals,
                                          DefaultInterval);
                  I ->
                      I
              end,
          Timeout = proplists:get_value(scrape_timeout, Props,
                                        min(Interval, DefaultTimeout)),
          #{job_name => {"~p_high_cardinality", [Name]},
            scrape_interval => {"~bs", [Interval]},
            scrape_timeout => {"~bs", [Timeout]},
            metrics_path => <<"/_prometheusMetricsHigh">>,
            basic_auth => #{username => list_to_binary(?USERNAME),
                            password_file => list_to_binary(TokenFile)},
            static_configs => [#{targets => [list_to_binary(Addr)]}],
            metric_relabel_configs => [#{source_labels => [<<"__name__">>],
                                         target_label => <<"name">>}],
            relabel_configs =>
              [#{regex => list_to_binary(addr2re(Addr)),
                 source_labels => [<<"__address__">>],
                 target_label => <<"instance">>,
                 replacement => Name}]}
      end, Services).

ensure_prometheus_config(Settings) ->
    File = prometheus_config_file(Settings),
    ScrapeInterval = proplists:get_value(scrape_interval, Settings),
    ScrapeTimeout = proplists:get_value(scrape_timeout, Settings),
    TokenFile = token_file(Settings),
    Targets = proplists:get_value(targets, Settings, []),
    TargetsBin = [list_to_binary(T) || {_, T} <- Targets],
    Cfg = #{global => #{scrape_interval => {"~bs", [ScrapeInterval]},
                        scrape_timeout => {"~bs", [ScrapeTimeout]}},
            scrape_configs =>
              [#{job_name => general,
                 metrics_path => <<"/_prometheusMetrics">>,
                 basic_auth => #{username => list_to_binary(?USERNAME),
                                 password_file => list_to_binary(TokenFile)},
                 static_configs => [#{targets => TargetsBin}],
                 metric_relabel_configs => [#{source_labels => [<<"__name__">>],
                                              target_label => <<"name">>}],
                 relabel_configs =>
                   [#{regex => list_to_binary(addr2re(A)),
                      source_labels => [<<"__address__">>],
                      target_label => <<"instance">>,
                      replacement => N} || {N, A} <- Targets] ++
                   [#{regex => <<"n1ql">>,
                      source_labels => [<<"instance">>],
                      target_label => <<"category">>,
                      replacement => <<"n1ql">>}]}] ++
              high_cardinality_jobs_config(Settings) ++
              prometheus_metrics_jobs_config(Settings)},
    ConfigBin = yaml:encode(Cfg),
    ?log_debug("Updating prometheus config file: ~s", [File]),
    ok = misc:atomic_write_file(File, ConfigBin).

prometheus_metrics_jobs_config(Settings) ->
    DropMetrics = ["prometheus_target_interval_length_seconds_sum",
                   "prometheus_target_interval_length_seconds",
                   "prometheus_target_interval_length_seconds_count"],
    DropRe = iolist_to_binary(lists:join("|", DropMetrics)),
    case proplists:get_bool(prometheus_metrics_enabled, Settings) of
        true ->
            TokenFile = token_file(Settings),
            Address = iolist_to_binary(
                              proplists:get_value(addr, Settings)),
            Interval = proplists:get_value(prometheus_metrics_scrape_interval,
                                           Settings),
            [#{job_name => prometheus,
               scrape_interval => {"~bs", [Interval]},
               scrape_timeout => {"~bs", [Interval]},
               basic_auth => #{username => list_to_binary(?USERNAME),
                               password_file => list_to_binary(TokenFile)},
               static_configs => [#{targets => [Address]}],
               metric_relabel_configs => [#{source_labels => [<<"__name__">>],
                                            regex => DropRe,
                                            action => <<"drop">>}],
               relabel_configs =>
                   [#{target_label => <<"instance">>,
                      replacement => <<"prometheus">>}]}];
        false ->
            []
    end.

get_service_port(ns_server) -> rest_port;
get_service_port(index) -> indexer_http_port;
get_service_port(cbas) -> cbas_admin_port;
get_service_port(n1ql) -> query_port;
get_service_port(fts) -> fts_http_port;
get_service_port(eventing) -> eventing_http_port;
get_service_port(kv) -> memcached_prometheus;
get_service_port(xdcr) -> xdcr_rest_port;
get_service_port(backup) -> backup_http_port.

addr2re(A) ->
    Replace = fun (P,V) ->
                  fun (X) -> re:replace(X, P, V, [{return, list}, global]) end
              end,
    functools:chain(A, [Replace("\\[", "\\\\["),
                        Replace("\\]", "\\\\]"),
                        Replace("\\.", "\\\\.")]).

sanitize_settings(Settings) ->
    lists:map(
      fun ({prometheus_creds, {Name, _Password}}) ->
              {prometheus_creds, {Name, "********"}};
          (KV) -> KV
      end, Settings).

restart_intervals_calculation_timer(#s{intervals_calc_timer_ref = undefined,
                         cur_settings = Settings} = State) ->
    case intervals_calculation_period(Settings) of
        disabled -> State;
        Timeout ->
            Ref = erlang:send_after(Timeout, self(),
                                    intervals_calculation_timer),
            State#s{intervals_calc_timer_ref = Ref}
    end;
restart_intervals_calculation_timer(#s{intervals_calc_timer_ref = Ref} = State) ->
    _ = erlang:cancel_timer(Ref),
    restart_intervals_calculation_timer(State#s{intervals_calc_timer_ref = undefined}).

%% The prometheus_cfg process wakes up every 10 min (it's configurable) and
%% performs the following steps:
%% 1) Firstly, it gets the latest scrape information for each target
%%    from prometheus. Right now we need to know only how many samples
%%    are reported in each scrape by each service. Prometheus keeps this
%%    information in the scrape_samples_scraped metric.
%% 2) All samples are divided into two parts: those for which the scrape
%%    interval is static, and those for which the scrape interval can be
%%    changed. First group is all the low cardinality metrics and
%%    the high cardinality metrics for which the scrape interval is set
%%    explicitly. All other samples fall to the second group (all high
%%    cardinality metrics where the scrape interval is not explicitly
%%    set).
%% 3) Then it calculates how many samples can be written per second to
%%    satisfy cbcollect dump size requirement and subtracts the rate of
%%    "static" samples from it (first group from #2). The resulting
%%    number is the maximum samples rate for metrics from second group.
%% 4) Now when it knows the max samples rate and the number of samples
%%    per scrape, it is easy to calculate scrape intervals for each
%%    service.
maybe_update_scrape_dynamic_intervals(Settings) ->
    case intervals_calculation_period(Settings) of
        disabled -> ok;
        _ ->
            ?log_debug("Recalculating prometheus scrape intervals for high "
                       "cardinality metrics"),
            try
                Info = scrapes_info(Settings),
                Intervals = calculate_dynamic_intervals(Info, Settings),
                RoundedIntervals = [{S, min(round(Float), ?MAX_SCRAPE_INTERVAL)}
                                        || {S, Float} <- Intervals],
                CurIntervals = ns_config:read_key_fast(
                                 {node, node(), stats_scrape_dynamic_intervals},
                                 undefined),
                case RoundedIntervals of
                    CurIntervals ->
                        ?log_debug("Scrape intervals haven't changed:~n~p~n"
                                   "Calculated based on scrapes info:~n~p~n"
                                   "Raw intervals:~n~p",
                                   [RoundedIntervals, Info, Intervals]);
                    _ ->
                        ns_config:set(
                          {node, node(), stats_scrape_dynamic_intervals},
                          RoundedIntervals),
                        ?log_debug("New scrape intervals:~n~p~n"
                                   "Previous scrape intervals: ~n~p~n"
                                   "Calculated based on scrapes info:~n~p~n"
                                   "Raw intervals:~n~p",
                                   [RoundedIntervals, CurIntervals, Info,
                                    Intervals])
                end
            catch
                C:E:ST ->
                    ?log_error("Failed to calculate scrape intervals because of"
                               " ~p: ~p~n~p", [C, E, ST])
            end,
            ok
    end.

%% Pure function that calculates scrape intervals for services' high cardinality
%% endpoints for given numbers of samples that are reported by those services
%% (ScrapeInfos) and stats settings.
%% Function returns a proplist where the key is a service name and the value is
%% a scrape interval for that service (as float). If some service is missing
%% in the resulting proplist, the default scrape interval should be
%% used for that service.
-spec calculate_dynamic_intervals([{Service, Type, NumberOfSamples}],
                                  [Setting]) -> [{Service, ScrapeInterval}] when
                        Service         :: atom(),
                        Type            :: low_cardinality | high_cardinality,
                        NumberOfSamples :: non_neg_integer(),
                        Setting         :: {Key :: atom(), Value :: term()},
                        ScrapeInterval  :: float().
calculate_dynamic_intervals(ScrapeInfos, Settings) ->
    ServiceSettings = proplists:get_value(services, Settings, []),
    MinScrapeInterval = proplists:get_value(scrape_interval, Settings),
    %% Split all reporting targets into two lists
    %% First list is for targets that use static scrape intervals (they can't be
    %% modified), we need to calculate total reported rate for them (in samples
    %% per second)
    %% Second list is targets for which we need to calculate scrape intervals.
    {StaticIntSampleRates, DynamicIntTargets} =
        misc:partitionmap(
          fun ({_Name, low_cardinality, Num}) ->
                  {left, Num / MinScrapeInterval};
              ({Name, high_cardinality, Num}) ->
                  Props = proplists:get_value(Name, ServiceSettings, []),
                  case proplists:get_value(high_cardinality_scrape_interval,
                                           Props, auto) of
                      auto -> {right, {Name, Num}};
                      I -> {left, Num / I}
                  end
          end, ScrapeInfos),
    %% This is the total sample rate reported by targets with static scrape
    %% interval
    StaticIntTotalRate = lists:sum(StaticIntSampleRates),
    %% This is how many samples we can report per second (to maintain the max
    %% cbcollect dump size)
    TotalSamplesQuota = samples_per_second_quota(Settings),
    %% This is how many samples can be reported per seconds by targets with
    %% dynamic scrape intervals
    DynamicIntSamplesQuota = max(TotalSamplesQuota - StaticIntTotalRate, 0),
    %% This is how many samples per second each service wants to report
    DynamicIntDesiredSamplesRates =
        [{Name, Num / MinScrapeInterval} || {Name, Num} <- DynamicIntTargets],
    %% The same as above but sorted by the second tuple element
    DynamicIntDesiredSamplesRatesSorted =
        lists:usort(fun ({T1, N1}, {T2, N2}) -> {N1, T1} =< {N2, T2} end,
                    DynamicIntDesiredSamplesRates),
    %% split_quota calculates max rates per service, the only thing left is
    %% to convert "report speed" to "scrape interval" by dividing "distance" by
    %% "speed"
    lists:map(fun ({Target, MaxSampleRate}) when MaxSampleRate < 1.0e-8 ->
                      {Target, infinity};
                  ({Target, MaxSampleRate}) ->
                      SamplesPerScrape = proplists:get_value(Target, DynamicIntTargets),
                      {Target, SamplesPerScrape / MaxSampleRate}
              end, split_quota(DynamicIntDesiredSamplesRatesSorted,
                               DynamicIntSamplesQuota, [])).

%% Distribute sample rate quota among services
%% Input proplist is how many samples per seconds services want to report
%% That list must be sorted by second tuple element the way that services that
%% report fewer samples go first.
%% If there are N services and total quota is Q, each service gets Q/N quota
%% but if some service doesn't need that much it lets other services to use its
%% unused quota (we put nothing in a resulting list in this case, which means
%% "no limit required"). If a service wants to report more then Q/N samples
%% per second, that service is given a quota = Q/N.
split_quota([], _Quota, Res) -> Res;
split_quota([{Target, Need} | Tail], Quota, Res) ->
    QuotaPerTarget = Quota / (length(Tail) + 1),
    case Need < QuotaPerTarget of
        true ->
            QuotaLeft = Quota - Need,
            split_quota(Tail, QuotaLeft, Res);
        false ->
            QuotaLeft = Quota - QuotaPerTarget,
            split_quota(Tail, QuotaLeft, [{Target, QuotaPerTarget} | Res])
    end.

intervals_calculation_period(Settings) ->
    case proplists:get_bool(enabled, Settings) of
        true ->
            case proplists:get_value(intervals_calculation_period, Settings) of
                undefined -> disabled;
                Timeout -> Timeout
            end;
        false ->
            disabled
    end.

scrapes_info(Settings) ->
    Query = io_lib:format("scrape_samples_scraped[~bs:1m]",
                          [?MAX_SCRAPE_INTERVAL]),
    case prometheus:query(lists:flatten(Query), undefined,
                          ?DEFAULT_PROMETHEUS_TIMEOUT, Settings) of
        {ok, JSON} ->
            lists:map(
              fun ({Props}) ->
                  {MetricProps} = proplists:get_value(<<"metric">>, Props),
                  TargetName = proplists:get_value(<<"instance">>, MetricProps),
                  JobName = proplists:get_value(<<"job">>, MetricProps),
                  Type = case JobName of
                             <<"general">> -> low_cardinality;
                             _ -> high_cardinality
                         end,
                  [_, ValBin] = lists:last(proplists:get_value(<<"values">>,
                                                               Props)),
                  Num = case prometheus:parse_value(ValBin) of
                            %% NaN will be returned as undefined
                            undefined -> 0;
                            %% We assume this metric should never return
                            %% +-Inf, so we are making sure it will crash here
                            %% in such case.
                            N when is_number(N) -> N
                        end,
                  {binary_to_atom(TargetName, latin1), Type, Num}
              end, JSON);
        {error, Error} ->
            erlang:error(Error)
    end.

samples_per_second_quota(Settings) ->
    MaxSize = proplists:get_value(cbcollect_stats_dump_max_size, Settings),
    MinPeriod = proplists:get_value(cbcollect_stats_min_period, Settings),
    AverageSampleSize = proplists:get_value(average_sample_size, Settings),
    MaxSize / AverageSampleSize / MinPeriod / 24 / 60 / 60.


-ifdef(TEST).

dynamic_intervals_monotonicity_test_() ->
    {timeout, 60,
     fun () ->
         [randomly_test_dynamic_intervals_monotonocity()
            || _ <- lists:seq(0,1000)]
     end}.

calculate_dynamic_intervals_test_() ->
    {timeout, 60,
     fun () ->
         [randomly_test_calculate_dynamic_intervals()
            || _ <- lists:seq(0,10000)]
     end}.

randomly_test_dynamic_intervals_monotonocity() ->
    LCS1Num = rand:uniform(500),
    LCS2Num = rand:uniform(500),
    HCS1Num = rand:uniform(10000),
    HCS2Num = rand:uniform(10000),
    ScrapeInt = rand:uniform(100),
    MaxSize = rand:uniform(2*1024*1024*1024),
    Period = rand:uniform(60),
    SampleSize = rand:uniform(10),

    ScrapeInfos = fun (N) ->
                      [{service1, low_cardinality, LCS1Num},
                       {service1, high_cardinality, HCS1Num},
                       {service2, low_cardinality, LCS2Num},
                       {service2, high_cardinality, N}]
                  end,

    Settings = fun (Size) ->
                   [{services, []},
                    {scrape_interval, ScrapeInt},
                    {cbcollect_stats_dump_max_size, Size},
                    {cbcollect_stats_min_period, Period},
                    {average_sample_size, SampleSize}]
               end,

    Fun = fun (ScrapeNum, Size) ->
              Intervals = calculate_dynamic_intervals(ScrapeInfos(ScrapeNum),
                                                      Settings(Size)),
              proplists:get_value(service2, Intervals, ScrapeInt)
          end,
    try
        assert_monotonic_fun(fun (N) -> Fun(N, MaxSize) end,
                             0, HCS2Num, max(HCS2Num div 100, 1)),
        assert_monotonic_fun(fun (N) -> Fun(HCS2Num, N) end,
                             MaxSize, 0, -max(MaxSize div 100, 1))
    catch
        C:E:ST ->
            io:format("Info:~n~p~nSettings:~n~p", [ScrapeInfos(HCS2Num),
                                                   Settings(MaxSize)]),
            erlang:raise(C, E, ST)
    end.

assert_monotonic_fun(Fun, From, To, Step) ->
    lists:mapfoldl(
      fun (Param, PrevValue) ->
          NextValue = Fun(Param),
          ?assert(NextValue >= PrevValue),
          {NextValue, NextValue}
      end, Fun(From), lists:seq(From + Step, To, Step)).


randomly_test_calculate_dynamic_intervals() ->
    ServiceNum = rand:uniform(10) - 1,
    ServiceName = fun (N) -> list_to_atom("service" ++ integer_to_list(N)) end,
    WithProbability = fun (P) -> rand:uniform() < P end,
    GenerateScrapeInfo =
        fun (N) ->
            Name = ServiceName(N),
            LCNum = rand:uniform(200),
            HCNum = rand:uniform(2000),
            [{Name, low_cardinality, LCNum} || WithProbability(0.8)] ++
            [{Name, high_cardinality, HCNum} || WithProbability(0.8)]
        end,
    ScrapeInfos = lists:flatmap(GenerateScrapeInfo, lists:seq(1, ServiceNum)),
    GenerateServiceSettings =
        fun (N) ->
            Name = ServiceName(N),
            Interval = case WithProbability(0.5) of
                           true -> auto;
                           false -> rand:uniform(120)
                       end,
            [{Name, [{high_cardinality_scrape_interval, Interval}]}
                || WithProbability(0.2)]
        end,
    ServicesSettings = lists:flatmap(GenerateServiceSettings,
                                     lists:seq(1, ServiceNum)),
    MaxSize = rand:uniform(1024*1024*1024),
    DefaultInterval = rand:uniform(60),
    Settings = [{services, ServicesSettings},
                {scrape_interval, DefaultInterval},
                {cbcollect_stats_dump_max_size, MaxSize},
                {cbcollect_stats_min_period, rand:uniform(60)},
                {average_sample_size, rand:uniform(10)}],

    try
        DynamicIntervals = calculate_dynamic_intervals(ScrapeInfos, Settings),

        lists:map(
          fun ({_, infinity}) -> ok;
              ({_, I}) -> ?assert(I >= DefaultInterval)
          end, DynamicIntervals),

        SizeEstimate = total_db_size_estimate(ScrapeInfos, Settings,
                                              DynamicIntervals),

        DynamicTargets =
            begin
                HCTargets = [N || {N, high_cardinality, _} <- ScrapeInfos],
                StaticTargets =
                    [N || {N, Props} <- ServicesSettings,
                          auto =/= proplists:get_value(
                                     high_cardinality_scrape_interval, Props)],
                HCTargets -- StaticTargets
            end,

        AllInfinities = lists:all(fun ({_, infinity}) -> true;
                                      ({_, _}) -> false
                                  end, DynamicIntervals),

        if
            %% If all intervals are static, we should not try to change anything
            DynamicTargets == [] -> ?assert(DynamicIntervals == []);

            %% If we are not changing any intervals while we can,
            %% db size should not be greater than max
            DynamicIntervals == [] -> ?assert(SizeEstimate =< MaxSize);

            %% If we are setting all possible intervals to infinity,
            %% it means that static metrics only should give us db size > max
            AllInfinities -> ?assert(SizeEstimate >= MaxSize);

            %% If we are setting some intervals to non infinity values,
            %% expected db size should be almost equal to max
            %% They don't match exactly because:
            %%    1) they are floats;
            %%    2) we treat very big intervals as infinities
            true -> ?assert((abs(SizeEstimate - MaxSize) / MaxSize) < 0.01)
        end
    catch
        C:E:ST ->
            io:format("Info:~n~p~nSettings:~n~p", [ScrapeInfos, Settings]),
            erlang:raise(C, E, ST)
    end.

total_db_size_estimate(Info, Settings, Intervals) ->
    DefaultInterval = proplists:get_value(scrape_interval, Settings),
    Services = proplists:get_value(services, Settings),
    GetRate =
        fun ({_, low_cardinality, Num}) -> Num / DefaultInterval;
            ({Name, high_cardinality, Num}) ->
                Props = proplists:get_value(Name, Services, []),
                Interval =
                    case proplists:get_value(high_cardinality_scrape_interval,
                                             Props, auto) of
                        auto ->
                            proplists:get_value(Name, Intervals, DefaultInterval);
                        I ->
                            I
                    end,
                case Interval of
                    infinity -> 0;
                    _ -> Num / Interval
                end
        end,
    TotalSamplesRate = lists:sum(lists:map(GetRate, Info)),

    Days = proplists:get_value(cbcollect_stats_min_period, Settings),
    SampleSize = proplists:get_value(average_sample_size, Settings),
    TotalSize = TotalSamplesRate * SampleSize
                * 60 %% seconds
                * 60 %% minutes
                * 24 %% hours
                * Days,
    round(TotalSize).

-endif.

