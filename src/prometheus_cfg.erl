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

%% API
-export([start_link/0, specs/1, authenticate/2, settings/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-record(s, {cur_settings = [],
            reload_timer_ref = undefined}).

-define(RELOAD_RETRY_PERIOD, 10000).
-define(USERNAME, "@prometheus").
-define(NS_TO_PROMETHEUS_USERNAME, "ns_server").
-define(DEFAULT_HIGH_CARD_SERVICES, [index, fts, kv, cbas]).

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
                 {afamily, AFamily}]
        end,

    misc:update_proplist(default_settings(), Settings).

specs(Config) ->
    Settings = build_settings(Config),
    case proplists:get_value(enabled, Settings) of
        true ->
            Args = generate_prometheus_args(Settings),
            LogFile = proplists:get_value(log_file_name, Settings),
            [{prometheus, path_config:component_path(bin, "prometheus"), Args,
              [via_goport, exit_status, stderr_to_stdout, {env, []},
               {log, LogFile}]}];
        false ->
            ?log_warning("Skipping prometheus start, since it's disabled"),
            []
    end.

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
    StoragePath = proplists:get_value(storage_path, Settings),
    FullStoragePath = path_config:component_path(data, StoragePath),
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

    ["--config.file", ConfigFile,
     "--web.enable-admin-api",
     "--web.enable-lifecycle", %% needed for hot cfg reload
     "--storage.tsdb.retention.size", RetentionSize,
     "--storage.tsdb.retention.time", RetentionTime,
     "--web.listen-address", misc:join_host_port(ListenAddress, Port),
     "--storage.tsdb.max-block-duration", MaxBlockDuration,
     "--storage.tsdb.path", FullStoragePath,
     "--log.level", LogLevel,
     "--query.max-samples", QueryMaxSamples] ++ PromAuthArgs.

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
            ({rest, _}) ->
                gen_server:cast(?MODULE, settings_updated);
            (_) -> ok
        end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),
    generate_ns_to_prometheus_auth_info(),
    Settings = build_settings(),
    ensure_prometheus_config(Settings),
    generate_prometheus_auth_info(Settings),
    case proplists:get_value(enabled, Settings) of
        true ->
            {ok, try_config_reload(#s{cur_settings = Settings})};
        false ->
            {ok, #s{cur_settings = Settings}}
    end.

handle_call(settings, _From, #s{cur_settings = Settings} = State) ->
    {reply, Settings, State};

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(settings_updated, State) ->
    {noreply, maybe_apply_new_settings(State)};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(reload_timer, State) ->
    {noreply, try_config_reload(State#s{reload_timer_ref = undefined})};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
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
            case proplists:get_value(enabled, NewSettings) of
                true ->
                    try_config_reload(State#s{cur_settings = NewSettings});
                false ->
                    State#s{cur_settings = NewSettings}
            end
    end.

try_config_reload(#s{cur_settings = Settings} = State) ->
    Addr = proplists:get_value(addr, Settings),
    URL = io_lib:format("http://~s/-/reload", [Addr]),
    {Username, Password} = proplists:get_value(prometheus_creds, Settings),
    Headers = [menelaus_rest:basic_auth_header(Username, Password)],
    ?log_debug("Reloading prometheus config by sending http post to ~s", [URL]),
    case lhttpc:request(lists:flatten(URL), 'post', Headers, [], 5000) of
        {ok, {{200, _}, _, _}} ->
            ?log_debug("Config successfully reloaded"),
            cancel_reload_timer(State);
        {ok, {{Code, Text}, _, Error}} ->
            ?log_error("Failed to reload config: ~p ~p ~p",
                       [Code, Text, Error]),
            start_reload_timer(State);
        {error, {econnrefused, _}} ->
            ?log_debug("Can't connect to prometheus (~s)", [URL]),
            start_reload_timer(State);
        {error, Error} ->
            ?log_error("Failed to reload config: ~p", [Error]),
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
    lists:map(
      fun ({Name, Props}) ->
          Addr = proplists:get_value(Name, Targets),
          Interval = proplists:get_value(scrape_interval, Props,
                                         DefaultInterval),
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
