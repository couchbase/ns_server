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
-export([start_link/0, specs/1, authenticate/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {cur_settings = [],
            reload_timer_ref = undefined}).

-define(RELOAD_RETRY_PERIOD, 10000).
-define(USERNAME, "@prometheus").

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, Pid :: pid()} | ignore | {error, Error :: term()}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

default_settings() ->
    [{enabled, false},
     {retention_size, 1024*20}, %% in MB
     {retention_time, 365}, %% in days
     {storage_path, "./stats_data"},
     {config_file, "prometheus.yml"},
     {log_file_name, "prometheus.log"},
     {log_level, "debug"},
     {max_block_duration, 25}, %% in hours
     {scrape_interval, 10}, %% in seconds
     {token_file, "prometheus_token"}].

settings() -> settings(ns_config:get()).
settings(Config) ->
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
                end, [ns_server | Services]),
    Settings =
        ns_config:search(Config, stats_settings, []) ++
        [{listen_addr, misc:join_host_port(LocalAddr, Port)},
         {targets, Targets}],
    misc:update_proplist(default_settings(), Settings).

specs(Config) ->
    Settings = settings(Config),
    ConfigFile = prometheus_config_file(Settings),
    RetentionSize = integer_to_list(proplists:get_value(retention_size,
                                                        Settings)) ++ "MB",
    RetentionTime = integer_to_list(proplists:get_value(retention_time,
                                                        Settings)) ++ "d",
    ListenAddress = proplists:get_value(listen_addr, Settings),
    StoragePath = proplists:get_value(storage_path, Settings),
    FullStoragePath = path_config:component_path(data, StoragePath),
    LogFile = proplists:get_value(log_file_name, Settings),
    MaxBlockDuration = integer_to_list(proplists:get_value(max_block_duration,
                                                           Settings)) ++ "h",
    LogLevel = proplists:get_value(log_level, Settings),

    Args = ["--config.file", ConfigFile,
            "--web.enable-admin-api",
            "--web.enable-lifecycle", %% needed for hot cfg reload
            "--storage.tsdb.retention.size", RetentionSize,
            "--storage.tsdb.retention.time", RetentionTime,
            "--web.listen-address", ListenAddress,
            "--storage.tsdb.max-block-duration", MaxBlockDuration,
            "--storage.tsdb.path", FullStoragePath,
            "--log.level", LogLevel],

    case proplists:get_value(enabled, Settings) of
        true ->
            [{prometheus, path_config:component_path(bin, "prometheus"), Args,
              [via_goport, exit_status, stderr_to_stdout, {env, []},
               {log, LogFile}]}];
        false ->
            ?log_warning("Skipping prometheus start, since it's disabled"),
            []
    end.

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
            ({node, Node, services}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            ({node, Node, rest}) when Node == node() ->
                gen_server:cast(?MODULE, settings_updated);
            (rest) ->
                gen_server:cast(?MODULE, settings_updated);
            (_) -> ok
        end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),
    Settings = settings(),
    ensure_prometheus_config(Settings),
    generate_prometheus_auth_info(Settings),
    case proplists:get_value(enabled, Settings) of
        true ->
            {ok, try_config_reload(#s{cur_settings = Settings})};
        false ->
            {ok, #s{cur_settings = Settings}}
    end.

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

%%%===================================================================
%%% Internal functions
%%%===================================================================

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
    case settings() of
        OldSettings ->
            ?log_debug("Settings didn't change, ignoring update"),
            State;
        NewSettings ->
            ?log_debug("New settings received: ~p~nOld settings: ~p",
                       [NewSettings, OldSettings]),
            ensure_prometheus_config(NewSettings),
            case proplists:get_value(enabled, NewSettings) of
                true ->
                    try_config_reload(State#s{cur_settings = NewSettings});
                false ->
                    State#s{cur_settings = NewSettings}
            end
    end.

try_config_reload(#s{cur_settings = Settings} = State) ->
    Addr = proplists:get_value(listen_addr, Settings),
    URL = io_lib:format("http://~s/-/reload", [Addr]),
    ?log_debug("Reloading prometheus config by sending http post to ~s", [URL]),
    case lhttpc:request(lists:flatten(URL), 'post', [], 5000) of
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

ensure_prometheus_config(Settings) ->
    File = prometheus_config_file(Settings),
    ScrapeInterval = proplists:get_value(scrape_interval, Settings),
    TokenFile = token_file(Settings),
    Targets = proplists:get_value(targets, Settings, []),
    TargetsStr = string:join(["'" ++ T ++ "'"|| {_, T} <- Targets], ","),
    ConfigTemplate =
        "global:\n"
        "  scrape_interval: ~bs\n"
        "scrape_configs:\n"
        "  - job_name: 'general'\n"
        "    metrics_path: /_prometheusMetrics\n"
        "    basic_auth:\n"
        "      username: \""?USERNAME"\"\n"
        "      password_file: ~s\n"
        "    static_configs:\n"
        "    - targets: [~s]\n"
        "    relabel_configs:\n"
        "    - source_labels: [__address__]\n"
        "      regex: '.*:(\\d*)'\n"
        "      target_label: 'instance'\n"
        "      replacement: \"localhost:${1}\"",
    Config = io_lib:format(ConfigTemplate, [ScrapeInterval, TokenFile,
                                            TargetsStr]),
    ?log_debug("Updating prometheus config file: ~s", [File]),
    ok = misc:atomic_write_file(File, Config).

get_service_port(ns_server) -> rest_port;
get_service_port(index) -> indexer_http_port;
get_service_port(cbas) -> cbas_admin_port;
get_service_port(n1ql) -> query_port;
get_service_port(fts) -> fts_http_port;
get_service_port(eventing) -> eventing_http_port;
get_service_port(kv) -> undefined.
