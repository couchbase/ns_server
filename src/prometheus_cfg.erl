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
-export([start_link/0, specs/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {}).

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
     {max_block_duration, 25}, %% in hours
     {scrape_interval, 10}]. %% in seconds

settings() -> settings(ns_config:get()).
settings(Config) ->
    AFamily = ns_config:search_node_with_default(Config, address_family, inet),
    Port = service_ports:get_port(prometheus_http_port, Config),
    ListenAddr = misc:localhost(AFamily, [url]),
    Settings =
        ns_config:search(Config, stats_settings, []) ++
        [{listen_addr, ListenAddr ++ ":" ++ integer_to_list(Port)}],
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

    Args = ["--config.file", ConfigFile,
            "--web.enable-admin-api",
            "--storage.tsdb.retention.size", RetentionSize,
            "--storage.tsdb.retention.time", RetentionTime,
            "--web.listen-address", ListenAddress,
            "--storage.tsdb.max-block-duration", MaxBlockDuration,
            "--storage.tsdb.path", FullStoragePath],

    case proplists:get_value(enabled, Settings) of
        true ->
            [{prometheus, path_config:component_path(bin, "prometheus"), Args,
              [via_goport, exit_status, stderr_to_stdout, {env, []},
               {log, LogFile}]}];
        false ->
            ?log_warning("Skipping prometheus start, since it's disabled"),
            []
    end.


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Settings = settings(),
    ensure_prometheus_config(Settings),
    {ok, #s{}}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

prometheus_config_file(Settings) ->
    File = proplists:get_value(config_file, Settings),
    filename:join(path_config:component_path(data, "config"), File).

ensure_prometheus_config(Settings) ->
    File = prometheus_config_file(Settings),
    ScrapeInterval = proplists:get_value(scrape_interval, Settings),
    TokenFile = path_config:component_path(data, "localtoken"),
    ConfigTemplate =
        "global:\n"
        "  scrape_interval: ~bs\n"
        "scrape_configs:\n"
        "  - job_name: 'ns_server'\n"
        "    metrics_path: /_prometheusMetrics\n"
        "    basic_auth:\n"
        "      username: \"@localtoken\"\n"
        "      password_file: ~s\n"
        "    static_configs:\n"
        "    - targets: ['localhost:9000']\n",
    Config = io_lib:format(ConfigTemplate, [ScrapeInterval, TokenFile]),
    ?log_debug("Updating prometheus config file: ~s", [File]),
    ok = misc:atomic_write_file(File, Config).
