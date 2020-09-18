%% @author Couchbase <info@couchbase.com>
%% @copyright 2018 Couchbase, Inc.
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
-module(chronicle_local).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include("ns_config.hrl").
-include("cut.hrl").
-include_lib("ale/include/ale.hrl").

-export([start_link/0,
         init/1,
         handle_call/3,
         rename/1,
         sync/0]).

%% exported chronicle log fun
-export([log/4]).

%% exported for log formatting
-export([format_msg/2, format_time/1]).

start_link() ->
    gen_server2:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    application:set_env(chronicle, data_dir,
                        path_config:component_path(data, "config")),
    application:set_env(chronicle, logger_function, {?MODULE, log}),

    ?log_debug("Ensure chronicle is started"),
    ok = application:ensure_started(chronicle, permanent),

    ok = ensure_provisioned(),
    case dist_manager:need_fixup() of
        {true, OldNode} ->
            ?log_info("Aborted rename from ~p was detected", [OldNode]),
            handle_rename(OldNode);
        false ->
            ok
    end,
    {ok, []}.

handle_call({rename, OldNode}, _From, State) ->
    handle_rename(OldNode),
    {reply, ok, State};
handle_call(sync, _From, State) ->
    {reply, ok, State}.

rename(OldNode) ->
    gen_server2:call(?MODULE, {rename, OldNode}).

sync() ->
    gen_server2:call(?MODULE, sync).

ensure_provisioned() ->
    ?log_debug("Ensure that chronicle is provisioned"),
    case chronicle:provision([{kv, chronicle_kv, []}]) of
        {error, provisioned} ->
            ?log_debug("Chronicle is already provisioned."),
            ok;
        Other ->
            Other
    end.

handle_rename(OldNode) ->
    NewNode = node(),
    ?log_debug("Handle renaming from ~p to ~p", [OldNode, NewNode]),
    ok = chronicle:reprovision(),

    {ok, _} =
        chronicle_kv:rewrite(
          kv,
          fun (K, V) ->
                  case {misc:rewrite_value(OldNode, NewNode, K),
                        misc:rewrite_value(OldNode, NewNode, V)} of
                      {K, V} ->
                          keep;
                      {NewK, NewV} ->
                          {update, NewK, NewV}
                  end
          end).

log(Level, Fmt, Args, Info) ->
    AleLevel = case Level of
                   warning -> warn;
                   _ -> Level
               end,
    ale:xlog(?CHRONICLE_ALE_LOGGER, AleLevel, Info, Fmt, Args).

format_time(Time) ->
    ale_default_formatter:format_time(Time).

format_msg(#log_info{user_data = #{module := M, function := F, line := L}}
           = Info, UserMsg) ->
    ale_default_formatter:format_msg(
      Info#log_info{module = M, function = F, line = L}, UserMsg).
