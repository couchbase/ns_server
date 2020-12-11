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
         prepare_join/1,
         join_cluster/1,
         leave_cluster/0,
         rename/1,
         get_snapshot/1,
         upgrade/1,
         node_keys/1,
         sync/0]).

%% exported chronicle log fun
-export([log/4]).

%% exported for log formatting
-export([format_msg/2, format_time/1]).

-define(PULL_TIMEOUT, ?get_timeout(upgrade_pull, 60000)).

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

handle_call({prepare_join, Info}, _From, State) ->
    ?log_debug("Wiping chronicle before prepare join."),
    ok = chronicle:wipe(),
    case Info of
        undefined ->
            ?log_debug("Joining not chronicle enabled cluster"),
            ok = ensure_provisioned();
        _ ->
            ?log_debug("Prepare join. Info: ~p", [Info]),
            ok = chronicle:prepare_join(Info)
    end,
    {reply, ok, State};
handle_call({join_cluster, Info}, _From, State) ->
    ?log_debug("Joining cluster. Info: ~p", [Info]),
    ok = chronicle:join_cluster(Info),
    {reply, ok, State};
handle_call(leave_cluster, _From, State) ->
    handle_leave(),
    {reply, ok, State};
handle_call({rename, OldNode}, _From, State) ->
    handle_rename(OldNode),
    {reply, ok, State};
handle_call({pull, Timeout}, _From, State) ->
    {reply, pull(Timeout), State};
handle_call(get_snapshot, _From, Pid) ->
    RV =
        try chronicle_kv:get_full_snapshot(kv) of
            {ok, {Snapshot, _}} ->
                {ok, maps:fold(fun (K, {V, _}, Acc) ->
                                       [{K, V} | Acc]
                               end, [], Snapshot)}
        catch T:E:S ->
                ?log_debug("Unable to obtain chronicle snapshot:~n~p",
                           [{T, E, S}]),
                {error, cannot_get_snapshot}
        end,
    {reply, RV, Pid};
handle_call(sync, _From, State) ->
    {reply, ok, State}.

leave_cluster() ->
    gen_server2:call(?MODULE, leave_cluster).

prepare_join(Info) ->
    gen_server2:call(?MODULE, {prepare_join, Info}).

join_cluster(undefined) ->
    ok;
join_cluster(Info) ->
    gen_server2:call(?MODULE, {join_cluster, Info}).

rename(OldNode) ->
    gen_server2:call(?MODULE, {rename, OldNode}).

get_snapshot(Node) ->
    {ok, Snapshot} = gen_server2:call({?MODULE, Node}, get_snapshot),
    Snapshot.

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

handle_leave() ->
    ?log_debug("Leaving cluster"),
    ok = chronicle:wipe(),
    ok = ensure_provisioned().

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

pull(Timeout) ->
    ?log_debug("Pull quorum view of chronicle"),
    case chronicle_rsm:sync(kv, quorum, Timeout) of
        ok ->
            ok;
        Error ->
            ?log_warning("Failed to pull quorum view of chronicle ~p", [Error]),
            Error
    end.

remote_pull([], _Timeout) ->
    ok;
remote_pull(Nodes, Timeout) ->
    ?log_debug("Asking nodes ~p to pull chronicle", [Nodes]),
    case misc:multi_call(Nodes, ?MODULE, {pull, Timeout}, Timeout, _ =:= ok) of
        {_, []} ->
            ok;
        {_, Errors} ->
            ?log_warning("Failed to push chronicle config ~p", [Errors]),
            {remote_pull_failed, Errors}
    end.

node_keys(Node) ->
    [{node, Node, membership},
     {node, Node, services},
     {node, Node, recovery_type},
     {node, Node, failover_vbuckets}].

should_move(nodes_wanted) ->
    true;
should_move(server_groups) ->
    true;
should_move({node, _, membership}) ->
    true;
should_move({node, _, services}) ->
    true;
should_move({node, _, recovery_type}) ->
    true;
should_move({node, _, failover_vbuckets}) ->
    true;
should_move(service_map) ->
    true;
should_move(service_failover_pending) ->
    true;
should_move(_) ->
    false.

upgrade(Config) ->
    case chronicle_compat:forced() of
        true ->
            do_upgrade(Config);
        false ->
            ok
    end.
do_upgrade(Config) ->
    OtherNodes = ns_node_disco:nodes_wanted(Config) -- [node()],
    ok = chronicle_master:upgrade_cluster(OtherNodes),

    ns_config:foreach(
      fun (Key, Value) ->
              case should_move(Key) of
                  true ->
                      {ok, Rev} = chronicle_kv:set(kv, Key, Value),
                      ?log_debug("Key ~p is migrated to chronicle. Rev = ~p."
                                 "Value = ~p",
                                 [Key, Rev, Value]);
                  false ->
                      ok
              end
      end, Config),

    remote_pull(OtherNodes, ?PULL_TIMEOUT).
