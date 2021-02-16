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
%%
%% @doc helpers for backward compatible calls to chronicle/ns_config
%%

-module(chronicle_compat).

-include("ns_common.hrl").
-include("cut.hrl").

-export([backend/0,
         enabled/0,
         forced/0,
         get/2,
         get/3,
         set/2,
         set_multiple/1,
         transaction/2,
         get_snapshot/1,
         get_snapshot_with_revision/1,
         subscribe_to_key_change/1,
         subscribe_to_key_change/2,
         notify_if_key_changes/2,
         start_refresh_worker/2,
         pull/0,
         pull/1,
         remote_pull/2,
         config_sync/2,
         config_sync/3]).

%% RPC from another nodes
-export([do_pull/1]).

-define(PULL_TIMEOUT, 15000).

backend() ->
    case enabled() of
        true ->
            chronicle;
        false ->
            ns_config
    end.

forced() ->
    case os:getenv("FORCE_CHRONICLE") of
        "0" ->
            false;
        _ ->
            true
    end.

enabled() ->
    cluster_compat_mode:is_cluster_cheshirecat() andalso forced().

get(Key, Opts) ->
    get(ns_config:latest(), Key, Opts).

get(direct, Key, Opts) ->
    get(ns_config:latest(), Key, Opts);
get(Config, Key, #{required := true}) ->
    {ok, Value} = get(Config, Key, #{}),
    Value;
get(Config, Key, #{default := Default}) ->
    case get(Config, Key, #{}) of
        {error, not_found} ->
            Default;
        {ok, Value} ->
            Value
    end;
get(Snapshot, Key, #{}) when is_map(Snapshot) ->
    case maps:find(Key, Snapshot) of
        {ok, {V, _R}} ->
            {ok, V};
        error ->
            {error, not_found}
    end;
get(Config, Key, #{}) ->
    case backend() of
        chronicle ->
            case ns_node_disco:couchdb_node() =:= node() of
                true ->
                    case ns_couchdb_chronicle_dup:lookup(Key) of
                        [{Key, Value}] ->
                            {ok, Value};
                        [] ->
                            {error, not_found}
                    end;
                false ->
                    case chronicle_kv:get(kv, Key, #{}) of
                        {ok, {V, _R}} ->
                            {ok, V};
                        Error ->
                            Error
                    end
            end;
        ns_config ->
            case ns_config:search(Config, Key) of
                {value, Value} ->
                    {ok, Value};
                false ->
                    {error, not_found}
            end
    end.

set(Key, Value) ->
    case backend() of
        chronicle ->
            case chronicle_kv:set(kv, Key, Value) of
                {ok, _} ->
                    ok;
                Error ->
                    Error
            end;
        ns_config ->
            ns_config:set(Key, Value),
            ok
    end.

set_multiple(List) ->
    case backend() of
        chronicle ->
            Fun = fun (_) -> {commit, [{set, K, V} || {K, V} <- List]} end,
            case chronicle_kv:transaction(kv, [], Fun, #{}) of
                {ok, _} ->
                    ok;
                Error ->
                    Error
            end;
        ns_config ->
            ns_config:set(List)
    end.

transaction(Keys, Fun) ->
    RunCallback =
        fun (Snapshot, BuildCommit) ->
                case Fun(Snapshot) of
                    {abort, _} = Abort ->
                        Abort;
                    {List, Extra} ->
                        {commit, BuildCommit(List), Extra};
                    List ->
                        {commit, BuildCommit(List)}
                end
        end,

    case backend() of
        chronicle ->
            RV =
                chronicle_kv:transaction(
                  kv, Keys,
                  fun (Snapshot) ->
                          RunCallback(Snapshot,
                                      ?cut([{set, K, V} || {K, V} <- _]))
                  end, #{}),
            case RV of
                {ok, _} ->
                    ok;
                {ok, _, Extra} ->
                    {ok, Extra};
                Error ->
                    Error
            end;
        ns_config ->
            TXNRV =
                ns_config:run_txn(
                  fun (Cfg, SetFn) ->
                          RunCallback(Cfg, fun (List) ->
                                                   lists:foldl(
                                                     fun ({K, V}, Acc) ->
                                                             SetFn(K, V, Acc)
                                                     end, Cfg, List)
                                           end)
                  end),
            case TXNRV of
                {commit, _} ->
                    ok;
                {commit, _, Extra} ->
                    {ok, Extra};
                {abort, Error} ->
                    Error;
                retry_needed ->
                    erlang:error(exceeded_retries)
            end
    end.

apply_filters(_, _, _, [], Acc) ->
    Acc;
apply_filters(K, V, Rev, [Fun | Rest], Acc) ->
    case Fun(K) of
        {true, Convert} ->
            lists:foldl(
              fun ({K1, V1}, Acc1) ->
                      maps:put(K1, {V1, Rev}, Acc1)
              end, Acc, Convert(V));
        true ->
            maps:put(K, {V, Rev}, Acc);
        false ->
            apply_filters(K, V, Rev, Rest, Acc)
    end.

get_snapshot(KeyFilters) ->
    {Snapshot, _} = get_snapshot_with_revision(KeyFilters),
    Snapshot.

get_snapshot_with_revision(KeyFilters) ->
    GroupedFilters = misc:groupby_map(fun functools:id/1,
                                      lists:flatten([KeyFilters])),
    UniqueFilters = [{Type, lists:usort(Filters)} ||
                        {Type, Filters} <- GroupedFilters],

    lists:foldl(get_snapshot_with_revision(_, _), {#{}, no_rev}, UniqueFilters).

get_snapshot_with_revision({Type, Filters}, {Acc, OldRev}) ->
    {ListFilters, FunFilters} =
        lists:partition(fun (F) when is_list(F) -> true;
                            (_) -> false end, Filters),
    UniqueKeys = lists:usort(lists:flatten(ListFilters)),
    AllFilters =
        case ListFilters of
            [] ->
                FunFilters;
            _ ->
                [lists:member(_, UniqueKeys) | FunFilters]
        end,
    case Type of
        ns_config ->
            {ns_config:fold(apply_filters(_, _, no_rev, AllFilters, _),
                            Acc, ns_config:get()), OldRev};
        chronicle ->
            case ns_node_disco:couchdb_node() == node() of
                true ->
                    {lists:foldl(
                       fun ({K, V}, Acc1) ->
                               apply_filters(K, V, no_rev, AllFilters, Acc1)
                       end, Acc, ns_couchdb_chronicle_dup:get_snapshot()),
                     no_rev};
                false ->
                    case FunFilters of
                        [] ->
                            {ok, {Snapshot, Rev}} =
                                chronicle_kv:get_snapshot(kv, UniqueKeys),
                            {Snapshot, Rev};
                        _ ->
                            {ok, {Snapshot, Rev}} =
                                chronicle_kv:get_full_snapshot(kv),
                            {maps:fold(
                               fun (K, {V, KeyRev}, Acc1) ->
                                       apply_filters(K, V, KeyRev, AllFilters,
                                                     Acc1)
                               end, Acc, Snapshot), Rev}
                    end
            end
    end.

subscribe_to_key_change(Handler) ->
    BuildHandler = fun (Type) ->
                           ?cut(Handler(extract_event_key(Type, _)))
                   end,
    ns_pubsub:subscribe_link(ns_config_events, BuildHandler(ns_config)),
    ns_pubsub:subscribe_link(chronicle_kv:event_manager(kv),
                             BuildHandler(chronicle)).

subscribe_to_key_change(Keys, Worker) when is_list(Keys) ->
    subscribe_to_key_change(lists:member(_, Keys), Worker);
subscribe_to_key_change(Filter, Worker) ->
    subscribe_to_key_change(fun (Key) ->
                                    case Filter(Key) of
                                        false ->
                                            ok;
                                        true ->
                                            Worker(Key)
                                    end
                            end).

notify_if_key_changes(Filter, Message) ->
    Self = self(),
    subscribe_to_key_change(Filter, fun (_) -> Self ! Message end).

start_refresh_worker(Filter, Refresh) ->
    RV = {ok, Pid} =
        work_queue:start_link(
          fun () ->
                  Self = self(),
                  subscribe_to_key_change(
                    Filter, fun (_) ->
                                    work_queue:submit_work(Self, Refresh)
                            end)
          end),
    work_queue:submit_sync_work(Pid, Refresh),
    RV.

extract_event_key(ns_config, {Key, _}) ->
    Key;
extract_event_key(chronicle, {{key, Key}, _, _}) ->
    Key;
extract_event_key(_, _) ->
    undefined.


pull() ->
    pull(ns_config_rep:get_timeout(pull)).

pull(Timeout) ->
    case backend() of
        ns_config ->
            ok;
        chronicle ->
            do_pull(Timeout)
    end.

do_pull(Timeout) ->
    case chronicle_rsm:sync(kv, quorum, Timeout) of
        ok ->
            ok;
        Error ->
            ?log_warning("Failed to pull chronicle config ~p", [Error])
    end.

remote_pull(Nodes, Timeout) ->
    {Results, BadNodes} =
        rpc:multicall(Nodes, ?MODULE, do_pull, [Timeout], Timeout),
    case BadNodes =:= [] andalso lists:all(fun(A) -> A =:= ok end,
                                           Results) of
        true ->
            ok;
        false ->
            Error = {remote_pull_failed, Results, BadNodes},
            ?log_warning("Failed to push chronicle config ~p", [Error]),
            {error, Error}
    end.

config_sync(Type, Nodes) ->
    config_sync(pull, Nodes, ns_config_rep:get_timeout(Type)).

config_sync(pull, Nodes, Timeout) ->
    case ns_config_rep:pull_remotes(Nodes, Timeout) of
        ok ->
            pull(Timeout);
        Error ->
            Error
    end;
config_sync(push, Nodes, Timeout) ->
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes, Timeout) of
        ok ->
            case backend() of
                ns_config ->
                    ok;
                chronicle ->
                    case remote_pull(Nodes, Timeout) of
                        ok ->
                            ok;
                        {error, {remote_pull_failed, Results, BadNodes}} ->
                            Results ++ [{N, bad_rpc} || N <- BadNodes]
                    end
            end;
        {error, SyncFailedNodes} ->
            SyncFailedNodes
    end.
