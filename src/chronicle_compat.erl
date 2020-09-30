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

-include("cut.hrl").

-export([backend/0,
         get/2,
         get/3,
         set/2,
         set_multiple/1,
         transaction/2,
         subscribe_to_key_change/2,
         notify_if_key_changes/2,
         start_refresh_worker/2]).

backend() ->
    case enabled() of
        true ->
            chronicle;
        false ->
            ns_config
    end.

enabled() ->
    ns_node_disco:couchdb_node() =/= node() andalso
        cluster_compat_mode:is_cluster_cheshirecat().

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
            case chronicle_kv:get(kv, Key, #{}) of
                {ok, {V, _R}} ->
                    {ok, V};
                Error ->
                    Error
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
