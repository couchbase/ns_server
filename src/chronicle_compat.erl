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

-export([backend/0,
         get/2,
         get/3,
         set/2,
         set_multiple/1]).

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
