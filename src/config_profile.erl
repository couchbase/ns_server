%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(config_profile).

-include("ns_common.hrl").

-export([env/0,
         set_env_data/1,
         env_data/0,
         name/0,
         get/0,
         get/1,
         search/1,
         search/2,
         get_value/2,
         get_bool/1,
         is_serverless/0]).

-define(PROFILE_ENV, "CB_CONFIG_PROFILE").

-spec(env() -> atom()).
env() ->
    case os:getenv(?PROFILE_ENV) of
        false ->
            ?DEFAULT_PROFILE;
        V ->
            erlang:list_to_atom(V)
    end.

-spec(set_env_data(term()) -> 'ok').
set_env_data(Value) ->
    application:set_env(ns_server, ?CONFIG_PROFILE, Value).

-spec(env_data() -> list()).
env_data() ->
    application:get_env(ns_server, ?CONFIG_PROFILE, []).

-spec(name() -> string()).
name() ->
    search_profile_key(name, erlang:atom_to_list(env())).

-spec(get() -> list()).
get() ->
    config_profile:get([]).

-spec(get(list()) -> list()).
get(Default) ->
    ns_config:search_node_with_default(?CONFIG_PROFILE, Default).

-spec(get_value(term(), term()) -> term()).
get_value(Key, Default) ->
    proplists:get_value(Key, config_profile:get(), Default).

-spec(get_bool(term()) -> boolean()).
get_bool(Key) ->
    proplists:get_bool(Key, config_profile:get()).

-spec(search(term()) -> term()).
search(Key) ->
    search_profile_key(Key).

-spec(search(term(), term()) -> term()).
search(Key, Default) ->
    search_profile_key(Key, Default).

-spec(is_serverless() -> boolean()).
is_serverless() ->
    case name() of
        "serverless" ->
            true;
        _ ->
            false
    end.

-spec(search_profile_key(term()) -> term()).
search_profile_key(Key) ->
    search_profile_key(Key, false).

-spec(search_profile_key(term(), term()) -> term()).
search_profile_key(Key, Default) ->
    ProfileData = ns_config:search_node_with_default(?CONFIG_PROFILE, []),
    case lookup_profile_key(ProfileData, Key) of
        {value, Value} ->
            Value;
        _ ->
            Default
    end.

-spec(lookup_profile_key(list(), term()) -> {value, term()} | false).
lookup_profile_key(ProfileData, Key) when is_list(ProfileData) ->
    case proplists:lookup(Key, ProfileData) of
        {_, Value} ->
            {value, Value};
        _ ->
            false
    end;
lookup_profile_key(_, _) ->
    false.
