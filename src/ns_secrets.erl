%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.
-module(ns_secrets).

-behaviour(active_cache).

%% API
-export([start_link/0, get_pkey_pass/0, get_pkey_pass/1,
         get_fresh_pkey_pass/1, reset/0]).

-export([init/1, translate_options/1]).

-include("ns_common.hrl").

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    active_cache:start_link(?MODULE, ?MODULE, [], [{renew_interval, infinity},
                                                   {max_size, 100},
                                                   {value_lifetime, 3600000},
                                                   {max_parallel_procs, 1},
                                                   {cache_exceptions, false}]).

get_fresh_pkey_pass(PassSettings) ->
    Key = {pkey_passphrase_fun, PassSettings},
    Fun = fun () -> extract_pkey_pass(PassSettings) end,
    active_cache:update_and_get_value(?MODULE, Key, Fun).

get_pkey_pass() ->
    Props = ns_config:read_key_fast({node, node(), node_cert}, []),
    PassSettings = proplists:get_value(pkey_passphrase_settings, Props, []),
    get_pkey_pass(PassSettings).

get_pkey_pass(PassSettings) ->
    Key = {pkey_passphrase_fun, PassSettings},
    Fun = fun () -> extract_pkey_pass(PassSettings) end,
    active_cache:get_value(?MODULE, Key, Fun).

reset() ->
    active_cache:flush(?MODULE).

%%%===================================================================
%%% callbacks
%%%===================================================================

init([]) -> ok.

translate_options(Opts) -> Opts.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% dummy implementation
extract_pkey_pass(PassSettings) ->
    case proplists:get_value(type, PassSettings) of
        plain ->
            P = proplists:get_value(password, PassSettings),
            fun () -> binary_to_list(P) end;
        _ -> fun () -> undefined end
    end.
