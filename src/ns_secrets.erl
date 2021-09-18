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

extract_pkey_pass(PassSettings) ->
    case proplists:get_value(type, PassSettings) of
        plain ->
            P = proplists:get_value(password, PassSettings),
            fun () -> binary_to_list(P) end;
        script ->
            extract_pkey_pass_with_script(PassSettings);
        undefined ->
            fun () -> undefined end
    end.

extract_pkey_pass_with_script(PassSettings) ->
    Path = proplists:get_value(path, PassSettings),
    Trim = proplists:get_value(trim, PassSettings),
    Args = proplists:get_value(args, PassSettings),
    Timeout = proplists:get_value(timeout, PassSettings),
    ?log_info("Calling external script to extract pkey passphrase: ~s~n"
              "Args: ~p~nTimeout: ~p", [Path, Args, Timeout]),
    try call_external_script(Path, Args, Timeout) of
        {0, P} ->
            MaybeTrimmed = case Trim of
                               true -> string:trim(P);
                               false -> P
                           end,
            ?log_info("Script executed successfully"),
            fun () -> binary_to_list(MaybeTrimmed) end;
        {Status, _} ->
            ?log_error("External pkey passphrase script ~s ~p finished "
                       "with exit status: ~p, ignoring returned data",
                       [Path, Args, Status]),
            fun () -> undefined end
    catch
        _:E:ST ->
            ?log_error("External pkey passphrase script execution "
                       "exception: ~s~nArgs: ~p~nException: ~p~n"
                       "Stacktrace: ~p", [Path, Args, E, ST]),
            fun () -> undefined end
    end.

call_external_script(Path, Args, Timeout) ->
    Port = erlang:open_port({spawn_executable, Path},
                            [stderr_to_stdout, binary,
                             stream, exit_status, hide,
                             {args, Args}]),
    StartTime = erlang:system_time(millisecond),
    Deadline = StartTime + Timeout,
    wait_for_exit(Port, <<>>, Deadline).

wait_for_exit(Port, Output, Deadline) ->
    Now = erlang:system_time(millisecond),
    Timeout = max(Deadline - Now, 0),
    receive
        {Port, {data, Data}} ->
            wait_for_exit(Port, <<Output/binary, Data/binary>>, Deadline);
        {Port, {exit_status, Status}} ->
            {Status, Output}
    after Timeout ->
        port_close(Port),
        error(timeout)
    end.
