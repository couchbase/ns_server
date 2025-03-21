%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_columnar).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-export([handle_settings_get/1, handle_settings_post/1]).

handle_settings_get(Req) ->
    menelaus_util:assert_is_columnar(),
    Env = ns_ports_setup:build_cbauth_env_vars(ns_config:latest(), "cbas_settings"),
    case misc:run_external_tool(
        path_config:component_path(bin, "cbas"),
        ["columnarSettings", "--get"], Env, [{stderr_to_stdout, false}]) of
        {0, StdErr, StdOut} ->
            ?log_debug("handle_settings_get success stderr: ~p", [StdErr]),
            menelaus_util:reply_ok(Req, "application/json", StdOut);
        {Code, StdErr, StdOut} ->
            ?log_debug("handle_settings_get fail ~p stderr: ~p",
                [Code, StdErr]),
            menelaus_util:reply_global_error(Req, StdOut)
    end.

handle_settings_post(Req) ->
    menelaus_util:assert_is_columnar(),
    %% we convert the body into a json object, and pass it to the cbas binary
    %% along with the preparation for audit logging
    Settings = [{settings,
                 (lists:map(fun({K, V}) ->
                                    {K, convert_for_json_encoding(V)} end,
                            mochiweb_request:parse_post(Req)))}],
    JsonObject = mochijson2:encode(
                   Settings ++ [{audit, ns_audit:prepare_log_body(Req, [])}]),
    Env = ns_ports_setup:build_cbauth_env_vars(ns_config:latest(),
                                               "cbas_settings"),
    MaxStoragePartitions = config_profile:search(
                             {cbas, max_storage_partitions}, -1),
    SkipValidation = config_profile:search(
                       {cbas, skip_blob_storage_validation}, false),

    Args = ["columnarSettings", "--set"]
        ++ ["-maxStoragePartitions=" ++ integer_to_list(MaxStoragePartitions)]
        ++ ["-skipValidation=" ++ atom_to_list(SkipValidation)],

    case misc:run_external_tool(
           path_config:component_path(bin, "cbas"), Args, Env,
           [{write_data, JsonObject}, {stderr_to_stdout, false}]) of
        {0, StdErr, StdOut} ->
            ?log_debug("handle_settings_post success stderr: ~p", [StdErr]),
            menelaus_util:reply_ok(Req, "application/json", StdOut);
        {Code, StdErr, StdOut} ->
            ?log_debug("handle_settings_post fail ~p stderr: ~p",
                       [Code, StdErr]),
            menelaus_util:reply(Req, StdOut, 400,
                                [{"Content-Type", "application/json"}])

    end.

convert_for_json_encoding(Value) ->
    case Value of
        "true" -> true;
        "false" -> false;
        _ ->
            case catch list_to_integer(Value) of
                {'EXIT', _} ->
                    case catch list_to_float(Value) of
                        {'EXIT', _} ->
                            case is_list(Value) of
                                true -> list_to_binary(Value);
                                false -> Value
                            end;
                        Float -> Float
                    end;
                Int -> Int
            end
    end.