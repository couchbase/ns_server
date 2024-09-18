%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

-module(cb_deks_raw_utils).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([dek_list/1,
         dek_list/2,
         bootstrap_get_deks/2]).

-type dek_utils_logger() :: ns_server_logger | fun((_, _) -> any()).

-spec dek_list(string()) ->
          {ok, {undefined | cb_deks:dek_id(),
                [cb_deks:dek_id()], ExtraInfo :: term()}} | {error, _}.
dek_list(DekPath) ->
    NoLogger = fun(_, _, _) -> ok end,
    get_dek_list(DekPath, NoLogger).

-spec dek_list(string(), dek_utils_logger()) ->
          {ok, {undefined | cb_deks:dek_id(),
                [cb_deks:dek_id()], ExtraInfo :: term()}} | {error, _}.
dek_list(DekPath, LoggerOrType) ->
    get_dek_list(DekPath, logger(LoggerOrType)).

get_dek_list(DekPath, Log) ->
    Log(debug, "Reading list of keys from (~p)...", [DekPath]),
    case external_list(DekPath) of
        {ok, ActiveKeyId, AllIds, [], ExtraInfo} ->
            {ok, {ActiveKeyId, AllIds, ExtraInfo}};
        {ok, ActiveKeyId, AllIds, OtherFiles, ExtraInfo} ->
            Log(warning, "Ignoring key files ~p as their names are "
                "not proper uuids or active keys file is missing",
                [OtherFiles]),
            {ok, {ActiveKeyId, AllIds, ExtraInfo}};
        {error, {read_dir_error, {DekDir, Reason}}} = Error ->
            Log(error, "Failed to read directory \"~s\": ~p",
                [DekDir, Reason]),
            Error;
        {error, {read_active_key_error, {ActiveKeyPath, Reason}}} = Error ->
            Log(error, "Failed to read active key file \"~s\": ~p",
                [ActiveKeyPath, Reason]),
            Error
    end.

external_list(DekPath) ->
    ActiveKeyPath = filename:join(DekPath, ?ACTIVE_KEY_FILENAME),
    case file:list_dir(DekPath) of
        {ok, Filenames} ->
            %% Ignore file that contains active key id:
            KeyFilenames = Filenames -- [?ACTIVE_KEY_FILENAME],

            %% Ignore files that doesn't look like keys:
            Ids = [F || F <- KeyFilenames,
                        cb_cluster_secrets:is_valid_key_id(iolist_to_binary(F))],
            IgnoredFiles = KeyFilenames -- Ids,
            BinIds = [list_to_binary(Id) || Id <- Ids],
            case file:read_file(ActiveKeyPath) of
                {ok, <<Vsn, Bin/binary>>} when Vsn == 0 ->
                    {ActiveKeyId, ExtraInfo} = binary_to_term(Bin),
                    {ok, ActiveKeyId, BinIds, IgnoredFiles, ExtraInfo};
                {error, enoent} ->
                    %% Ignoring all keys in this case
                    {ok, undefined, [], KeyFilenames, undefined};
                {error, Reason} ->
                    {error, {read_active_key_error, {ActiveKeyPath, Reason}}}
            end;
        {error, enoent} ->
            {ok, undefined, [], [], undefined};
        {error, Reason} ->
            {error, {read_dir_error, {DekPath, Reason}}}
    end.

-spec bootstrap_get_deks(chronicleDek | configDek | logDek, map()) ->
          {ok, cb_crypto:dek_snapshot()} | {error, _}.
bootstrap_get_deks(DekKind, Opts) ->
    maybe
        %% Note per spec, this is only called for static paths, so no extra
        %% infra is needed to get those
        DekPath = encryption_service:key_path(DekKind),
        {ok, ActiveDekId,
         KeyIdsBin, _, Enabled} ?= external_list(DekPath),
        KeyIds = [binary_to_list(K) || K <- KeyIdsBin],
        {empty, [_ | _]} ?= {empty, KeyIds},
        ConfigDir =
            case maps:get(config_path_override, Opts, undefined) of
                undefined ->
                    path_config:component_path(data, "config");
                P ->
                    P
            end,
        GosecretsCfg = filename:join(ConfigDir, "gosecrets.cfg"),
        GosecretsPath = path_config:component_path(bin, "gosecrets"),
        Path = path_config:component_path(bin, "dump-keys"),
        {ok, DumpKeysPath} ?= case os:find_executable(Path) of
                                  false -> {error, {no_dump_keys, Path}};
                                  DKPath -> {ok, DKPath}
                              end,
        {0, Output} ?= ns_secrets:call_external_script(
                         DumpKeysPath,
                         ["--gosecrets", GosecretsPath,
                          "--config", GosecretsCfg,
                          "--key-kind", atom_to_list(DekKind),
                          "--key-ids"] ++ KeyIds,
                         60000),
        {JsonKeys} = ejson:decode(Output),
        Deks =
            lists:filtermap(
              fun ({Id, {Props}}) ->
                      case maps:from_list(Props) of
                          #{<<"result">> := <<"error">>,
                            <<"response">> := Error} ->
                              %% Not clear where to write the error; we can't use
                              %% logger here because this function can be called
                              %% from CLI
                              io:format("Error: ~s~n", [Error]),
                              false;
                          #{<<"result">> := <<"raw-aes-gcm">>,
                            <<"response">> := KeyProps} ->
                              {true, #{type => 'raw-aes-gcm',
                                       id => Id,
                                       info =>
                                           encryption_service:decode_key_info(
                                             KeyProps)}}
                      end
              end, JsonKeys),
        case Enabled of
            true ->
                {value, ActiveDek} =
                    lists:search(fun (#{id := Id}) ->
                                         Id == ActiveDekId
                                 end, Deks),
                {ok, cb_crypto:create_deks_snapshot(ActiveDek, Deks,
                                                    undefined)};
            false ->
                {ok, cb_crypto:create_deks_snapshot(undefined, Deks, undefined)}
        end
    else
        {empty, []} ->
            {ok, cb_crypto:create_deks_snapshot(undefined, [], undefined)};
        {Status, ErrorsBin} when is_integer(Status) ->
            {error, {dump_keys_returned, Status, ErrorsBin}};
        {error, _} = Error ->
            Error
    end.

logger(ns_server_logger) ->
    fun(debug, Fmt, Args) ->
            ?log_debug(Fmt, Args);
       (warning, Fmt, Args) ->
            ?log_warning(Fmt, Args);
       (error, Fmt, Args) ->
            ?log_error(Fmt, Args)
    end;
logger(GenericLogger) when is_function(GenericLogger, 2) ->
    fun (_Tag, Fmt, Args) ->
            GenericLogger(Fmt, Args)
    end.