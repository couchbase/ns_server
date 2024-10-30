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

-export([bootstrap_get_deks/2,
         external_list/3,
         read_deks_file/2,
         new_deks_file_record/3]).

-type deks_file_record() :: #{is_enabled := boolean(),
                              active_id := cb_deks:dek_id() | undefined,
                              dek_ids := [cb_deks:dek_id()]}.

-spec external_list(cb_deks:dek_kind(),
                    fun((cb_deks:dek_id()) -> cb_deks:dek()), #{}) ->
          {ok, {undefined | cb_deks:dek_id(), [cb_deks:dek_id()], boolean()}} |
          {error, {read_dek_cfg_file_error, {string, term()}}}.
external_list(DekKind, GetCfgDekFun, Opts) ->
    ConfigDir =
        case maps:get(config_path_override, Opts, undefined) of
            undefined ->
                path_config:component_path(data, "config");
            P ->
                P
        end,
    DeksFilePath = filename:join(ConfigDir, ?DEK_CFG_FILENAME),
    maybe
        {ok, Term} ?= read_deks_file(DeksFilePath, GetCfgDekFun),
        case maps:find(DekKind, Term) of
            {ok, #{is_enabled := Enabled,
                   active_id := ActiveKeyId,
                   dek_ids := KeyIds}} ->
                {ok, {ActiveKeyId, KeyIds, Enabled}};
            error ->
                {ok, {undefined, [], false}}
        end
    end.

-spec bootstrap_get_deks(chronicleDek | configDek | logDek | auditDek, map()) ->
          {ok, cb_crypto:dek_snapshot()} | {error, _}.
bootstrap_get_deks(DekKind, Opts) ->
    maybe
        GetCfgDekFun =
            fun (CfgKeyId) ->
                case external_read_keys(configDek, [CfgKeyId], Opts) of
                    {ok, {[K], []}} -> {ok, K};
                    {ok, {[], [{CfgKeyId, E}]}} -> {error, E};
                    {error, E} -> {error, E}
                end
            end,
        {ok, {ActiveDekId, DekIds, Enabled}} ?=
            external_list(DekKind, GetCfgDekFun, Opts),
        {empty, [_ | _]} ?= {empty, DekIds},
        {ok, {Deks, Errors}} ?= external_read_keys(DekKind, DekIds, Opts),
        LogFun = maps:get(error_log_fun, Opts, fun (_S, _F, _A) -> ok end),
        lists:foreach(fun ({Id, E}) ->
                          LogFun(error, "Error reading ~s: ~s~n", [Id, E])
                      end, Errors),
        case Enabled of
            true ->
                case proplists:get_value(ActiveDekId, Errors) of
                    undefined ->
                        {value, ActiveDek} =
                            lists:search(fun (#{id := Id}) ->
                                                 Id == ActiveDekId
                                         end, Deks),
                        DS = cb_crypto:create_deks_snapshot(ActiveDek, Deks,
                                                            undefined),
                        {ok, DS};
                    KeyError ->
                        {error, {active_key_read_failure, KeyError}}
                end;
            false ->
                DS = cb_crypto:create_deks_snapshot(undefined, Deks, undefined),
                {ok, DS}
        end
    else
        {error, {read_dek_cfg_file_error,
                 {_CfgDekFilePath, {dump_keys_returned, _, _} = E}}} ->
            %% External utilities rely on the dump_keys_returned error, so
            %% we need to remove the read_dek_cfg_file_error wrap here
            %% (because the real reason is not that we can't read the file,
            %% but the fact that we can't read cfg key).
            {error, E};
        {error, missing_kind} -> %% No info about this Kind in the deks file
            {ok, cb_crypto:create_deks_snapshot(undefined, [], undefined)};
        {empty, []} ->
            {ok, cb_crypto:create_deks_snapshot(undefined, [], undefined)};
        {error, _} = Error ->
            Error
    end.

%% Reads keys via dump-guts utility
%% This function is supposed to be used by external utilities
external_read_keys(DekKind, KeyIds, Opts) ->
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
    maybe
        {ok, DumpKeysPath} ?= case os:find_executable(Path) of
                                  false -> {error, {no_dump_keys, Path}};
                                  DKPath -> {ok, DKPath}
                              end,
        KeyIdsStr = [binary_to_list(K) || K <- KeyIds],
        {0, Output} ?= ns_secrets:call_external_script(
                         DumpKeysPath,
                         ["--gosecrets", GosecretsPath,
                          "--config", GosecretsCfg,
                          "--key-kind", atom_to_list(DekKind),
                          "--key-ids"] ++ KeyIdsStr,
                         60000),
        {JsonKeys} = ejson:decode(Output),
        {Deks, Errors} =
            misc:partitionmap(
              fun ({Id, {Props}}) ->
                      case maps:from_list(Props) of
                          #{<<"result">> := <<"error">>,
                            <<"response">> := Error} ->
                              {right, {Id, Error}};
                          #{<<"result">> := <<"raw-aes-gcm">>,
                            <<"response">> := KeyProps} ->
                              {left, #{type => 'raw-aes-gcm',
                                       id => Id,
                                       info =>
                                           encryption_service:decode_key_info(
                                             KeyProps)}}
                      end
              end, JsonKeys),
        {ok, {Deks, Errors}}
    else
        {error, _} = Error ->
            Error;
        {Status, ErrorsBin} when is_integer(Status) ->
            {error, {dump_keys_returned, Status, ErrorsBin}}
    end.

-spec read_deks_file(string(), fun((cb_deks:dek_id()) -> cb_deks:dek())) ->
          {ok, #{cb_deks:dek_kind() := deks_file_record()}} |
          {error, {read_dek_cfg_file_error, {string, term()}}}.
read_deks_file(Path, GetCfgDekFun) ->
    case cb_crypto:read_file(Path, GetCfgDekFun) of
        {T, Data} when T == decrypted; T == raw ->
            try
                {ok, binary_to_term(Data)}
            catch
                _:_ ->
                    {error, {read_dek_cfg_file_error,
                             {Path, invalid_file_format}}}
            end;
        {error, enoent} ->
            {ok, #{}};
        {error, Reason} ->
            {error, {read_dek_cfg_file_error, {Path, Reason}}}
    end.

-spec new_deks_file_record(cb_deks:dek_id() | undefined, boolean(),
                           [cb_deks:dek_id()]) -> deks_file_record().
new_deks_file_record(ActiveId, IsEnabled, Ids) ->
    #{is_enabled => IsEnabled,
      active_id => ActiveId,
      dek_ids => Ids}.
