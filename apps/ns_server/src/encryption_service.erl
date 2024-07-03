-module(encryption_service).

-behaviour(gen_server).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").

-export([start_link/0,
         decrypt/1,
         encrypt/1,
         encrypt_key/2,
         decrypt_key/2,
         change_password/1,
         get_keys_ref/0,
         rotate_data_key/0,
         maybe_clear_backup_key/1,
         get_state/0,
         os_pid/0,
         reconfigure/1,
         store_kek/4,
         store_awskey/7,
         store_dek/4,
         read_dek/2,
         key_path/1,
         decode_key_info/1,
         garbage_collect_keks/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(RUNNER, {cb_gosecrets_runner, ns_server:get_babysitter_node()}).
-define(RESTART_WAIT_TIMEOUT, 120000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

encrypt(Data) ->
    cb_gosecrets_runner:encrypt(?RUNNER, Data).

decrypt(Data) ->
    cb_gosecrets_runner:decrypt(?RUNNER, Data).

change_password(NewPassword) ->
    cb_gosecrets_runner:change_password(?RUNNER, NewPassword).

get_keys_ref() ->
    cb_gosecrets_runner:get_keys_ref(?RUNNER).

get_state() ->
    cb_gosecrets_runner:get_state(?RUNNER).

rotate_data_key() ->
    cb_gosecrets_runner:rotate_data_key(?RUNNER).

maybe_clear_backup_key(DataKey) ->
    cb_gosecrets_runner:maybe_clear_backup_key(?RUNNER, DataKey).

os_pid() ->
    cb_gosecrets_runner:os_pid(?RUNNER).

reconfigure(NewCfg) ->
    safe_call({change_config, NewCfg}, infinity).

garbage_collect_keks(InUseKeyIds) ->
    garbage_collect_keys(kek, InUseKeyIds).

store_kek(Id, Key, false, undefined) ->
    store_key(kek, Id, 'raw-aes-gcm', Key, false, <<"encryptionService">>);
store_kek(Id, Key, AlreadEncrypted, KekIdToEncrypt) ->
    store_key(kek, Id, 'raw-aes-gcm', Key, AlreadEncrypted, KekIdToEncrypt).

store_dek({bucketDek, Bucket}, Id, Key, KekIdToEncrypt) ->
    store_dek(bucketDek, bucket_dek_id(Bucket, Id), Key, KekIdToEncrypt);
store_dek(Kind, Id, Key, KekIdToEncrypt) ->
    store_key(Kind, Id, 'raw-aes-gcm', Key, false, KekIdToEncrypt).

store_awskey(Id, KeyArn, Region, Profile, CredsFile, ConfigFile, UseIMDS) ->
    Data = ejson:encode({[{keyArn, iolist_to_binary(KeyArn)},
                          {region, iolist_to_binary(Region)},
                          {profile, iolist_to_binary(Profile)},
                          {credsFile, iolist_to_binary(CredsFile)},
                          {configFile, iolist_to_binary(ConfigFile)},
                          {useIMDS, UseIMDS}]}),
    store_key(kek, Id, awskm, Data, false, <<"encryptionService">>).

read_dek(Kind, DekId) ->
    {NewId, NewKind} = case Kind of
                           {bucketDek, Bucket} ->
                               {bucket_dek_id(Bucket, DekId), bucketDek};
                           _ ->
                               {DekId, Kind}
                       end,
    case wrap_error_msg(
           cb_gosecrets_runner:read_key(?RUNNER, NewKind, NewId),
           read_key_error) of
        {ok, Json} ->
            {Props} = ejson:decode(Json),
            Res = maps:from_list(
                    lists:map(fun ({<<"type">>, <<"raw-aes-gcm">>}) -> 
                                      {type, 'raw-aes-gcm'};
                                  ({<<"info">>, InfoProps}) ->
                                      {info, decode_key_info(InfoProps)}
                              end, Props)),
            {ok, Res#{id => DekId}};
        {error, Error} ->
            {error, Error}
    end.

decode_key_info({InfoProps}) ->
    maps:from_list(
      lists:map(
        fun ({<<"key">>, B64Key}) ->
                Key = base64:decode(B64Key),
                {key, fun () -> Key end};
            ({<<"encryptionKeyId">>, KekId}) ->
                {encryption_key_id, KekId}
        end, InfoProps)).

encrypt_key(Data, KekId) when is_binary(Data), is_binary(KekId) ->
    wrap_error_msg(
      cb_gosecrets_runner:encrypt_with_key(?RUNNER, Data, kek, KekId),
      encrypt_key_error).

decrypt_key(Data, KekId) when is_binary(Data), is_binary(KekId) ->
    wrap_error_msg(
      cb_gosecrets_runner:decrypt_with_key(?RUNNER, Data, kek, KekId),
      decrypt_key_error).

%%%===================================================================
%%% callbacks
%%%===================================================================

init([]) ->
    case recover() of
        ok ->
            EventFilter = fun (database_dir) -> true;
                              (_) -> false
                          end,
            chronicle_compat_events:notify_if_key_changes(
                                      EventFilter, update),
            case maybe_update_dek_path_in_config() of
                ok ->
                    {ok, #{}};
                {error, Reason} ->
                    {stop, Reason}
            end;
        {error, _} = Error -> {stop, {recover_failed, Error}}
    end.

handle_call({change_config, Cfg}, _From, State) ->
    case change_config(Cfg) of
        ok -> {reply, ok, State};
        {error, _} = Error ->
            {stop, {change_cfg_failed, Error}, Error, State}
    end;
handle_call(sync, _From, State) ->
    {reply, ok, State};
handle_call(Msg, _From, State) ->
    ?log_error("unhandled call: ~p", [Msg]),
    {reply, unhandled, State}.

handle_cast(Msg, State) ->
    ?log_error("unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(update, State) ->
    case maybe_update_dek_path_in_config() of
        ok -> {noreply, State};
        {error, Reason} -> {stop, Reason, State}
    end;

handle_info(Info, State) ->
    ?log_error("unhandled info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

change_config(NewCfg) ->
    OldCfg = ns_config:read_key_fast(ns_config_sm_key(), []),
    ?log_debug("Change config started.~nOld cfg: ~p~nNew cfg: ~p",
               [OldCfg, NewCfg]),
    MarkerPath = change_cfg_marker(),
    write_change_cfg_marker(MarkerPath, {config_change, {OldCfg, NewCfg}}),
    case change_config(NewCfg, OldCfg, MarkerPath, _CopySecrets = needed,
                       _ResetPassword = true) of
        ok ->
            misc:remove_marker(MarkerPath),
            ok;
        {error, _} = Error -> Error
    end.

%% Note: We don't need to copy secrets if we are recovering after failure
%% because if we have removed old cfg secrets, the config change is actually
%% already finished.
change_config(NewCfg, OldCfg, MarkerPath, _CopySecrets = needed,
              ResetPassword = true) ->
    case cb_gosecrets_runner:copy_secrets(?RUNNER, NewCfg) of
        {ok, <<"same">>} ->
            write_change_cfg_marker(MarkerPath, {config_change_same_secrets,
                                                 {OldCfg, NewCfg}}),
            change_config(NewCfg, OldCfg, MarkerPath, not_needed,
                          false);
        {ok, <<"copied">>} ->
            write_change_cfg_marker(MarkerPath, {config_change_copy_done,
                                                 {OldCfg, NewCfg}}),
            change_config(NewCfg, OldCfg, MarkerPath, done, ResetPassword);
        {error, _} = Error ->
            Error
    end;
%% copy_secrets doesn't support using custom passwords, because we always
%% reset it. Looks like we don't really need to support that case anyway.
%% The only scenario when we don't want to reset password is when we are
%% recovering after unsuccessful change_config attempt.
change_config(_NewCfg, _OldCfg, _MarkerPath, _CopySecrets = needed,
              _ResetPassword = false) ->
    error(not_supported);
%% Can't (and shouldn't) reset password here because password is reset during
%% copying of secrets, since no copying is done, the password should stay
%% the same
change_config(NewCfg, _OldCfg, _MarkerPath, _CopySecrets = not_needed,
              ResetPassword = false) ->
    ns_config:set(ns_config_sm_key(), NewCfg),
    case cb_gosecrets_runner:set_config(?RUNNER, NewCfg, ResetPassword) of
        ok ->
            ok;
        {error, _} = Error ->
            Error
    end;
change_config(NewCfg, OldCfg, MarkerPath, _CopySecrets = done, ResetPassword) ->
    ns_config:set(ns_config_sm_key(), NewCfg),
    case cb_gosecrets_runner:set_config(?RUNNER, NewCfg, ResetPassword) of
        ok ->
            %% If a hard error happens during removal of old secrets,
            %% it might be very hard to recover to previous config
            %% (because old secrets can be already removed and we can't
            %% copy secrets back because of that hard error).
            %% So it seems like it is safer to not return error here.
            write_change_cfg_marker(MarkerPath, {cleanup_secrets, OldCfg}),
            cb_gosecrets_runner:cleanup_secrets(?RUNNER, OldCfg),
            ok;
        {error, _} = Error ->
            Error
    end.

recover() ->
    MarkerPath = change_cfg_marker(),
    case misc:consult_marker(MarkerPath) of
        %% Actual change has not started yet, so we can just remove new secrets
        %% that we created during the config change attempt and be done
        {ok, [{config_change, {_OldCfg, NewCfg}}]} ->
            ?log_warning("Found config_change marker. Starting cleanup for new cfg: ~p",
                         [NewCfg]),
            case cb_gosecrets_runner:cleanup_secrets(?RUNNER, NewCfg) of
                ok ->
                    ?log_debug("Cleanup finished successfully");
                {error, _} = Error ->
                    %% Ignoring because there is not match we can do
                    ?log_error("Cleanup failed with error: ~p. Ignoring...",
                               [Error])
            end,
            misc:remove_marker(MarkerPath),
            ok;
        %% Copy of configs has finished, and actual config change has probably
        %% started, but old secrets are not removed yet.
        {ok, [{config_change_copy_done, {OldCfg, NewCfg}}]} ->
            ?log_warning("Found change config marker. Starting gosecrets "
                         "recover to old config~nOld cfg: ~p~nNew cfg: ~p",
                         [OldCfg, NewCfg]),
            case change_config(OldCfg, NewCfg, MarkerPath,
                               _CopySecrets = done, _ResetPassword = false) of
                ok ->
                    ?log_debug("Recover finished successfully"),
                    misc:remove_marker(MarkerPath),
                    ok;
                {error, _} = Error ->
                    ?log_error("Recover failed with reason: ~p", [Error]),
                    Error
            end;
        %% Copy of configs was not needed, and actual config change has probably
        %% started.
        {ok, [{config_change_same_secrets, {OldCfg, NewCfg}}]} ->
            ?log_warning("Found change config marker. Starting gosecrets "
                         "recover to old config~nOld cfg: ~p~nNew cfg: ~p",
                         [OldCfg, NewCfg]),
            case change_config(OldCfg, NewCfg, MarkerPath,
                               _CopySecrets = not_needed,
                               _ResetPassword = false) of
                ok ->
                    ?log_debug("Recover finished successfully"),
                    misc:remove_marker(MarkerPath),
                    ok;
                {error, _} = Error ->
                    ?log_error("Recover failed with reason: ~p", [Error]),
                    Error
            end;
        %% We have already finished new config reload. The only thing that is
        %% not done yet, is the removal of old secrets.
        {ok, [{cleanup_secrets, OldCfg}]} ->
            ?log_warning("Found cleanup marker. Starting cleanup for cfg: ~p",
                         [OldCfg]),
            case cb_gosecrets_runner:cleanup_secrets(?RUNNER, OldCfg) of
                ok ->
                    ?log_debug("Cleanup finished successfully");
                {error, _} = Error ->
                    %% Ignoring because there is not match we can do
                    ?log_error("Cleanup failed with error: ~p. Ignoring...",
                               [Error])
            end,
            misc:remove_marker(MarkerPath),
            ok;
        false ->
            ?log_debug("Config marker ~s doesn't exist", [MarkerPath]),
            ok
    end.

change_cfg_marker() ->
    filename:join(path_config:component_path(data, "config"),
                  "sm_load_config_marker").

write_change_cfg_marker(MarkerPath, Term) ->
    MarkerBody = io_lib:format("~p.", [Term]),
    misc:create_marker(MarkerPath, iolist_to_binary(MarkerBody)).

ns_config_sm_key() -> {node, node(), secret_mngmt_cfg}.

safe_call(Req, Timeout) ->
    safe_call(Req, Timeout, 100).

safe_call(Req, _Timeout, AttemptsLeft) when AttemptsLeft =< 0 ->
    ?log_error("Call ~p retries exceeded", [Req]),
    {error, call_retries_exceeded};
safe_call(Req, Timeout, AttemptsLeft) ->
    wait_for_server_start(),
    try
        gen_server:call(?MODULE, Req, Timeout)
    catch
        exit:{{change_cfg_failed, _}, _} ->
            %% The process is being restarted because it failed to change
            %% config (previous call has failed, not this one), so we should
            %% wait until it restarts, and retry
            true = wait_for_server_start(),
            safe_call(Req, Timeout, AttemptsLeft - 1);
        exit:{{recover_failed, _}, _} ->
            %% The process is being restarted because it failed to recover
            %% after unsuccessful config change.
            %% config (previous call has failed, not this one), so we should
            %% wait until it restarts, and retry
            true = wait_for_server_start(),
            safe_call(Req, Timeout, AttemptsLeft - 1)
    end.

wait_for_server_start() ->
    misc:poll_for_condition(
      fun () ->
          try
              is_process_alive(whereis(?MODULE)) andalso
              (ok == gen_server:call(?MODULE, sync))
          catch
              _:_ -> false
          end
      end, ?RESTART_WAIT_TIMEOUT, 100).

store_key(Kind, Name, Type, KeyData, IsKeyDataEncrypted, EncryptionKeyId)
                                            when is_atom(Kind),
                                                 is_binary(Name),
                                                 is_atom(Type),
                                                 is_binary(KeyData),
                                                 is_boolean(IsKeyDataEncrypted),
                                                 is_binary(EncryptionKeyId) ->
    wrap_error_msg(
      cb_gosecrets_runner:store_key(?RUNNER, Kind, Name, Type, KeyData,
                                    IsKeyDataEncrypted, EncryptionKeyId),
      store_key_error).

maybe_update_dek_path_in_config() ->
    case ns_storage_conf:this_node_dbdir() of
        {ok, BucketDekPath} ->
            Cfg = ns_config:read_key_fast(ns_config_sm_key(), []),
            case proplists:get_value(bucket_dek_path, Cfg) of
                BucketDekPath -> ok;
                OldBucketDekPath ->
                    ?log_debug("Dek directory needs to be updated "
                               "(old value: ~p, new value: ~p)",
                               [OldBucketDekPath, BucketDekPath]),
                    NewCfg = misc:update_proplist(
                               Cfg, [{bucket_dek_path, BucketDekPath}]),
                    case change_config(NewCfg) of
                        ok -> ok;
                        {error, _} = Error ->
                            {error, {change_cfg_failed, Error}}
                    end
            end;
        {error, not_found} -> ok
    end.

wrap_error_msg(ok, _A) -> ok;
wrap_error_msg({ok, _} = R, _A) -> R;
wrap_error_msg({error, Msg}, A) when is_list(Msg) -> {error, {A, Msg}}.

garbage_collect_keys(Kind, InUseKeyIds) ->
    KeyDir = key_path(Kind),
    %% Just making sure the list is in expected format (so we don't end up
    %% comparing string and binary)
    lists:foreach(fun (Id) -> true = is_binary(Id) end, InUseKeyIds),
    IdsInUseSet = maps:from_keys(InUseKeyIds, true),
    ToRemove = lists:filter(
                 fun (Id) when is_binary(Id) ->
                      not maps:get(Id, IdsInUseSet, false)
                 end, get_all_keys_in_dir(KeyDir)),
    case ToRemove of
        [] ->
            ?log_debug("~p keys gc: no keys to retire", [Kind]),
            ok;
        _ ->
            ?log_info("~p keys gc: retiring ~p", [Kind, ToRemove]),
            lists:foreach(fun (Id) -> retire_key(Kind, Id) end, ToRemove),
            ok
    end.

get_all_keys_in_dir(KeyDir) ->
    case file:list_dir(KeyDir) of
        {ok, Filenames} ->
            AllFiles = [iolist_to_binary(F) || F <- Filenames],
            Keys = AllFiles -- [iolist_to_binary(?ACTIVE_KEY_FILENAME)],
            [F || F <- Keys, misc:is_valid_v4uuid(F)];
        {error, enoent} ->
            [];
        {error, Reason} ->
            ?log_error("Failed to get list of files in ~p: ~p",
                       [KeyDir, Reason]),
            []
    end.

key_path({bucketDek, Bucket}) ->
    case key_path(bucketDek) of
        undefined ->
            undefined;
        PathToDeks ->
            iolist_to_binary(filename:join([PathToDeks, Bucket, "deks"]))
    end;
%% Only bucketDek can change in config, other paths are static.
%% Moreover we don't have ns_config started yet when we already need other
%% paths (like chronicleDek path), so we can't call ns_config:read_key_fast for
%% those paths.
key_path(bucketDek) ->
    Cfg = ns_config:read_key_fast(ns_config_sm_key(), []),
    cb_gosecrets_runner:key_path(bucketDek, Cfg);
key_path(Kind) ->
    cb_gosecrets_runner:key_path(Kind, []).

bucket_dek_id(Bucket, DekId) ->
    iolist_to_binary(filename:join([Bucket, "deks", DekId])).

retire_key(Kind, Id) ->
    Dir = key_path(Kind),
    FromPath = filename:join(Dir, Id),
    {{Y, M, _}, _} = calendar:universal_time(),
    MonthDir = lists:flatten(io_lib:format("~b-~b", [Y, M])),
    ToPath = filename:join([path_config:component_path(data),
                            "retired_keys",
                            MonthDir,
                            Id]),
    case filelib:ensure_dir(ToPath) of
        ok ->
            case misc:atomic_rename(FromPath, ToPath) of
                ok -> ok;
                {error, Reason} ->
                    ?log_error("Failed to retire ~p key ~p (~p): ~p",
                                [Kind, Id, FromPath, Reason])
            end;
        {error, Reason} ->
            ?log_error("Failed to ensure dir ~p when retiring key ~p: ~p",
                       [ToPath, Id, Reason])
    end.
