%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

-module(cb_deks).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([list/1,
         external_list/1,
         read/2,
         generate_new/3,
         set_active/3,
         maybe_reencrypt_deks/4,
         dek_kinds_list/0,
         dek_kinds_list/1,
         dek_config/1,
         dek_chronicle_keys_filter/1]).

-export_type([dek_id/0, dek/0, dek_kind/0, encryption_method/0]).

-type encryption_method() :: {secret, cb_cluster_secrets:secret_id()} |
                             encryption_service |
                             disabled.
-type dek_id() :: binary().
-type dek_kind() :: kek | chronicleDek | configDek | {bucketDek, string()}.
-type dek() :: #{id := dek_id(), type := 'raw-aes-gcm',
                 info := #{key := fun(() -> binary()),
                           encryption_key_id := cb_cluster_secrets:kek_id()}}.

-spec list(dek_kind()) ->
    {ok, {undefined | dek_id(), [dek_id()], ExtraInfo :: term()}} | {error, _}.
list(Kind) ->
    ?log_debug("Reading list of keys (~p)...", [Kind]),
    case external_list(Kind) of
        {ok, ActiveKeyId, AllIds, [], ExtraInfo} ->
            {ok, {ActiveKeyId, AllIds, ExtraInfo}};
        {ok, ActiveKeyId, AllIds, OtherFiles, ExtraInfo} ->
            ?log_warning("Ignoring key files ~p as their names are "
                         "not proper uuids or active keys file is missing",
                         [OtherFiles]),
            {ok, {ActiveKeyId, AllIds, ExtraInfo}};
        {error, {read_dir_error, {DekDir, Reason}}} = Error ->
            ?log_error("Failed to read directory \"~s\": ~p",
                       [DekDir, Reason]),
            Error;
        {error, {read_active_key_error, {ActiveKeyPath, Reason}}} = Error ->
            ?log_error("Failed to read active key file \"~s\": ~p",
                      [ActiveKeyPath, Reason]),
            Error
    end.

external_list(Kind) ->
    DekDir = encryption_service:key_path(Kind),
    ActiveKeyPath = filename:join(DekDir, ?ACTIVE_KEY_FILENAME),
    case file:list_dir(DekDir) of
        {ok, Filenames} ->
            %% Ignore file that contains active key id:
            KeyFilenames = Filenames -- [?ACTIVE_KEY_FILENAME],

            %% Ignore files that doesn't look like keys:
            Ids = [F || F <- KeyFilenames, misc:is_valid_v4uuid(F)],
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
            {error, {read_dir_error, {DekDir, Reason}}}
    end.

-spec read(dek_kind(), [dek_id()]) -> {ok, [dek()]}.
read(Kind, DekIds) ->
    ?log_debug("Reading the following keys (~p) from disk: ~p", [Kind, DekIds]),
    {Keys, Errors} = misc:partitionmap(
                       fun (DekId) when is_binary(DekId) ->
                           case encryption_service:read_dek(Kind, DekId) of
                               {ok, B} -> {left, B};
                               {error, R} -> {right, {DekId, R}}
                           end
                       end, DekIds),
    case Errors of
        [] ->
            {ok, Keys};
        _ ->
            ?log_error("Failed to read some keys: ~p", [Errors]),
            {error, {read_key_errors, Errors}}
    end.

-spec generate_new(dek_kind(), {secret, Id} | encryption_service,
                   cb_cluster_secrets:chronicle_snapshot()) ->
        {ok, dek_id()} | {error, _} when Id :: cb_cluster_secrets:secret_id().
generate_new(Kind, encryption_service, _Snapshot) ->
    increment_counter_in_chronicle(Kind, encryption_service),
    new(Kind, <<"encryptionService">>);
generate_new(Kind, {secret, Id}, Snapshot) ->
    increment_counter_in_chronicle(Kind, {secret, Id}),
    maybe
        {ok, KekId} ?= cb_cluster_secrets:get_active_key_id(Id, Snapshot),
        new(Kind, KekId)
    end.

-spec new(dek_kind(), cb_cluster_secrets:kek_id()) ->
                                                    {ok, dek_id()} | {error, _}.
new(Kind, KekIdToEncrypt) ->
    ?log_debug("Generating new dek (~p)", [Kind]),
    Id = misc:uuid_v4(),
    true = misc:is_valid_v4uuid(Id),
    Bin = cb_cluster_secrets:generate_raw_key(aes_256_gcm),
    case encryption_service:store_dek(Kind, Id, Bin, KekIdToEncrypt) of
        ok -> {ok, Id};
        {error, Reason} ->
            ?log_error("Failed to store key ~p on disk: ~p", [Id, Reason]),
            {error, Reason}
    end.

-spec set_active(dek_kind(), undefined | dek_id(), term()) -> ok | {error, _}.
set_active(Kind, KeyId, ExtraInfo) ->
    ?log_debug("Writing new active key file for ~p (KeyId: ~p, Info: ~p)",
               [Kind, KeyId, ExtraInfo]),
    DirStr = binary_to_list(encryption_service:key_path(Kind)),
    ActiveKeyPath = filename:join(DirStr, ?ACTIVE_KEY_FILENAME),
    ToWrite = <<0, (term_to_binary({KeyId, ExtraInfo}))/binary>>,
    case filelib:ensure_dir(ActiveKeyPath) of
        ok ->
            case misc:atomic_write_file(ActiveKeyPath, ToWrite) of
                ok ->
                    ok;
                {error, Reason} ->
                    ?log_error("Failed to write file \"~s\": ~p",
                               [ActiveKeyPath, Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            ?log_error("Failed to ensure dir for \"~s\": ~p",
                               [ActiveKeyPath, Reason]),
            {error, Reason}
    end.

-spec maybe_reencrypt_deks(dek_kind(), [dek()], encryption_method(),
                           cb_cluster_secrets:chronicle_snapshot()) ->
          no_change | %% nothing changed
          {changed, [Error :: term()]} |
          {error, term()}.
maybe_reencrypt_deks(_Kind, [], disabled, _Snapshot) -> no_change;
maybe_reencrypt_deks(_Kind, [], _, _Snapshot) -> {changed, []};
maybe_reencrypt_deks(Kind, Deks, EncryptionMethod, Snapshot) ->
    TargetKekIdRes =
        case EncryptionMethod of
            {secret, SecretId} ->
                case cb_cluster_secrets:get_active_key_id(SecretId, Snapshot) of
                    {ok, KekId} ->
                        {ok, KekId};
                    {error, Reason} ->
                        ?log_error("Dek ~p uses invalid secret ~p: ~p",
                                   [Kind, SecretId, Reason]),
                        {error, {invalid_secret_id, SecretId, Reason}}
                end;
            encryption_service ->
                {ok, <<"encryptionService">>};
            disabled ->
                {ok, undefined}
        end,

    case TargetKekIdRes of
        %% Encryption is disabled, but we still have deks. We should reencrypt
        %% them with the most recent keks.
        {ok, undefined} ->
            KekSecretMap =
                cb_cluster_secrets:get_secret_by_kek_id_map(Snapshot),
            maybe_reencrypt_deks(
              Kind, Deks,
              fun (#{type := 'raw-aes-gcm',
                     info := #{encryption_key_id := CurKekId}} = Dek) ->
                  maybe
                      false ?= (CurKekId == <<"encryptionService">>),
                      {ok, CurSecId} ?= maps:find(CurKekId, KekSecretMap),
                      {ok, NewKekId} ?= cb_cluster_secrets:get_active_key_id(
                                          CurSecId, Snapshot),
                      case NewKekId == CurKekId of
                          true -> false;
                          false -> {true, {{secret, CurSecId}, NewKekId}}
                      end
                  else
                      true ->
                          false;
                      error ->
                          ?log_error("Orphaned key: ~p", [CurKekId]),
                          false;
                      {error, Reason2} ->
                          ?log_error("Encryption secret is missing for dek: "
                                     "~p: ~p", [Dek, Reason2]),
                          false
                  end
              end);
        {ok, TargetKekId} ->
            maybe_reencrypt_deks(
              Kind, Deks,
              fun (#{type := 'raw-aes-gcm',
                     info := #{encryption_key_id := CurKekId}}) ->
                  case CurKekId == TargetKekId of
                      true -> false;
                      false -> {true, {EncryptionMethod, TargetKekId}}
                  end
              end);
        {error, _} = Error ->
            Error
    end.

maybe_reencrypt_deks(Kind, Deks, NewEncryptionKeyFun) ->
    ?log_debug("Checking if ~p deks need reencryption. All deks "
               "must be encrypted with current active key", [Kind]),
    ToReencrypt =
        lists:filtermap(
          fun (Dek) ->
                  case NewEncryptionKeyFun(Dek) of
                      {true, V} -> {true, {Dek, V}};
                      false -> false
                  end
          end, Deks),
    case ToReencrypt of
        [] -> no_change;
        _ ->
            IdsToBeUsed = lists:usort(lists:map(
                                        fun ({_Dek, {SId, _KId}}) -> SId end,
                                        ToReencrypt)),
            [increment_counter_in_chronicle(Kind, Id) || Id <- IdsToBeUsed],
            Errors =
                lists:filtermap(
                  fun ({#{type := 'raw-aes-gcm',
                          id := DekId,
                          info := #{encryption_key_id := CurKekId,
                                    key := DekKey}}, {EncMethod, NewKekId}}) ->
                      ?log_debug("Dek ~p is encrypted with ~p, "
                                 "while correct kek is ~p (~p), will reencrypt",
                                 [DekId, CurKekId, NewKekId, EncMethod]),
                      case encryption_service:store_dek(
                             Kind, DekId, DekKey(), NewKekId) of
                          ok -> false;
                          {error, Reason} ->
                              ?log_error("Failed to store key ~p on disk: "
                                         "~p", [DekId, Reason]),
                              {true, {DekId, Reason}}
                      end
                  end, ToReencrypt),
            {changed, Errors}
    end.

increment_counter_in_chronicle(Kind, SecretId) ->
    {ok, _} =
        chronicle_kv:transaction(
          kv, [?CHRONICLE_DEK_COUNTERS_KEY],
          fun (Snapshot) ->
               All = chronicle_compat:get(Snapshot,
                                          ?CHRONICLE_DEK_COUNTERS_KEY,
                                          #{default => #{}}),
               SecretCounters = maps:get(SecretId, All, #{}),
               Counter = maps:get(Kind, SecretCounters, 0),
               NewSecretCounters = SecretCounters#{Kind => Counter + 1},
               NewDEKCounters = All#{SecretId => NewSecretCounters},
               {commit, [{set, ?CHRONICLE_DEK_COUNTERS_KEY, NewDEKCounters}]}
          end),
    ok.

%% Chronicle keys that can trigger dek reencryption, enablement/disablement
%% of encryption, etc...
%% Returns a dek kind that is affected by a given chronicle key.
%% Returns false otherwise.
dek_chronicle_keys_filter(?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY) ->
    [chronicleDek, configDek];
dek_chronicle_keys_filter(Key) ->
    case ns_bucket:sub_key_match(Key) of
        {true, Bucket, props} -> [{bucketDek, Bucket}];
        {true, _Bucket, _} -> false;
        false -> false
    end.

%% encryption_method_callback - called to determine if encryption is enabled
%% or not for that type of entity.
%% Parameters: Chronicle snapshot that contains all chronicle_txn_keys.
%% Returns {secret, Id} | encryption_service | disabled.
%% Must be lightweight, as it can be called often.
%%
%% set_active_key_callback - called to set active encryption key.
%% Parameters: undefined | cb_deks:dek().
%% Returns ok if the set is successfull, {error, Reason} if set fails.
%% undefined means encryption must be disabled.
%% Must be idempotent (can be called with a dek that is already in use).
%% Must be lightweight if the dek is already in use.
%%
%% chronicle_txn_keys - list of chronicle keys that is needed to determine
%% state of encryption for a given entity
%%
%% required_usage - the secret usage that secret must contain in order to be
%% allowed to encrypt this kind of deks
dek_config(chronicleDek) ->
    #{name => chronicle,
      encryption_method_callback => cb_crypto:get_encryption_method(
                                      config_encryption, _),
      set_active_key_callback => fun chronicle_local:set_active_dek/1,
      chronicle_txn_keys => [?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
      required_usage => config_encryption};
dek_config(configDek) ->
    #{name => configuration,
      encryption_method_callback => cb_crypto:get_encryption_method(
                                      config_encryption, _),
      set_active_key_callback => fun (_) ->
                                     ok
                                 end,
      chronicle_txn_keys => [?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
      required_usage => config_encryption};
dek_config({bucketDek, Bucket}) ->
    #{name => {bucket, Bucket},
      encryption_method_callback => ns_bucket:get_encryption(Bucket, _),
      set_active_key_callback => ns_memcached:set_active_dek(Bucket, _),
      chronicle_txn_keys => [ns_bucket:root(),
                             ns_bucket:sub_key(Bucket, props)],
      required_usage => {bucket_encryption, Bucket}}.

%% Returns all possible deks kinds on the node.
%% The list was supposed to be static if not buckets. Buckets can be created and
%% removed in real time, so the list is dynamic because of that. Note that the
%% list doesn't depend if encryption is on or off.
dek_kinds_list() ->
    dek_kinds_list(direct).
dek_kinds_list(Snapshot) ->
    Buckets = ns_bucket:get_bucket_names(Snapshot),
    [chronicleDek, configDek] ++ [{bucketDek, B} || B <- Buckets].
