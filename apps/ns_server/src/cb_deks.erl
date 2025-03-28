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
         read/2,
         generate_new/3,
         handle_ale_log_dek_update/1,
         maybe_reencrypt_deks/4,
         dek_cluster_kinds_list/0,
         dek_cluster_kinds_list/1,
         dek_kinds_list_existing_on_node/1,
         dek_config/1,
         dek_chronicle_keys_filter/1,
         kind2bin/1,
         kind2datatype/1]).

-export_type([dek_id/0, dek/0, dek_kind/0, encryption_method/0]).

-define(LOG_ENCR_RPC_TIMEOUT, ?get_timeout(log_encr_rpc_timeout, 60000)).

-type encryption_method() :: {secret, cb_cluster_secrets:secret_id()} |
                             encryption_service |
                             disabled.
-type dek_id() :: cb_cluster_secrets:key_id().
-type dek_kind() :: kek | configDek | logDek | auditDek |
                    {bucketDek, string()}.
-type good_dek() :: #{id := dek_id(), type := 'raw-aes-gcm',
                      info := #{key := fun(() -> binary()),
                               encryption_key_id := cb_cluster_secrets:key_id(),
                               creation_time := calendar:datetime()}}.
-type bad_dek() :: #{id := dek_id(), type := error, reason := term()}.
-type dek() :: good_dek() | bad_dek().

-spec list(dek_kind()) ->
    {ok, {undefined | dek_id(), [dek_id()], boolean()}} | {error, _}.
list(Kind) ->
    GetCfgDekFun = encryption_service:read_dek(configDek, _),
    VerifyMac = fun encryption_service:verify_mac/2,
    ?log_debug("Reading list of ~p deks...", [Kind]),
    case cb_deks_raw_utils:external_list(Kind, GetCfgDekFun, VerifyMac, #{}) of
        {ok, {ActiveKeyId, AllIds, IsEnabled}} ->
            ?log_debug("~p DEK read res: Active: ~0p, AllIds: ~0p, "
                       "IsEnabled: ~0p",
                       [Kind, ActiveKeyId, AllIds, IsEnabled]),
            {ok, {ActiveKeyId, AllIds, IsEnabled}};
        {error, {read_dek_cfg_file_error, {Path, Reason}}} = Error ->
            ?log_error("Failed to read dek cfg file \"~s\": ~p",
                       [Path, Reason]),
            Error
    end.

-spec read(dek_kind(), [dek_id()]) -> [dek()].
read(Kind, DekIds) ->
    ?log_debug("Reading the following keys (~p) from disk: ~p", [Kind, DekIds]),
    lists:map(
        fun (DekId) when is_binary(DekId) ->
            case encryption_service:read_dek(Kind, DekId) of
                {ok, B} -> B;
                {error, R} ->
                    ?log_error("Failed to read key ~s: ~p", [DekId, R]),
                    #{id => DekId, type => error, reason => R}
            end
        end, DekIds).

-spec generate_new(dek_kind(), {secret, Id} | encryption_service,
                   cb_cluster_secrets:chronicle_snapshot()) ->
        {ok, dek_id()} | {error, _} when Id :: cb_cluster_secrets:secret_id().
generate_new(Kind, encryption_service, _Snapshot) ->
    maybe
        ok ?= increment_dek_encryption_counter(Kind, encryption_service),
        new(Kind, <<"encryptionService">>)
    end;
generate_new(Kind, {secret, Id}, Snapshot) ->
    maybe
        ok ?= increment_dek_encryption_counter(Kind, {secret, Id}),
        {ok, KekId} ?= cb_cluster_secrets:get_active_key_id(Id, Snapshot),
        new(Kind, KekId)
    end.

-spec new(dek_kind(), cb_cluster_secrets:key_id()) ->
                                                    {ok, dek_id()} | {error, _}.
new(Kind, KekIdToEncrypt) ->
    Id = cb_cluster_secrets:new_key_id(),
    ?log_debug("Generating new dek (~p): ~p", [Kind, Id]),
    Bin = cb_cluster_secrets:generate_raw_key(aes_256_gcm),
    CreateTime = calendar:universal_time(),
    case encryption_service:store_dek(Kind, Id, Bin, KekIdToEncrypt,
                                      CreateTime) of
        ok -> {ok, Id};
        {error, Reason} ->
            ?log_error("Failed to store key ~p on disk: ~p", [Id, Reason]),
            {error, Reason}
    end.

-spec maybe_reencrypt_deks(dek_kind(), [dek()], encryption_method(),
                           cb_cluster_secrets:chronicle_snapshot()) ->
          no_change | %% nothing changed
          {changed, [dek_id()], [Error :: term()]} |
          {error, term()}.
maybe_reencrypt_deks(_Kind, [], disabled, _Snapshot) -> no_change;
maybe_reencrypt_deks(_Kind, [], _, _Snapshot) -> {changed, [], []};
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
                          %% When node is leaving the cluster, configuration
                          %% gets wiped out, so all KEKs disappear.
                          %% We should simply reencrypt all DEKs with the
                          %% encryption service in this case, as this is the
                          %% only key that is available no matter what.
                          ?log_warning(
                            "Orphaned key: ~p, key ~p is missing "
                            "(will reencrypt with encryptionService) - this is "
                            "expected when node is leaving the cluster",
                            [Dek, CurKekId]),
                          {true, {encryption_service, <<"encryptionService">>}};
                      {error, Reason2} ->
                          ?log_error("Encryption secret is missing for dek: "
                                     "~p: ~p", [Dek, Reason2]),
                          {true, {encryption_service, <<"encryptionService">>}}
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
          fun (#{type := error}) -> false;
              (Dek) ->
                  case NewEncryptionKeyFun(Dek) of
                      {true, V} -> {true, {Dek, V}};
                      false -> false
                  end
          end, Deks),

    case ToReencrypt of
        [] -> no_change;
        _ ->
            %% Sleep to avoid coordinated writes to chronicle
            %% When KEK is rotated, all nodes start reencryption
            %% simultaneously, which causes N chronicle transactions
            %% to be started in parallel, causing a lot of retries, and
            %% possible exceeded_retries errors
            timer:sleep(rand:uniform(1000)),

            %% Group by EncMethod to increment counter only once per method
            ByEncMethod = maps:groups_from_list(
                            fun({_Dek, {EncMethod, _}}) -> EncMethod end,
                            fun({Dek, {_, NewKekId}}) -> {Dek, NewKekId} end,
                            ToReencrypt),

            {Changed, Errors} =
                lists:foldl(
                  fun ({EncMethod, DeksAndKekIds},
                          {ChangedAcc, ErrorsAcc}) ->
                      {NewChanged, NewErrors} =
                          store_deks_reencrypted(Kind, EncMethod,
                                                 DeksAndKekIds),
                      {ChangedAcc ++ NewChanged, ErrorsAcc ++ NewErrors}
                  end, {[], []}, maps:to_list(ByEncMethod)),
            {changed, Changed, Errors}
    end.

-spec store_deks_reencrypted(dek_kind(), encryption_method(),
                             [{dek(), cb_cluster_secrets:key_id()}]) ->
    {[dek_id()], [{dek_id(), term()}]}.
store_deks_reencrypted(Kind, EncMethod, DeksAndKekIds) ->
    %% Increment counter once per encryption method
    case increment_dek_encryption_counter(Kind, EncMethod) of
        ok ->
            %% Process all DEKs for this method
            misc:partitionmap(
                fun ({#{type := 'raw-aes-gcm',
                    id := DekId,
                    info := #{encryption_key_id := CurKekId,
                            key := DekKey,
                            creation_time := CT}},
                    NewKekId}) ->
                    ?log_debug("Dek ~p is encrypted with ~p, "
                                "while correct kek is ~p (~p), "
                                "will reencrypt",
                                [DekId, CurKekId, NewKekId,
                                EncMethod]),
                    maybe
                        ok ?= encryption_service:store_dek(
                                Kind, DekId, DekKey(), NewKekId,
                                CT),
                        {left, DekId}
                    else
                        {error, Reason} ->
                            ?log_error("Failed to reencrypt "
                                        "dek ~p: ~p",
                                        [DekId, Reason]),
                            {right, {DekId, Reason}}
                    end
                end, DeksAndKekIds);
        {error, R} ->
            ?log_error("Failed to increment dek encryption "
                        "counter for ~p deks: ~p", [Kind, R]),
            {[], lists:map(fun ({#{id := DekId}, _}) ->
                               {DekId, R}
                           end, DeksAndKekIds)}
    end.

increment_dek_encryption_counter(Kind, SecretId) ->
    cb_cluster_secrets:chronicle_transaction(
      [?CHRONICLE_DEK_COUNTERS_KEY],
      fun (Snapshot) ->
           All = chronicle_compat:get(Snapshot,
                                      ?CHRONICLE_DEK_COUNTERS_KEY,
                                      #{default => #{}}),
           NewDEKCounters = increment_dek_encryption_counter(Kind, SecretId,
                                                             All),
           {commit, [{set, ?CHRONICLE_DEK_COUNTERS_KEY, NewDEKCounters}]}
      end).

-spec increment_dek_encryption_counter(
        dek_kind(),
        cb_cluster_secrets:secret_id(),
        cb_cluster_secrets:dek_encryption_counters()) ->
          cb_cluster_secrets:dek_encryption_counters().
increment_dek_encryption_counter(Kind, SecretId, AllCounters) ->
    SecretCounters = maps:get(SecretId, AllCounters, #{}),
    {Counter, _Rev} = maps:get(Kind, SecretCounters, {0, undefined}),
    NewRev = rand:uniform(16#FFFFFFFF),
    NewSecretCounters = SecretCounters#{Kind => {Counter + 1, NewRev}},
    AllCounters#{SecretId => NewSecretCounters}.

%% Chronicle keys that can trigger dek reencryption, enablement/disablement
%% of encryption, etc...
%% Returns a dek kind that is affected by a given chronicle key.
%% Returns false otherwise.
dek_chronicle_keys_filter(?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY) ->
    [configDek, logDek, auditDek];
dek_chronicle_keys_filter(Key) ->
    MembershipKeys = ns_cluster_membership:node_membership_keys(node()),
    lists:uniq(
        case ns_bucket:sub_key_match(Key) of
            {true, Bucket, props} -> [{bucketDek, Bucket}];
            {true, Bucket, encr_at_rest} -> [{bucketDek, Bucket}];
            {true, _Bucket, _} -> [];
            false -> []
        end ++
        case lists:member(Key, MembershipKeys) of
            true ->
                Buckets = ns_bucket:get_bucket_names(direct),
                [{bucketDek, B} || B <- Buckets];
            false ->
                []
        end).

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
-spec dek_config(dek_kind()) ->
    #{encryption_method_callback :=
        fun( (Snapshot) -> {ok, encryption_method()} | {error, not_found} ),
      set_active_key_callback :=
        fun ( (undefined | dek_id()) -> ok | {error, _}),
      lifetime_callback :=
        fun ( (Snapshot) -> {ok, IntOrUndefined} | {error, not_found} ),
      rotation_int_callback :=
        fun ( (Snapshot) -> {ok, IntOrUndefined} | {error, not_found} ),
      drop_keys_timestamp_callback :=
        fun ( (Snapshot) -> {ok, IntOrUndefined} | {error, not_found} ),
      get_ids_in_use_callback :=
        fun ( () -> {ok, Ids} | {error, not_found | _}),
      drop_callback :=
        fun ( (Ids) -> {ok, done | started} | {error, not_found | retry | _} ) |
        not_supported,
      chronicle_txn_keys := [term()],
      required_usage := cb_cluster_secrets:secret_usage()
     } when Ids :: [dek_id()],
            Snapshot :: cb_cluster_secrets:chronicle_snapshot(),
            IntOrUndefined :: undefined | pos_integer().
dek_config(configDek) ->
    #{encryption_method_callback => cb_crypto:get_encryption_method(
                                      config_encryption, _),
      set_active_key_callback => fun set_config_active_key/1,
      lifetime_callback => cb_crypto:get_dek_kind_lifetime(
                             config_encryption, _),
      rotation_int_callback => cb_crypto:get_dek_rotation_interval(
                                 config_encryption, _),
      drop_keys_timestamp_callback => cb_crypto:get_drop_keys_timestamp(
                                        config_encryption, _),
      get_ids_in_use_callback => ?cut(get_config_dek_ids_in_use()),
      drop_callback => fun drop_config_deks/1,
      chronicle_txn_keys => [?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
      required_usage => config_encryption};
dek_config(logDek) ->
    #{encryption_method_callback => cb_crypto:get_encryption_method(
                                      log_encryption, _),
      set_active_key_callback => fun set_log_active_key/1,
      lifetime_callback => cb_crypto:get_dek_kind_lifetime(
                             log_encryption, _),
      rotation_int_callback => cb_crypto:get_dek_rotation_interval(
                                 log_encryption, _),
      drop_keys_timestamp_callback => cb_crypto:get_drop_keys_timestamp(
                                        log_encryption, _),
      get_ids_in_use_callback => ?cut(get_dek_ids_in_use(logDek)),
      drop_callback => not_supported,
      chronicle_txn_keys => [?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
      required_usage => log_encryption};
dek_config(auditDek) ->
    #{encryption_method_callback => cb_crypto:get_encryption_method(
                                      audit_encryption, _),
      set_active_key_callback => fun (_) ->
                                     push_memcached_dek("@audit", auditDek)
                                 end,
      lifetime_callback => cb_crypto:get_dek_kind_lifetime(
                             audit_encryption, _),
      rotation_int_callback => cb_crypto:get_dek_rotation_interval(
                                 audit_encryption, _),
      drop_keys_timestamp_callback => cb_crypto:get_drop_keys_timestamp(
                                        audit_encryption, _),
      get_ids_in_use_callback => ?cut(get_dek_ids_in_use(auditDek)),
      drop_callback => not_supported,
      chronicle_txn_keys => [?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
      required_usage => audit_encryption};
dek_config({bucketDek, Bucket}) ->
    #{encryption_method_callback => ns_bucket:get_encryption(Bucket, _),
      set_active_key_callback => ns_memcached:set_active_dek_for_bucket(Bucket,
                                                                        _),
      lifetime_callback => ns_bucket:get_dek_lifetime(Bucket, _),
      rotation_int_callback => ns_bucket:get_dek_rotation_interval(Bucket, _),
      drop_keys_timestamp_callback => ns_bucket:get_drop_keys_timestamp(Bucket,
                                                                        _),
      get_ids_in_use_callback => fun () ->
                                     ns_memcached:get_dek_ids_in_use(Bucket)
                                 end,
      drop_callback => drop_bucket_deks(Bucket, _),
      chronicle_txn_keys =>
          [ns_bucket:root(),
           ns_bucket:sub_key(Bucket, props),
           ns_bucket:sub_key(Bucket, encr_at_rest) |
           ns_cluster_membership:node_membership_keys(node())],
      required_usage => {bucket_encryption, Bucket}}.

%% Returns all possible deks kinds for this cluster.
%% The list was supposed to be static if not buckets. Buckets can be created and
%% removed in real time, so the list is dynamic because of that. Note that the
%% list doesn't depend if encryption is on or off.
dek_cluster_kinds_list() ->
    dek_cluster_kinds_list(direct).
dek_cluster_kinds_list(Snapshot) ->
    Buckets = ns_bucket:get_bucket_names(Snapshot),
    [configDek, logDek, auditDek] ++
    [{bucketDek, B} || B <- Buckets].

dek_kinds_list_existing_on_node(Snapshot) ->
    AllKinds = dek_cluster_kinds_list(Snapshot),
    lists:filter(
        fun(Kind) ->
            #{encryption_method_callback := GetMethod} = dek_config(Kind),
            case GetMethod(Snapshot) of
                {ok, _} -> true;
                {error, not_found} -> false
            end
        end,
        AllKinds).

set_config_active_key(_ActiveDek) ->
    force_config_encryption_keys().

push_memcached_dek(MemcachedDekName, Kind) ->
    {ok, LogDeksSnapshot} = cb_crypto:fetch_deks_snapshot(Kind),
    ns_memcached:set_active_dek(MemcachedDekName, LogDeksSnapshot).

handle_ale_log_dek_update(CreateNewDS) ->
    Old = ale:get_global_log_deks_snapshot(),
    New = CreateNewDS(Old),
    case (cb_crypto:get_dek_id(Old) /= cb_crypto:get_dek_id(New)) of
        true ->
            ale:set_log_deks_snapshot(New);
        false ->
            ok
    end.

set_log_active_key(_ActiveKey) ->
    %% DS can't be shared across nodes since it has atomic references, so we
    %% pass in function to allow local nodes to create DS based on same keys
    {ok, CurrDS} = cb_crypto:fetch_deks_snapshot(logDek),
    CreateNewDS =
        fun(PrevDS) ->
                {ActiveKey, AllKeys} = cb_crypto:get_all_deks(CurrDS),
                cb_crypto:create_deks_snapshot(ActiveKey, AllKeys, PrevDS)
        end,

    maybe
        %% Push the dek update to the local memcached instance
        ok ?= ns_memcached:set_active_dek("@logs", CurrDS),

        %% Push the dek update locally to ns_server disk sinks
        ok ?= handle_ale_log_dek_update(CreateNewDS),

        %% Push the dek update to babysitter node disk sinks
        ok ?= rpc:call(ns_server:get_babysitter_node(), cb_deks,
                       handle_ale_log_dek_update, [CreateNewDS],
                       ?LOG_ENCR_RPC_TIMEOUT),

        %% Push the dek update to couchdb node disk sinks
        ok ?= rpc:call(ns_node_disco:couchdb_node(), cb_deks,
                       handle_ale_log_dek_update, [CreateNewDS],
                       ?LOG_ENCR_RPC_TIMEOUT),

        %% Reencrypt all rebalance reports local to this node based on CurrentDS
        ok ?= ns_rebalance_report_manager:reencrypt_local_reports(CurrDS)
    else
        {error, _} = Error ->
            Error;
        {badrpc, _} = Error ->
            {error, Error}
    end.

force_config_encryption_keys() ->
    maybe
        %% How it works:
        %%  1. memcached_config_mgr pushes new keys to memcached and saves the
        %%     DekSnapshot in persistent_term memcached_native_encryption_deks.
        %%     This persistent_term determines DEKs that memcached knows about.
        %%     Only these DEKs can be used for encryption of files that are
        %%     to be read by memcached
        %%  2. memcached_config_mgr reloads memcached.json encrypted by the new
        %%     dek
        %%  3. password and permissions files get reencrypted on disk
        %%     (sync_reload) with the DekSnapshot taken from
        %%     memcached_native_encryption_deks
        %%  4. all historical keys in memcached_native_encryption_deks get
        %%     dropped, because old deks are not used anywhere
        ok ?= memcached_config_mgr:push_config_encryption_key(true),
        ok ?= memcached_passwords:sync_reload(),
        ok ?= memcached_permissions:sync_reload(),
        ok ?= memcached_config_mgr:drop_historical_deks(),
        ok ?= ns_config:resave(),
        ok ?= menelaus_users:apply_keys_and_resave(),
        ok ?= menelaus_local_auth:resave(),
        ok ?= simple_store:resave(?XDCR_CHECKPOINT_STORE),
        ok ?= chronicle_local:maybe_apply_new_keys(),
        ok ?= ns_ssl_services_setup:resave_encrypted_files(),
        ok ?= encryption_service:remove_old_integrity_tokens(
                [kek | dek_kinds_list_existing_on_node(direct)]),
        ok
    end.

get_config_dek_ids_in_use() ->
    maybe
        {ok, Ids1} ?= memcached_config_mgr:get_key_ids_in_use(),
        {ok, Ids2} ?= memcached_passwords:get_key_ids_in_use(),
        {ok, Ids3} ?= memcached_permissions:get_key_ids_in_use(),
        {ok, Ids4} ?= ns_config:get_key_ids_in_use(),
        {ok, Ids5} ?= menelaus_users:get_key_ids_in_use(),
        {ok, Ids6} ?= menelaus_local_auth:get_key_ids_in_use(),
        {ok, Ids7} ?= simple_store:get_key_ids_in_use(?XDCR_CHECKPOINT_STORE),
        {ok, Ids8} ?= chronicle_local:get_encryption_dek_ids(),
        {ok, Ids9} ?= ns_ssl_services_setup:get_key_ids_in_use(),
        {ok, Ids10} ?= encryption_service:get_key_ids_in_use(),
        {ok, lists:map(fun (undefined) -> ?NULL_DEK;
                           (Id) -> Id
                       end, lists:uniq(Ids1 ++ Ids2 ++ Ids3 ++ Ids4 ++ Ids5 ++
                                       Ids6 ++ Ids7 ++ Ids8 ++ Ids9 ++ Ids10))}
    end.

get_dek_ids_in_use(logDek) ->
    maybe
        {ok, InUseMemcached} ?= ns_memcached:get_dek_ids_in_use("@logs"),

        {ok, InUseLocal} ?= ale:get_all_used_deks(),

        {ok, InuseBabySitter} ?= rpc:call(ns_server:get_babysitter_node(),
                                          ale, get_all_used_deks, [],
                                          ?LOG_ENCR_RPC_TIMEOUT),

        {ok, InuseCouchDb} ?= rpc:call(ns_node_disco:couchdb_node(),
                                       ale, get_all_used_deks, [],
                                       ?LOG_ENCR_RPC_TIMEOUT),

        {ok, InUseRebReports} ?= ns_rebalance_report_manager:get_in_use_deks(),

        AllInUse = lists:map(
                      fun(undefined) ->
                              ?NULL_DEK;
                         (Elem) ->
                              Elem
                      end, InUseMemcached ++ InUseLocal ++ InuseBabySitter ++
                           InuseCouchDb ++ InUseRebReports),
        {ok, lists:usort(AllInUse)}
    else
        {error, _} = Error ->
            Error;
        {badrpc, _} = Error ->
            {error, Error}
    end;
get_dek_ids_in_use(auditDek) ->
    ns_memcached:get_dek_ids_in_use("@audit").

drop_config_deks(DekIdsToDrop) ->
    maybe
        ok ?= force_config_encryption_keys(),
        {ok, DekIdsInUse} ?= get_config_dek_ids_in_use(),
        StillInUse = [Id || Id <- DekIdsInUse, lists:member(Id, DekIdsToDrop)],
        case StillInUse of
            [] -> {ok, done};
            [_ | _] -> {error, {still_in_use, StillInUse}}
        end
    end.

drop_bucket_deks(Bucket, DekIds) ->
    Continuation = fun (_) ->
                       cb_cluster_secrets:dek_drop_complete({bucketDek, Bucket})
                   end,
    ns_memcached:drop_deks(Bucket, DekIds, cb_cluster_secrets, Continuation).

kind2bin({bucketDek, B}) -> iolist_to_binary(["bucketDek_", B]);
kind2bin(K) -> atom_to_binary(K).

kind2datatype({bucketDek, B}) -> iolist_to_binary(["bucket_", B]);
kind2datatype(bucketDek) -> <<"bucket_data">>;
kind2datatype(kek) -> <<"keys">>;
kind2datatype(configDek) -> <<"config">>;
kind2datatype(logDek) -> <<"logs">>;
kind2datatype(auditDek) -> <<"audit">>.
