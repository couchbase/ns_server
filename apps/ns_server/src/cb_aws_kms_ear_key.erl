%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_aws_kms_ear_key).

-behaviour(cb_cluster_secrets).

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").

-export([prepare_new_props/2,
         modify_props/2,
         sanitize_props/1,
         persist/2,
         generate_key/1,
         set_new_active_key_in_props/2,
         historical_keys_to_remove_from_props/1,
         get_next_rotation_time_from_props/1,
         maybe_update_next_rotation_time_in_props/2,
         remove_historical_key_from_props/2,
         test_props/2,
         is_encrypted_by_secret_manager/1,
         get_active_key_id_from_props/1,
         get_all_key_ids_from_props/1,
         get_key_ids_that_encrypt_props/1,
         get_secret_ids_that_encrypt_props/1,
         get_props_encryption_method/1,
         maybe_reencrypt_props/3]).

-export_type([secret_props/0]).

-type secret_props() :: #{key_arn := string(),
                          region := string(),
                          profile := string(),
                          config_file := string(),
                          credentials_file := string(),
                          use_imds := boolean(),
                          stored_ids := [key_props()],
                          last_rotation_time := calendar:datetime()}.

-type key_props() :: #{id := cb_cluster_secrets:key_id(),
                       creation_time := calendar:datetime()}.

-spec prepare_new_props(calendar:datetime(), map()) -> secret_props().
prepare_new_props(CreationTime, PropsFromValidator) ->
    {ok, Key} = generate_key(CreationTime),
    PropsFromValidator#{stored_ids => [Key]}.

-spec modify_props(secret_props(), map()) -> secret_props().
modify_props(OldProps, PropsFromValidator) ->
    #{stored_ids := StoredIds} = OldProps,
    LastRotationTime = maps:get(last_rotation_time, OldProps, undefined),
    set_last_rotation_time_in_props(
        PropsFromValidator#{stored_ids => StoredIds},
        LastRotationTime).

-spec sanitize_props(secret_props()) -> secret_props().
sanitize_props(Props) ->
    Props.

-spec persist(secret_props(), binary()) -> ok | {error, _}.
persist(Props, _ExtraAD) ->
    ensure_aws_kek_on_disk(Props, false).

-spec generate_key(calendar:datetime()) -> {ok, key_props()}.
generate_key(CreationTime) ->
    {ok, #{id => cb_cluster_secrets:new_key_id(),
           creation_time => CreationTime}}.

-spec set_new_active_key_in_props(key_props(), secret_props()) ->
          secret_props().
set_new_active_key_in_props(Key, #{stored_ids := StoredIds} = Props) ->
    Time = calendar:universal_time(),
    NewStoredIds = [Key | StoredIds],
    set_last_rotation_time_in_props(Props#{stored_ids => NewStoredIds}, Time).

-spec historical_keys_to_remove_from_props(secret_props()) ->
          [cb_cluster_secrets:key_id()].
historical_keys_to_remove_from_props(#{stored_ids := StoredIds}) ->
    [Id || #{id := Id} <- tl(StoredIds)].

-spec get_next_rotation_time_from_props(secret_props()) -> undefined.
get_next_rotation_time_from_props(#{}) ->
    undefined.

-spec maybe_update_next_rotation_time_in_props(secret_props(),
                                               calendar:datetime()) ->
          {error, not_supported}.
maybe_update_next_rotation_time_in_props(_Props, _CurTime) ->
    {error, not_supported}.

-spec remove_historical_key_from_props(secret_props(),
                                       cb_cluster_secrets:key_id()) ->
          {ok, secret_props()} | {error, active_key | not_found}.
remove_historical_key_from_props(Props, KeyId) ->
    #{stored_ids := [#{id := ActiveId} | _] = StoredIds} = Props,
    case ActiveId of
        KeyId -> {error, active_key};
        _ ->
            NewStoredIds = lists:filter(fun(#{id := Id}) -> Id =/= KeyId end,
                                        StoredIds),
            case length(NewStoredIds) =:= length(StoredIds) of
                true -> {error, not_found};
                false -> {ok, Props#{stored_ids => NewStoredIds}}
            end
    end.

-spec test_props(secret_props(), binary()) -> ok | {error, _}.
test_props(#{stored_ids := [StoredId | _]} = Props, _ExtraAD) ->
    %% We don't want to test all stored ids
    PropsWithoutHistKeys = Props#{stored_ids => [StoredId]},
    case ensure_aws_kek_on_disk(PropsWithoutHistKeys, true) of
        ok -> ok;
        {error, [{_, Reason}]} -> {error, Reason};
        {error, _} = E -> E
    end.

-spec is_encrypted_by_secret_manager(secret_props()) -> false.
is_encrypted_by_secret_manager(#{}) ->
    false.

-spec get_active_key_id_from_props(secret_props()) ->
          {ok, cb_cluster_secrets:key_id()}.
get_active_key_id_from_props(#{stored_ids := [#{id := Id} | _]}) ->
    {ok, Id}.

-spec get_all_key_ids_from_props(secret_props()) ->
          [cb_cluster_secrets:key_id()].
get_all_key_ids_from_props(#{stored_ids := StoredIds}) ->
    lists:map(fun (#{id := Id}) -> Id end, StoredIds).

-spec get_key_ids_that_encrypt_props(secret_props()) -> [].
get_key_ids_that_encrypt_props(#{}) ->
    [].

-spec get_secret_ids_that_encrypt_props(secret_props()) -> [].
get_secret_ids_that_encrypt_props(#{}) ->
    [].

-spec get_props_encryption_method(secret_props()) -> disabled.
get_props_encryption_method(#{}) ->
    disabled.

-spec maybe_reencrypt_props(secret_props(),
                            cb_cluster_secrets:get_active_id_fun(),
                            binary()) -> no_change.
maybe_reencrypt_props(_Props, _GetActiveId, _ExtraAD) ->
    no_change.

%%%===================================================================
%%% Internal functions
%%%===================================================================

set_last_rotation_time_in_props(Props, undefined) ->
    Props;
set_last_rotation_time_in_props(Props, CurUTCTime) ->
    Props#{last_rotation_time => CurUTCTime}.

ensure_aws_kek_on_disk(#{stored_ids := StoredIds} = Props, TestOnly) ->
    Params = maps:with([key_arn, region, profile, config_file,
                        credentials_file, use_imds], Props),
    Res = lists:map(
            fun (#{id := Id, creation_time := CreationTime}) ->
                {Id, encryption_service:store_aws_key(Id, Params, CreationTime,
                                                      TestOnly)}
            end, StoredIds),
    misc:many_to_one_result(Res).