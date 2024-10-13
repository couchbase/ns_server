%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

%% @doc rest api's for cluster secrets

-module(menelaus_web_secrets).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-include("cb_cluster_secrets.hrl").
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([handle_get_secrets/1,
         handle_get_secret/2,
         handle_post_secret/1,
         handle_put_secret/2,
         handle_delete_secret/2,
         handle_rotate/2]).

handle_get_secrets(Req) ->
    All = cb_cluster_secrets:get_all(),
    FilteredSecrets = read_filter_secrets_by_permission(All, Req),
    Res = lists:map(
            fun (Props) ->
                {export_secret(Props)}
            end, FilteredSecrets),
    menelaus_util:reply_json(Req, Res).

handle_get_secret(IdStr, Req) when is_list(IdStr) ->
    case cb_cluster_secrets:get_secret(parse_id(IdStr)) of
        {ok, Props} ->
            case read_filter_secrets_by_permission([Props], Req) of
                [] -> menelaus_util:reply_not_found(Req);
                [_] ->
                    Res = {export_secret(Props)},
                    menelaus_util:reply_json(Req, Res)
            end;
        {error, not_found} ->
            menelaus_util:reply_not_found(Req)
    end.

handle_post_secret(Req) ->
    validator:handle(
      fun (RawProps) ->
          maybe
              ToAdd = import_secret(RawProps),
              true ?= is_writable(ToAdd, Req),
              {ok, Res} ?= cb_cluster_secrets:add_new_secret(ToAdd),
              Formatted = export_secret(Res),
              menelaus_util:reply_json(Req, {Formatted})
          else
              false ->
                  menelaus_util:web_exception(403, "Forbidden");
              {error, Reason} ->
                  menelaus_util:reply_global_error(Req, format_error(Reason))
          end
      end, Req, json, secret_validators(#{})).

handle_put_secret(IdStr, Req) ->
    Id = parse_id(IdStr),
    case cb_cluster_secrets:get_secret(Id) of
        {ok, CurProps} ->
            validator:handle(
              fun (RawProps) ->
                  maybe
                      Props = import_secret(RawProps),
                      %% Note: All "usages" should be writable by current user.
                      %% This includes "new usages" (usages that are being set)
                      %% and "old usages" (usages that are being replaced)
                      %% Checking "new usages" here:
                      true ?= is_writable(Props, Req),
                      %% replace_secret will check "old usages" inside txn
                      {ok, Res} ?= cb_cluster_secrets:replace_secret(
                                     Id, Props, is_writable(_, Req)),
                      Formatted = export_secret(Res),
                      menelaus_util:reply_json(Req, {Formatted})
                  else
                      false ->
                          menelaus_util:web_exception(403, "Forbidden");
                      {error, forbidden} ->
                          menelaus_util:web_exception(403, "Forbidden");
                      {error, not_found} ->
                          menelaus_util:reply_not_found(Req);
                      {error, Reason} ->
                          menelaus_util:reply_global_error(
                            Req, format_error(Reason))
                  end
              end, Req, json,
              secret_validators(CurProps));
        {error, not_found} ->
            %% We don't want PUT to create secrets because we generate id's
            menelaus_util:reply_not_found(Req)
    end.

%% Note: CurProps can only be used for static fields validation here.
%% Any field that can be modified and needs to use CurProps should be
%% checked in transaction in cb_cluster_secret:replace_secret_internal.
secret_validators(CurProps) ->
    [validator:string(name, _),
     validator:required(name, _),
     validator:validate(
       fun ("") -> {error, "Must not not be empty"};
           (Str) ->
               Id = maps:get(id, CurProps, ?SECRET_ID_NOT_SET),
               case cb_cluster_secrets:is_name_unique(Id, Str, direct) of
                   true -> ok;
                   %% Checking it here and inside transaction later
                   %% Check here is needed mostly to make it user friendly in UI
                   false -> {error, "Must be unique"}
               end
       end, name, _),
     validator:one_of(type, [?GENERATED_KEY_TYPE, ?AWSKMS_KEY_TYPE], _),
     validator:convert(type, binary_to_atom(_, latin1), _),
     validator:required(type, _),
     validate_key_usage(usage, _),
     validator:required(usage, _),
     validate_secrets_data(data, CurProps, _),
     validator:required(data, _)].

enforce_static_field_validator(Name, CurValue, State) ->
    validator:validate(fun (NewValue) when NewValue == CurValue -> ok;
                            (_) -> {error, "the field can't be changed"}
                       end, Name, State).

handle_delete_secret(IdStr, Req) ->
    case cb_cluster_secrets:delete_secret(parse_id(IdStr),
                                          is_writable(_, Req)) of
        ok ->
            menelaus_util:reply(Req, 200);
        {error, forbidden} ->
            menelaus_util:web_exception(403, "Forbidden");
        {error, not_found} ->
            menelaus_util:reply_not_found(Req);
        {error, {used_by, UsedByList}} ->
            Formatted = format_secrets_used_by_list(UsedByList),
            menelaus_util:reply_global_error(
              Req, io_lib:format("Can't be removed because ~s", [Formatted]))
    end.

handle_rotate(IdStr, Req) ->
    case cb_cluster_secrets:rotate(parse_id(IdStr)) of
        ok -> menelaus_util:reply(Req, 200);
        {error, not_found} ->
            menelaus_util:reply_not_found(Req);
        {error, Error} ->
            Msg = iolist_to_binary(io_lib:format("~p", [Error])),
            menelaus_util:reply(Req, Msg, 500, [])
    end.

keys_remap() ->
    #{creation_time => creationDateTime,
      rotation_interval_in_days => rotationIntervalInDays,
      next_rotation_time => nextRotationTime,
      last_rotation_time => lastRotationTime,
      auto_rotation => autoRotation,
      key_arn => keyARN,
      credentials_file => credentialsFile,
      config_file => configFile,
      use_imds => useIMDS,
      encrypt_by => encryptBy,
      encrypt_secret_id => encryptSecretId,
      stored_ids => storedKeyIds}.

keys_to_json(Term) ->
    transform_keys(keys_remap(), Term).

keys_from_json(Term) ->
    transform_keys(#{V => K || K := V <- keys_remap()}, Term).

transform_keys(Map, Term) ->
    generic:transformt(fun ({K, V}) -> {maps:get(K, Map, K), V};
                           (T) -> T
                       end, Term).

import_secret(Props) ->
    #{data := Data} = Map = maps:from_list(keys_from_json(Props)),
    Map#{data => maps:from_list(Data)}.

export_secret(#{type := DataType} = Props) ->
    keys_to_json(
      maps:to_list(
        maps:map(
          fun (id, Id) ->
                  Id;
              (name, Name) ->
                  iolist_to_binary(Name);
              (creation_time, DateTime) ->
                  format_datetime(DateTime);
              (type, T) ->
                  T;
              (usage, UList) ->
                  lists:map(
                    fun ({bucket_encryption, BucketName}) ->
                            iolist_to_binary([<<"bucket-encryption-">>,
                                              BucketName]);
                        (config_encryption) ->
                            <<"configuration-encryption">>;
                        (secrets_encryption) ->
                            <<"secrets-encryption">>;
                        (log_encryption) ->
                            <<"log-encryption">>
                    end, UList);
              (data, D) when DataType == ?GENERATED_KEY_TYPE ->
                  {format_auto_generated_key_data(D)};
              (data, D) when DataType == ?AWSKMS_KEY_TYPE ->
                  {format_aws_key_data(D)}
          end, Props))).

format_auto_generated_key_data(Props) ->
    ActiveKeyId = maps:get(active_key_id, Props),
    maps:to_list(
      maps:map(
        fun (auto_rotation, B) ->
                B;
            (rotation_interval_in_days, Interval) ->
                Interval;
            (next_rotation_time, DateTime) ->
                format_datetime(DateTime);
            (last_rotation_time, DateTime) ->
                format_datetime(DateTime);
            (encrypt_by, E) ->
                E;
            (encrypt_secret_id, SId) ->
                SId;
            (keys, Keys) ->
                lists:map(
                  fun (KeyProps) ->
                      {format_key(KeyProps, ActiveKeyId)}
                  end, Keys)
        end, maps:remove(active_key_id, Props))).

format_aws_key_data(Props) ->
    maps:to_list(
      maps:map(
        fun (key_arn, U) -> iolist_to_binary(U);
            (region, R) -> iolist_to_binary(R);
            (credentials_file, F) -> iolist_to_binary(F);
            (config_file, F) -> iolist_to_binary(F);
            (profile, P) -> iolist_to_binary(P);
            (use_imds, U) -> U;
            (last_rotation_time, DT) -> format_datetime(DT);
            (stored_ids, StoredIds) ->
                [{[{id, Id}, {creation_time, format_datetime(CT)}]}
                 || #{id := Id, creation_time := CT} <- StoredIds]
        end, Props)).

format_key(Props, ActiveKeyId) ->
    lists:flatmap(fun ({id, Id}) ->
                      [{id, Id}, {active, Id == ActiveKeyId}];
                  ({creation_time, DateTime}) ->
                      [{creation_time, format_datetime(DateTime)}];
                  ({active, Active}) ->
                      [{active, Active}];
                  ({key, {_, _Binary}}) ->
                      [{key, <<"******">>}]
              end, maps:to_list(maps:remove(encrypted_by, Props))).

format_datetime(DateTime) ->
    misc:utc_to_iso8601(DateTime, local).

validate_key_usage(Name, State) ->
    validator:string_array(
      Name,
      fun (Str) ->
          case iolist_to_binary(Str) of
              <<"bucket-encryption-", N/binary>> when size(N) > 0 ->
                  {value, {bucket_encryption, binary_to_list(N)}};
              <<"secrets-encryption">> ->
                  {value, secrets_encryption};
              <<"configuration-encryption">> ->
                  {value, config_encryption};
              <<"log-encryption">> ->
                  {value, log_encryption};
              _ ->
                  {error, "unknown usage"}
          end
      end, false, State).

%% Note: CurSecretProps can only be used for static fields validation here.
%% Any field that can be modified and needs to use CurProps should be
%% checked in transaction in cb_cluster_secret:replace_secret_internal.
validate_secrets_data(Name, CurSecretProps, State) ->
    Type = validator:get_value(type, State),
    CurType = maps:get(type, CurSecretProps, Type),
    case Type == CurType of
        true ->
            Validators =
                case Type of
                    ?GENERATED_KEY_TYPE ->
                        generated_key_validators(CurSecretProps);
                    ?AWSKMS_KEY_TYPE ->
                        awskms_key_validators(CurSecretProps);
                    _ -> []
                end,
            validator:decoded_json(
              Name,
              Validators ++ [validator:unsupported(_)],
              State);
        %% We can't call data validators because they assume
        %% the type of CurSecretProps
        false ->
            enforce_static_field_validator(type, CurType, State)
    end.

%% Note: CurSecretProps can only be used for static fields validation here.
%% Any field that can be modified and needs to use CurProps should be
%% checked in transaction in cb_cluster_secret:replace_secret_internal.
generated_key_validators(CurSecretProps) ->
    [validator:boolean(autoRotation, _),
     validator:default(autoRotation, true, _),
     validator:range(rotationIntervalInDays, 1, infinity, _),
     validate_iso8601_datetime(nextRotationTime, _),
     validate_datetime_in_the_future(nextRotationTime, _),
     mandatory_rotation_fields(_),
     validator:validate(fun (_) -> {error, "read only"} end, keys, _),
     validator:one_of(encryptBy, ["nodeSecretManager", "clusterSecret"], _),
     validator:convert(encryptBy, binary_to_atom(_, latin1), _),
     validate_encrypt_by(encryptBy, _),
     validator:default(encryptBy, nodeSecretManager, _),
     validator:integer(encryptSecretId, -1, infinity, _),
     validate_encrypt_secret_id(encryptSecretId, CurSecretProps, _)].

validate_encrypt_by(Name, State) ->
    validator:validate(
      fun (clusterSecret) ->
              case validator:get_value(encryptSecretId, State) of
                  undefined ->
                      {error, "encryptSecretId must be set when "
                              "'clusterSecret' is used"};
                  _ -> ok
              end;
          (nodeSecretManager) ->
              case cb_crypto:get_encryption_method(config_encryption, direct) of
                  {ok, disabled} ->
                      {error, format_error(config_encryption_disabled)};
                  {ok, _} ->
                      ok
              end
      end, Name, State).

validate_encrypt_secret_id(Name, CurSecretProps, State) ->
    CurId = case CurSecretProps of
                #{id := Id} -> Id;
                #{} when map_size(CurSecretProps) == 0 -> undefined
            end,
    validator:validate_relative(
      fun (?SECRET_ID_NOT_SET, nodeSecretManager) ->
              ok;
          (_, nodeSecretManager) ->
              {error, "can't be set when encryptBy is nodeSecretManager"};
          (EId, clusterSecret) when EId == CurId, CurId =/= undefined ->
              {error, "key can't encrypt itself"};
          (_EId, clusterSecret) ->
              ok
      end, Name, encryptBy, State).

%% Note: CurSecretProps can only be used for static fields validation here.
%% Any field that can be modified and needs to use CurProps should be
%% checked in transaction in cb_cluster_secret:replace_secret_internal.
awskms_key_validators(CurSecretProps) ->
    [validator:string(keyARN, _),
     validator:required(keyARN, _),
     validator:string(region, _),
     validator:default(region, "", _),
     validator:boolean(useIMDS, _),
     validator:default(useIMDS, false, _),
     validator:string(credentialsFile, _),
     validator:default(credentialsFile, "", _),
     validator:string(configFile, _),
     validator:default(configFile, "", _),
     validator:validate(fun (_) -> {error, "read only"} end, storedKeyIds, _),
     validator:string(profile, _),
     validator:default(profile, "", _)] ++
    case CurSecretProps of
        #{data := #{key_arn := KeyArn, region := Region}} ->
            [enforce_static_field_validator(keyARN, KeyArn, _),
             enforce_static_field_validator(region, Region, _)];
        #{} when map_size(CurSecretProps) == 0 ->
            []
    end.

mandatory_rotation_fields(State) ->
    case validator:get_value(autoRotation, State) of
        true ->
            functools:chain(State,
                            [validator:required(nextRotationTime, _),
                             validator:required(rotationIntervalInDays, _)]);
        false ->
            State
    end.

validate_iso8601_datetime(Name, State) ->
    validator:validate(
      fun (S) ->
          try
              {value, iso8601:parse(S)}
          catch
              _:_ ->
                  {error, "invalid ISO 8601 time"}
          end
      end, Name, State).

validate_datetime_in_the_future(Name, State) ->
    validator:validate(
      fun (DT) ->
          case DT > calendar:universal_time() of
              true -> ok;
              false -> {error, "must be in the future"}
          end
      end, Name, State).

is_usage_allowed({bucket_encryption, "*"}, write, Req) ->
    %% Those who can create a bucket should be able to create a secret to
    %% encrypt that bucket
    menelaus_auth:has_permission({[buckets], create}, Req) orelse
    menelaus_auth:has_permission({[admin, security], write}, Req);
is_usage_allowed({bucket_encryption, "*"}, read, Req) ->
    %% Those who can view bucket list should be able to view the secrets
    %% that can encrypt buckets
    menelaus_auth:has_permission({[{bucket, any}, settings], read}, Req) orelse
    menelaus_auth:has_permission({[admin, security], read}, Req);

is_usage_allowed({bucket_encryption, B}, write, Req) ->
    %% Those who can modify bucket settings should be able to create a secret
    %% that encrypts that specific bucket
    menelaus_auth:has_permission({[{bucket, B}, settings], write}, Req) orelse
    menelaus_auth:has_permission({[admin, security], write}, Req);
is_usage_allowed({bucket_encryption, B}, read, Req) ->
    %% Those who can read bucket settings should be able to see secrets that
    %% can encrypt that specific bucket
    menelaus_auth:has_permission({[{bucket, B}, settings], read}, Req) orelse
    menelaus_auth:has_permission({[admin, security], read}, Req);

is_usage_allowed(secrets_encryption, write, Req) ->
    menelaus_auth:has_permission({[admin, security], write}, Req);
is_usage_allowed(secrets_encryption, read, Req) ->
    menelaus_auth:has_permission({[admin, security], read}, Req);

is_usage_allowed(config_encryption, write, Req) ->
    menelaus_auth:has_permission({[admin, security], write}, Req);
is_usage_allowed(config_encryption, read, Req) ->
    menelaus_auth:has_permission({[admin, security], read}, Req);

is_usage_allowed(log_encryption, write, Req) ->
    menelaus_auth:has_permission({[admin, security], write}, Req);
is_usage_allowed(log_encryption, read, Req) ->
    menelaus_auth:has_permission({[admin, security], read}, Req).

read_filter_secrets_by_permission(Secrets, Req) ->
    lists:filter(is_readable(_, Req), Secrets).

is_readable(#{usage := Usages}, Req) when Usages /= [] ->
    lists:any(is_usage_allowed(_, read, Req), Usages).

is_writable(#{usage := Usages}, Req) when Usages /= [] ->
    lists:all(is_usage_allowed(_, write, Req), Usages).

parse_id(Str) when is_list(Str) ->
    try list_to_integer(Str) of
        N -> N
    catch
        _:_ ->
            menelaus_util:web_exception(404, menelaus_util:reply_text_404())
    end.

format_error({encrypt_id, not_found}) ->
    "Encryption secret does not exist";
format_error({encrypt_id, not_allowed}) ->
    "Encryption secret not allowed";
format_error({usage, in_use}) ->
    "Can't modify usage as this secret is in use";
format_error(name_not_unique) ->
    "Name is not unique";
format_error(config_encryption_disabled) ->
    "Can't use master password for encryption because "
    "config encryption is disabled";
format_error(Reason) ->
    lists:flatten(io_lib:format("~p", [Reason])).

format_secrets_used_by_list(UsedByMap) ->
    UsedByCfg = maps:get(by_config, UsedByMap, []),
    Secrets = maps:get(by_secrets, UsedByMap, []),
    UsedByDeks = maps:get(by_deks, UsedByMap, []),

    FormatUsages =
        fun (Usages) ->
                {Buckets, Other} = misc:partitionmap(
                                     fun ({bucket_encryption, B}) -> {left, B};
                                         (K) -> {right, K}
                                     end, Usages),
                FormattedUsages = lists:map(fun (config_encryption) ->
                                                    "configuration";
                                                (log_encryption) ->
                                                    "logs";
                                                (audit_encryption) ->
                                                    "audit"
                                            end, Other),
                Buckets2 = ["\"" ++ B ++ "\"" || B <- Buckets],
                BucketsStr =
                    case length(Buckets) of
                        0 -> [];
                        1 -> ["bucket " ++ Buckets2];
                        _ -> ["buckets " ++ lists:join(", ", Buckets2)]
                    end,
                FormattedUsages ++ BucketsStr
        end,
    Kind2Usage = ?cut(maps:get(required_usage, cb_deks:dek_config(_))),
    UsagesUsedByCfg = lists:uniq(lists:map(Kind2Usage, UsedByCfg)),
    UsagesUsedByDeks = lists:uniq(lists:map(Kind2Usage, UsedByDeks)),
    SecretsStrs = ["secrets " ++ lists:join(", ", Secrets) || Secrets /= []],
    Strings1 = FormatUsages(UsagesUsedByCfg) ++ SecretsStrs,
    Strings2 = FormatUsages(UsagesUsedByDeks -- UsagesUsedByCfg),

    case {Strings1, Strings2} of
        {_, []} ->
            "this secret is configured to encrypt " ++
            lists:join(", ", Strings1);
        {[], _} ->
            "this secret still encrypts some data in " ++
            lists:join(", ", Strings2);
        {_ , _} ->
            "this secret is configured to encrypt " ++
            lists:join(", ", Strings1) ++
            "; it also still encrypts some data in " ++
            lists:join(", ", Strings2)
    end.

-ifdef(TEST).

format_secrets_used_by_list_test() ->
    All = cb_deks:dek_kinds_list(#{bucket_names => {["b1", "b2"], 1}}),
    Secrets = ["s1", "s2"],
    F = ?cut(lists:flatten(format_secrets_used_by_list(_))),
    ?assertEqual("this secret is configured to encrypt configuration, logs, "
                 "audit, buckets \"b1\", \"b2\"",
                 F(#{by_deks => All, by_config => All, by_secrets => []})),
    ?assertEqual("this secret is configured to encrypt configuration, logs, "
                 "audit, buckets \"b1\", \"b2\"",
                 F(#{by_deks => [], by_config => All, by_secrets => []})),
    ?assertEqual("this secret still encrypts some data in configuration, logs, "
                 "audit, buckets \"b1\", \"b2\"",
                 F(#{by_deks => All, by_config => [], by_secrets => []})),
    ?assertEqual("this secret is configured to encrypt secrets s1, s2",
                 F(#{by_deks => [], by_config => [], by_secrets => Secrets})),
    ?assertEqual("this secret is configured to encrypt configuration, logs, "
                 "audit, buckets \"b1\", \"b2\", secrets s1, s2",
                 F(#{by_deks => [], by_config => All, by_secrets => Secrets})),
    ?assertEqual("this secret is configured to encrypt configuration, logs, "
                 "audit, buckets \"b1\", \"b2\", secrets s1, s2",
                 F(#{by_deks => All, by_config => All, by_secrets => Secrets})),
    ?assertEqual("this secret is configured to encrypt configuration; it also "
                 "still encrypts some data in logs, audit, "
                 "buckets \"b1\", \"b2\"",
                 F(#{by_deks => All, by_config => [configDek],
                     by_secrets => []})),
    ?assertEqual("this secret is configured to encrypt configuration, "
                 "bucket \"b2\", secrets s1, s2; "
                 "it also still encrypts some data in bucket \"b1\"",
                 F(#{by_deks => [configDek, {bucketDek, "b1"}],
                     by_config => [{bucketDek, "b2"}, chronicleDek],
                     by_secrets => Secrets})).

-endif.
