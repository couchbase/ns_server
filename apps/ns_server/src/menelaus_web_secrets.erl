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

-export([handle_get_secrets/1,
         handle_get_secret/2,
         handle_post_secret/1,
         handle_put_secret/2,
         handle_delete_secret/2,
         handle_rotate/2]).

handle_get_secrets(Req) ->
    Res = lists:map(
            fun (Props) ->
                {export_secret(Props)}
            end, cb_cluster_secrets:get_all()),
    menelaus_util:reply_json(Req, Res).

handle_get_secret(IdStr, Req) when is_list(IdStr) ->
    case cb_cluster_secrets:get_secret(parse_id(IdStr)) of
        {ok, Props} ->
            Res = {export_secret(Props)},
            menelaus_util:reply_json(Req, Res);
        {error, not_found} ->
            menelaus_util:reply_not_found(Req)
    end.

handle_post_secret(Req) ->
    validator:handle(
      fun (RawProps) ->
          ToAdd = import_secret(RawProps),
          case cb_cluster_secrets:add_new_secret(ToAdd) of
              {ok, Res} ->
                  Formatted = export_secret(Res),
                  menelaus_util:reply_json(Req, {Formatted});
              {error, encrypt_id_not_found} ->
                  menelaus_util:reply_global_error(
                    Req, "encryption secret does not exist");
              {error, encrypt_id_not_allowed} ->
                  menelaus_util:reply_global_error(
                    Req, "encryption secret not allowed");
              {error, Reason} ->
                  menelaus_util:reply_global_error(
                    Req, io_lib:format("~p", [Reason]))
          end
      end, Req, json, secret_validators(#{})).

handle_put_secret(IdStr, Req) ->
    case cb_cluster_secrets:get_secret(parse_id(IdStr)) of
        {ok, CurProps} ->
            validator:handle(
              fun (RawProps) ->
                  Props = import_secret(RawProps),
                  case cb_cluster_secrets:replace_secret(CurProps, Props) of
                      {ok, Res} ->
                          Formatted = export_secret(Res),
                          menelaus_util:reply_json(Req, {Formatted});
                      {error, encrypt_id_not_found} ->
                          menelaus_util:reply_global_error(
                            Req, "encryption secret does not exist");
                      {error, encrypt_id_not_allowed} ->
                          menelaus_util:reply_global_error(
                            Req, "encryption secret not allowed");
                      {error, not_found} ->
                          menelaus_util:reply_not_found(Req)
                  end
              end, Req, json,
              secret_validators(CurProps));
        {error, not_found} ->
            %% We don't want PUT to create secrets because we generate id's
            menelaus_util:reply_not_found(Req)
    end.

secret_validators(CurProps) ->
    [validator:string(name, _),
     validator:required(name, _),
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

handle_delete_secret(_Id, _Req) ->
    ok.

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
      rotation_interval => rotationIntervalInDays,
      auto_rotation => autoRotation,
      first_rotation_time => firstRotationTime,
      key_arn => keyARN,
      credentials_file => credentialsFile,
      config_file => configFile,
      use_imds => useIMDS,
      encrypt_by => encryptBy,
      encrypt_secret_id => encryptSecretId}.

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
      lists:map(
        fun ({id, Id}) ->
                {id, Id};
            ({name, Name}) ->
                {name, iolist_to_binary(Name)};
            ({creation_time, DateTime}) ->
                {creation_time, iso8601:format(DateTime)};
            ({type, T}) ->
                {type, T};
            ({usage, UList}) ->
                {usage, lists:map(
                          fun ({bucket_encryption, BucketName}) ->
                                  iolist_to_binary([<<"bucket-encryption-">>,
                                                    BucketName]);
                              (secrets_encryption) ->
                                  <<"secrets-encryption">>
                          end, UList)};
            ({data, D}) when DataType == ?GENERATED_KEY_TYPE ->
                {data, {format_auto_generated_key_data(D)}};
            ({data, D}) when DataType == ?AWSKMS_KEY_TYPE ->
                {data, {format_aws_key_data(D)}}
        end, maps:to_list(Props))).

format_auto_generated_key_data(Props) ->
    ActiveKeyId = maps:get(active_key_id, Props),
    lists:map(
      fun ({auto_rotation, B}) ->
              {auto_rotation, B};
          ({rotation_interval, Interval}) ->
              {rotation_interval, Interval};
          ({first_rotation_time, DateTime}) ->
              {first_rotation_time, iso8601:format(DateTime)};
          ({encrypt_by, E}) ->
              {encrypt_by, E};
          ({encrypt_secret_id, SId}) ->
              {encrypt_secret_id, SId};
          ({keys, Keys}) ->
              {keys, lists:map(
                       fun (KeyProps) ->
                           {format_key(KeyProps, ActiveKeyId)}
                       end, Keys)}
      end, maps:to_list(maps:remove(active_key_id, Props))).

format_aws_key_data(Props) ->
    lists:map(
      fun ({key_arn, U}) -> {key_arn, iolist_to_binary(U)};
          ({region, R}) -> {region, iolist_to_binary(R)};
          ({credentials_file, F}) -> {credentials_file, iolist_to_binary(F)};
          ({config_file, F}) -> {config_file, iolist_to_binary(F)};
          ({profile, P}) -> {profile, iolist_to_binary(P)};
          ({use_imds, U}) -> {use_imds, U}
      end, maps:to_list(maps:remove(uuid, Props))).

format_key(Props, ActiveKeyId) ->
    lists:flatmap(fun ({id, Id}) ->
                      [{id, Id}, {active, Id == ActiveKeyId}];
                  ({creation_time, DateTime}) ->
                      [{creation_time, iso8601:format(DateTime)}];
                  ({active, Active}) ->
                      [{active, Active}];
                  ({key, {_, _Binary}}) ->
                      [{key, <<"******">>}]
              end, maps:to_list(maps:remove(encrypted_by, Props))).

validate_key_usage(Name, State) ->
    validator:string_array(
      Name,
      fun (Str) ->
          case iolist_to_binary(Str) of
              <<"bucket-encryption-", N/binary>> when size(N) > 0 ->
                  {value, {bucket_encryption, binary_to_list(N)}};
              <<"secrets-encryption">> ->
                  {value, secrets_encryption};
              _ ->
                  {error, "unknown usage"}
          end
      end, State).

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

generated_key_validators(CurSecretProps) ->
    [validator:boolean(autoRotation, _),
     validator:range(rotationIntervalInDays, 1, infinity, _),
     validate_iso8601_datetime(firstRotationTime, _),
     validator:validate(fun (_) -> {error, "read only"} end, keys, _),
     validator:one_of(encryptBy, ["nodeSecretManager", "clusterSecret"], _),
     validator:convert(encryptBy, binary_to_atom(_, latin1), _),
     validate_encrypt_by(encryptBy, _),
     validator:default(encryptBy, nodeSecretManager, _),
     validator:integer(encryptSecretId, 0, infinity, _),
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
              ok
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
     validator:string(profile, _),
     validator:default(profile, "", _)] ++
    case CurSecretProps of
        #{data := #{key_arn := KeyArn, region := Region}} ->
            [enforce_static_field_validator(keyARN, KeyArn, _),
             enforce_static_field_validator(region, Region, _)];
        #{} when map_size(CurSecretProps) == 0 ->
            []
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

parse_id(Str) when is_list(Str) ->
    try list_to_integer(Str) of
        N -> N
    catch
        _:_ ->
            menelaus_util:web_exception(404, menelaus_util:reply_text_404())
    end.
