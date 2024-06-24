%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_encr_at_rest).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-include("cb_cluster_secrets.hrl").

-export([handle_get/2, handle_post/2, get_settings/1]).

params() ->
    [{"config.encryptionMethod",
      #{cfg_key => [config_encryption, encryption],
        type => {one_of, existing_atom,
                 [disabled, encryption_service, secret]}}},
     {"config.encryptionSecretId",
      #{cfg_key => [config_encryption, secret_id],
        type => {int, -1, infinity}}}].

handle_get(Path, Req) ->
    Settings = get_settings(direct),
    List = maps:to_list(maps:map(fun (_, V) -> maps:to_list(V) end, Settings)),
    menelaus_web_settings2:handle_get(Path, params(), undefined, List, Req).

handle_post(Path, Req) ->
    menelaus_web_settings2:handle_post(
      fun (Params, Req2) ->
          NewSettings = maps:map(fun (_, V) -> maps:from_list(V) end,
                                 maps:groups_from_list(
                                   fun ({[K1, _K2], _V}) -> K1 end,
                                   fun ({[_K1, K2], V}) -> {K2, V} end,
                                   Params)),
          RV = chronicle_kv:transaction(
                 kv, [?CHRONICLE_SECRETS_KEY,
                      ?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY],
                 fun (Snapshot) ->
                     #{config_encryption := Cfg} = ToApply =
                        get_settings(Snapshot, NewSettings),
                     case validate_sec_settings(config_encryption,
                                                Cfg, Snapshot) of
                         ok ->
                             {commit, [{set,
                                        ?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY,
                                        ToApply}]};
                         {error, _} = Error ->
                             {abort, Error}
                     end
                 end),
         case RV of
             {ok, _} ->
                 cb_cluster_secrets:sync_with_all_node_monitors(),
                 handle_get(Path, Req2);
             {error, Msg} ->
                 menelaus_util:reply_global_error(Req2, Msg)
         end
      end, Path, params(), undefined, Req).

get_settings(Snapshot) -> get_settings(Snapshot, #{}).
get_settings(Snapshot, ExtraSettings) ->
    Merge = fun (Settings1, Settings2) ->
                maps:merge_with(fun (_K, V1, V2) -> maps:merge(V1, V2) end,
                                Settings1, Settings2)
            end,
    Settings = chronicle_compat:get(Snapshot,
                                    ?CHRONICLE_ENCR_AT_REST_SETTINGS_KEY,
                                    #{default => #{}}),
    Merge(Merge(defaults(), Settings), ExtraSettings).

defaults() ->
    #{config_encryption => #{encryption => disabled,
                             secret_id => ?SECRET_ID_NOT_SET}}.

validate_sec_settings(_, #{encryption := disabled,
                           secret_id := ?SECRET_ID_NOT_SET}, _) ->
    ok;
validate_sec_settings(_, #{encryption := disabled,
                           secret_id := _}, _) ->
    {error, "Secret id must not be set when encryption is disabled"};
validate_sec_settings(_, #{encryption := encryption_service,
                           secret_id := ?SECRET_ID_NOT_SET}, _) ->
    ok;
validate_sec_settings(_, #{encryption := encryption_service,
                           secret_id := _}, _) ->
    {error, "Secret id must not be set when encryption_service is used"};
validate_sec_settings(_, #{encryption := secret,
                        secret_id := ?SECRET_ID_NOT_SET}, _) ->
    {error, "Secret id must be set"};
validate_sec_settings(Name, #{encryption := secret,
                              secret_id := Id}, Snapshot) ->
    case cb_cluster_secrets:is_allowed_usage_for_secret(Id, Name, Snapshot) of
        ok -> ok;
        {error, not_found} -> {error, "Secret not found"};
        {error, not_allowed} -> {error, "Secret not allowed"}
    end.
