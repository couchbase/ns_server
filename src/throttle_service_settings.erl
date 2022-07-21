%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(throttle_service_settings).

-include("ns_common.hrl").
-include("ns_config.hrl").

%% API
-export([handle_settings_throttle_post/1,
         handle_settings_throttle_post/2,
         handle_settings_throttle_get/1,
         handle_settings_throttle_get/2,
         remove_bucket_settings/1,
         default_config/1]).

-import(menelaus_util,
        [reply_json/3]).

-define(THROTTLE_CONFIG_KEY, <<"/throttle/settings/config">>).

is_enabled() ->
    config_profile:search(enable_throttle_settings).

throttle_limits_type_spec(undefined) ->
    undefined.

throttle_limit_params() ->
    [{"kvThrottleLimit", #{type => non_neg_int,
                           cfg_key => kv_throttle_limit}},
     {"indexThrottleLimit", #{type => non_neg_int,
                              cfg_key => index_throttle_limit}},
     {"ftsThrottleLimit", #{type => non_neg_int,
                            cfg_key => fts_throttle_limit}},
     {"n1qlThrottleLimit", #{type => non_neg_int,
                              cfg_key => n1ql_throttle_limit}},
     {"sgwReadThrottleLimit", #{type => non_neg_int,
                                   cfg_key => sgw_read_throttle_limit}},
     {"sgwWriteThrottleLimit", #{type => non_neg_int,
                                    cfg_key => sgw_write_throttle_limit}}].

attributes() ->
    [{kv_throttle_limit,
      <<"throttle.settings.limit.kv">>, 5000},
     {index_throttle_limit,
      <<"throttle.settings.limit.index">>, 5000},
     {fts_throttle_limit,
      <<"throttle.settings.limit.fts">>, 5000},
     {n1ql_throttle_limit,
      <<"throttle.settings.limit.n1ql">>, 5000},
     {sgw_read_throttle_limit,
      <<"throttle.settings.limit.sgw.read">>, 2500},
     {sgw_write_throttle_limit,
      <<"throttle.settings.limit.sgw.write">>, 2500}].

key_map() ->
    [{PKey, MKey} || {PKey, MKey, _} <- attributes()].

%% Default config will be provided based on the Profile settings that
%% specify if throttling is enabled. This function is used by ns_config
%% to build the default settings
default_config(Profile) ->
    case proplists:get_bool(enable_throttle_settings, Profile) of
        true ->
            Defaults = [{Key, Val} || {_, Key, Val} <- attributes()],
            [{{metakv, ?THROTTLE_CONFIG_KEY}, ejson:encode({Defaults})}];
        false ->
            []
    end.

get_bucket_key(BucketId, PKey) ->
    MKey = proplists:get_value(PKey, key_map()),
    binary:list_to_bin(binary:bin_to_list(MKey) ++ "[" ++ BucketId ++ "]").

get_metakv_props() ->
    case metakv:get(?THROTTLE_CONFIG_KEY) of
        false ->
            [];
        {value, Val, _} ->
            case Val =:= ?DELETED_MARKER of
                true ->
                    [];
                false ->
                    JSON = binary:bin_to_list(Val),
                    {MetaKvProps} = ejson:decode(JSON),
                    MetaKvProps
            end
    end.

not_allowed_error(Req) ->
    reply_json(Req,
               {[{errors,
                  [<<"Operation not allowed in this config profile">>]}]},
               400).

get_limits(KeyMap) ->
    CurrProps = get_metakv_props(),
    [{PKey, proplists:get_value(MKey, CurrProps)} ||
        {PKey, MKey} <- KeyMap,
        proplists:is_defined(MKey, CurrProps)].

get_throttle_settings(Req, false = _isEnabled) ->
    not_allowed_error(Req);
get_throttle_settings(Req, true = _isEnabled) ->
    CurrThrottleLimits = get_limits(key_map()),
    menelaus_web_settings2:handle_get([], throttle_limit_params(),
                                      fun throttle_limits_type_spec/1,
                                      CurrThrottleLimits, Req).

handle_settings_throttle_get(Req) ->
    get_throttle_settings(Req, is_enabled()).

get_bucket_throttle_settings(_BucketId, Req, false = _isEnabled) ->
    not_allowed_error(Req);
get_bucket_throttle_settings(BucketId, Req, true = _isEnabled) ->
    BucketThrottleKeys = [{Key, get_bucket_key(BucketId, Key)} ||
                             {Key, _} <- key_map()],
    CurrThrottleLimits = get_limits(BucketThrottleKeys),
    menelaus_web_settings2:handle_get([], throttle_limit_params(),
                                      fun throttle_limits_type_spec/1,
                                      CurrThrottleLimits, Req).

handle_settings_throttle_get(BucketId, Req) ->
    get_bucket_throttle_settings(BucketId, Req, is_enabled()).

apply_throttle_params(NewParams) ->
    CurrProps = get_metakv_props(),
    UpdateProps = misc:update_proplist(CurrProps, NewParams),
    metakv:set(?THROTTLE_CONFIG_KEY, ejson:encode({UpdateProps})).

set_throttle_settings(Req, false = _isEnabled) ->
    not_allowed_error(Req);
set_throttle_settings(Req, true = _isEnabled) ->
    menelaus_web_settings2:handle_post(
      fun(Params, Req2) ->
              NewParams = [{proplists:get_value(PKey, key_map()), Val} ||
                              {[PKey], Val} <- Params],
              apply_throttle_params(NewParams),
              handle_settings_throttle_get(Req2)
      end, [], throttle_limit_params(), fun throttle_limits_type_spec/1, Req).

handle_settings_throttle_post(Req) ->
    set_throttle_settings(Req, is_enabled()).

set_bucket_throttle_settings(_BucketId, Req, false = _IsEnabled) ->
    not_allowed_error(Req);
set_bucket_throttle_settings(BucketId, Req, true = _IsEnabled) ->
    menelaus_web_settings2:handle_post(
      fun(Params, Req2) ->
              NewParams = [{get_bucket_key(BucketId, PKey), Val} ||
                              {[PKey], Val} <- Params],
              apply_throttle_params(NewParams),
              handle_settings_throttle_get(BucketId, Req2)
      end, [], throttle_limit_params(), fun throttle_limits_type_spec/1, Req).

handle_settings_throttle_post(BucketId, Req) ->
    case ns_bucket:get_bucket(BucketId) of
        not_present ->
            reply_json(Req, {[{errors, [<<"Bucket does not exist">>]}]}, 400);
        _ ->
            set_bucket_throttle_settings(BucketId, Req, is_enabled())
    end.

remove_bucket_settings(_BucketId, false = _IsEnabled) ->
    ok;
remove_bucket_settings(BucketId, true = _IsEnabled) ->
    CurrProps = get_metakv_props(),
    BucketKeys = [get_bucket_key(BucketId, PKey) || {PKey, _} <- key_map()],
    DeleteItems = [{X, Y} || {X, Y} <- CurrProps, lists:member(X, BucketKeys)],
    UpdateProps = CurrProps -- DeleteItems,
    metakv:set(?THROTTLE_CONFIG_KEY, ejson:encode({UpdateProps})).

remove_bucket_settings(BucketId) ->
    remove_bucket_settings(BucketId, is_enabled()).
