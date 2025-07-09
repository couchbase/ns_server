%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_queries).
-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-export([handle_settings_get/1,
         handle_curl_whitelist_post/1,
         handle_curl_whitelist_get/1,
         handle_settings_post/1,
         cluster_init_validators/0]).

handle_settings_get(Req) ->
    Config = get_settings(),
    menelaus_util:reply_json(Req, {Config}).

get_settings() ->
    query_settings_manager:get(generalSettings) ++
    query_settings_manager:get(curlWhitelistSettings).

settings_post_validators() ->
    [validator:has_params(_),
     validator:integer(queryTmpSpaceSize, _),
     validate_tmp_space_size(queryTmpSpaceSize, _),
     validator:dir(queryTmpSpaceDir, _),
     validator:convert(queryTmpSpaceDir, fun list_to_binary/1, _),
     validator:integer(queryPipelineBatch, _),
     validator:integer(queryPipelineCap, _),
     validator:integer(queryScanCap, _),
     validator:integer(queryTimeout, _),
     validator:integer(queryPreparedLimit, 0, max_uint64, _),
     validator:integer(queryCompletedLimit, _),
     validator:integer(queryCompletedThreshold, _),
     validator:integer(queryMaxParallelism, _),
     validator:integer(queryN1QLFeatCtrl, _),
     validator:one_of(queryLogLevel, ["debug", "trace", "info", "warn",
                                      "error", "severe", "none"], _),
     validator:convert(queryLogLevel, fun list_to_binary/1, _),
     validator:time_duration(queryTxTimeout, _),
     validator:convert(queryTxTimeout, fun list_to_binary/1, _),
     validator:integer(queryMemoryQuota, _),
     validator:boolean(queryUseCBO, _),
     validator:boolean(queryCleanupClientAttempts, _),
     validator:boolean(queryCleanupLostAttempts, _),
     validator:time_duration(queryCleanupWindow, _),
     validator:convert(queryCleanupWindow, fun list_to_binary/1, _),
     validator:integer(queryNumAtrs, _)] ++
        case cluster_compat_mode:is_cluster_76() of
            true ->
                [validator:integer(queryNodeQuotaValPercent, _),
                 validator:range(queryNodeQuotaValPercent, 0, 100, _),
                 validator:string(queryUseReplica, _),
                 validator:convert(queryUseReplica, fun list_to_binary/1, _),
                 validator:one_of(queryUseReplica,
                                  [<<"unset">>, <<"off">>, <<"on">>], _),
                 validator:integer(queryNumCpus, _),
                 validator:range(queryNumCpus, 0, max_uint64, _),
                 validator:integer(queryCompletedMaxPlanSize, _),
                 validator:range(queryCompletedMaxPlanSize, 0, max_uint64, _)]
                    ++ node_quota_validators();
            false ->
                []
        end ++
        case cluster_compat_mode:is_cluster_79() of
            true ->
                [validator:integer(queryCompletedStreamSize, _),
                 validator:range(queryCompletedStreamSize, 0, max_uint64, _)];
            false ->
                []
        end ++
        [validator:unsupported(_)].

validate_tmp_space_size(Name, State) ->
    %% zero disables the feature, and -1 implies unlimited quota
    validator:range(Name, -1, max_uint64, State).

update_settings(Key, Value) ->
    case query_settings_manager:update(Key, Value) of
        {ok, _} ->
            ok;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

handle_settings_post(Req) ->
    validator:handle(
      fun (Values) ->
              ok = update_settings(generalSettings, Values),
              ns_audit:settings(Req, modify_query, Values),
              menelaus_util:reply_json(Req, {get_settings()})
      end, Req, form, settings_post_validators()).

settings_curl_whitelist_validators() ->
    ConvertArray = [list_to_binary(L) || L <- _],
    [validator:required(all_access, _),
     validator:boolean(all_access, _),
     validator:string_array(allowed_urls, _),
     validator:convert(allowed_urls, ConvertArray, _),
     validator:string_array(disallowed_urls, _),
     validator:convert(disallowed_urls, ConvertArray, _),
     validator:unsupported(_)].

get_curl_whitelist_settings() ->
    Config = query_settings_manager:get(curlWhitelistSettings),
    %% queryCurlWhitelist should always be present.
    proplists:get_value(queryCurlWhitelist, Config).

handle_curl_whitelist_post(Req) ->
    validator:handle(
      fun (Values) ->
              ok = update_settings(curlWhitelistSettings,
                                   [{queryCurlWhitelist, {Values}}]),
              ns_audit:settings(Req, modify_query,
                                [{curl_whitelist, ejson:encode({Values})}]),
              menelaus_util:reply_json(Req, get_curl_whitelist_settings())
      end, Req, json, settings_curl_whitelist_validators()).

handle_curl_whitelist_get(Req) ->
    menelaus_util:reply_json(Req, get_curl_whitelist_settings()).

%% Add additional individual validators to this function and they will be
%% included during cluster-init.
cluster_init_validators() ->
    node_quota_validators().

node_quota_validators() ->
    [validator:integer(queryNodeQuota, _),
     validator:range(queryNodeQuota, 0, max_uint64, _)].
