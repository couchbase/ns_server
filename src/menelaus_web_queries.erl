%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-2018 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
-module(menelaus_web_queries).

-include("cut.hrl").
-export([handle_settings_get/1,
         handle_curl_whitelist_post/1,
         handle_curl_whitelist_get/1,
         handle_settings_post/1]).

handle_settings_get(Req) ->
    menelaus_util:assert_is_vulcan(),

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
     validator:unsupported(_)].

validate_tmp_space_size(Name, State) ->
    %% zero disables the feature, and -1 implies unlimited quota
    validator:range(Name, -1, infinity, State).

update_settings(Key, Value) ->
    case query_settings_manager:update(Key, Value) of
        {ok, _} ->
            ok;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

handle_settings_post(Req) ->
    menelaus_util:assert_is_vulcan(),

    validator:handle(
      fun (Values) ->
              ok = update_settings(generalSettings, Values),
              menelaus_util:reply_json(Req, {get_settings()})
      end, Req, form, settings_post_validators()).

validate_array(Array) when is_list(Array) ->
    case lists:all(fun is_binary/1, Array) of
        false -> {error, "Invalid array"};
        true -> {value, Array}
    end;
validate_array(_) ->
    {error, "Invalid array"}.

settings_curl_whitelist_validators() ->
    [validator:required(all_access, _),
     validator:boolean(all_access, _),
     validator:validate(fun validate_array/1, allowed_urls, _),
     validator:validate(fun validate_array/1, disallowed_urls, _),
     validator:unsupported(_)].

get_curl_whitelist_settings() ->
    Config = query_settings_manager:get(curlWhitelistSettings),
    %% queryCurlWhitelist should always be present.
    proplists:get_value(queryCurlWhitelist, Config).

handle_curl_whitelist_post(Req) ->
    menelaus_util:assert_is_vulcan(),
    validator:handle(
      fun (Values) ->
              ok = update_settings(curlWhitelistSettings,
                                   [{queryCurlWhitelist, {Values}}]),
              menelaus_util:reply_json(Req, get_curl_whitelist_settings())
      end, Req, json, settings_curl_whitelist_validators()).

handle_curl_whitelist_get(Req) ->
    menelaus_util:assert_is_vulcan(),
    menelaus_util:reply_json(Req, get_curl_whitelist_settings()).
