%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-2019 Couchbase, Inc.
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

%% @doc rest api's for collections

-module(menelaus_web_collections).

-include("ns_common.hrl").
-include("cut.hrl").

-export([handle_get/2,
         handle_post_scope/2,
         handle_post_collection/3,
         handle_delete_scope/3,
         handle_delete_collection/4]).

handle_get(Bucket, Req) ->
    assert_api_available(Bucket),
    menelaus_util:reply_json(Req, collections:for_rest(Bucket)).

handle_post_scope(Bucket, Req) ->
    assert_api_available(Bucket),

    validator:handle(
      fun (Values) ->
              Name = proplists:get_value(name, Values),
              handle_rv(collections:create_scope(Bucket, Name), Req)
      end, Req, form,
      [validator:required(name, _),
       validator:length(name, 1, 30, _),
       name_validator(_),
       name_first_char_validator(_),
       validator:unsupported(_)]).

handle_post_collection(Bucket, Scope, Req) ->
    assert_api_available(Bucket),

    validator:handle(
      fun (Values) ->
              Name = proplists:get_value(name, Values),
              handle_rv(collections:create_collection(Bucket, Scope, Name), Req)
      end, Req, form,
      [validator:required(name, _),
       validator:length(name, 1, 30, _),
       name_validator(_),
       name_first_char_validator(_),
       validator:unsupported(_)]).

handle_delete_scope(Bucket, Name, Req) ->
    assert_api_available(Bucket),
    handle_rv(collections:drop_scope(Bucket, Name), Req).

handle_delete_collection(Bucket, Scope, Name, Req) ->
    assert_api_available(Bucket),
    handle_rv(collections:drop_collection(Bucket, Scope, Name), Req).

assert_api_available(Bucket) ->
    case collections:enabled() of
        true ->
            ok;
        false ->
            erlang:throw({web_exception, 400,
                          "Not allowed on this version of cluster", []})
    end,
    {ok, BucketConfig} = ns_bucket:get_bucket(Bucket),
    case collections:enabled(BucketConfig) of
        true ->
            ok;
        false ->
            erlang:throw({web_exception, 400,
                          "Not allowed on this type of bucket", []})
    end.

name_first_char_validator(State) ->
    validator:validate(
      fun ([Char | _]) ->
              case lists:member(Char, "_%") of
                  true ->
                      {error, "First character must not be _ or %"};
                  false ->
                      ok
              end
      end, name, State).

name_validator(State) ->
    validator:string(
      name, "^[0-9A-Za-z_%\-]+$",
      "Can only contain characters A-Z, a-z, 0-9 and the following symbols "
      "_ - %", State).

handle_rv({ok, Uid}, Req) ->
    menelaus_util:reply_json(Req, {[{uid, Uid}]}, 200);
handle_rv(scope_already_exists, Req) ->
    menelaus_util:reply_json(
      Req, <<"Scope with this name already exists">>, 400);
handle_rv(collection_already_exists, Req) ->
    menelaus_util:reply_json(
      Req, <<"Collection with this name already exists">>, 400);
handle_rv(collection_not_found, Req) ->
    menelaus_util:reply_json(
      Req, <<"Collection with this name is not found">>, 404);
handle_rv(scope_not_found, Req) ->
    menelaus_util:reply_json(
      Req, <<"Scope with this name is not found">>, 404);
handle_rv(default_scope, Req) ->
    menelaus_util:reply_json(
      Req, <<"Deleting _default scope is not allowed">>, 400);
handle_rv(Error, Req) when Error =:= unsafe;
                           Error =:= push_config;
                           Error =:= pull_config ->
    menelaus_util:reply_json(
      Req, <<"Operation is unsafe at this time. Retry later.">>, 503);
handle_rv(Error, Req) ->
    menelaus_util:reply_json(
      Req, iolist_to_binary(io_lib:format("Unknown error ~p", [Error])), 400).
