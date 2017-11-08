%% @author Couchbase <info@couchbase.com>
%% @copyright 2017 Couchbase, Inc.
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
       validator:unsupported(_)]).

handle_post_collection(Bucket, Scope, Req) ->
    assert_api_available(Bucket),

    validator:handle(
      fun (Values) ->
              Name = proplists:get_value(name, Values),
              handle_rv(collections:create_collection(Bucket, Scope, Name), Req)
      end, Req, form,
      [validator:required(name, _),
       validator:unsupported(_)]).

handle_delete_scope(Bucket, Name, Req) ->
    assert_api_available(Bucket),
    handle_rv(collections:drop_scope(Bucket, Name), Req).

handle_delete_collection(Bucket, Scope, Name, Req) ->
    assert_api_available(Bucket),
    handle_rv(collections:drop_collection(Bucket, Scope, Name), Req).

assert_api_available(Bucket) ->
    menelaus_util:assert_cluster_version(fun collections:enabled/0),
    {ok, BucketConfig} = ns_bucket:get_bucket(Bucket),
    case ns_bucket:bucket_type(BucketConfig) of
        membase ->
            ok;
        memcached ->
            erlang:throw({web_exception, 400,
                          "Not allowed on this type of bucket", []})
    end.

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
