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
-module(rest_utils).

-include("ns_common.hrl").

-export([request/6,
         get_json_local/4,
         get_json_local/5]).

request(Type, URL, Method, Headers, Body, Timeout) ->
    ns_server_stats:increment_counter({Type, requests}, 1),

    Start = os:timestamp(),
    RV = lhttpc:request(URL, Method, Headers, Body, Timeout,
                        [{pool, rest_lhttpc_pool}]),
    case RV of
        {ok, {{Code, _}, _, _}} ->
            Diff = timer:now_diff(os:timestamp(), Start),
            ns_server_stats:add_histo({Type, latency}, Diff),

            Class = (Code div 100) * 100,
            ns_server_stats:increment_counter({Type, status, Class}, 1);
        _ ->
            ns_server_stats:increment_counter({Type, failed_requests}, 1)
    end,

    RV.

request_local(Type, URL, Method, Headers, Body, Timeout) ->
    HeadersWithAuth = [menelaus_rest:special_auth_header() | Headers],

    request(Type, URL, Method, HeadersWithAuth, Body, Timeout).

get_json(Type, URL, Path, Timeout, ReqHeaders) ->
    RV = request_local(Type, URL, "GET", ReqHeaders, [], Timeout),
    case RV of
        {ok, {{200, _}, Headers, BodyRaw}} ->
            try
                {ok, Headers, ejson:decode(BodyRaw)}
            catch
                T:E ->
                    ?log_error("Received bad json in response from (~p) ~s: ~p",
                               [Type, Path, {T, E}]),
                    {error, bad_json}
            end;
        {ok, {{304, _}, Headers, <<>> = Body}} ->
            {ok, Headers, Body};
        _ ->
            ?log_error("Request to (~p) ~s failed: ~p", [Type, Path, RV]),
            {error, RV}
    end.

-spec get_json_local(atom(), string(), integer(), integer()) ->
    {ok, [{any(), any()}], any()} | {error, any()}.
get_json_local(Type, Path, Port, Timeout) ->
    get_json_local(Type, Path, Port, Timeout, []).

-spec get_json_local(atom(), string(), integer(), integer(),
                     [{any(), any()}]) -> {ok, [{any(), any()}], any()} |
                                          {error, any()}.
get_json_local(Type, Path, Port, Timeout, Headers) ->
    URL = misc:local_url(Port, Path, []),
    get_json(Type, URL, Path, Timeout, Headers).
