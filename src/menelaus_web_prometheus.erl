%% @author Couchbase <info@couchbase.com>
%% @copyright 2020 Couchbase, Inc.
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
-module(menelaus_web_prometheus).

%% API
-export([handle_get_local_metrics/1, handle_create_snapshot/1,
         handle_get_metrics/1]).

-include("ns_common.hrl").

-define(METRICS_TIMEOUT, 5000).
-define(PART_SIZE, 1024).
-define(WINDOW_SIZE, 3).

%%%===================================================================
%%% API
%%%===================================================================

handle_get_metrics(Req) ->
    Resp = mochiweb_request:respond({200, [], chunked}, Req),
    ns_server_stats:report_prom_stats(fun (M) -> report_metric(M, Resp) end),
    Settings = prometheus_cfg:settings(),
    AllTargets = proplists:get_value(targets, Settings),
    AlmostAllTargets = proplists:delete(ns_server, AllTargets),
    Services = proplists:get_value(external_prometheus_services, Settings),
    HighCardTargets = lists:filter(
                        fun ({Name, _Addr}) ->
                            Props = proplists:get_value(Name, Services, []),
                            proplists:get_bool(high_cardinality_enabled, Props)
                        end, AllTargets),
    %% Addr is supposed to be a loopback address (127.0.0.1 or [::1] depending
    %% on configured ip family) with port, hence no need to use https
    MakeURL = fun (Addr, Path) -> "http://" ++ Addr ++ Path end,
    URLs = [MakeURL(Addr,"/_prometheusMetrics")
                || {_, Addr} <- AlmostAllTargets] ++
           [MakeURL(Addr,"/_prometheusMetricsHigh")
                || {_, Addr} <- HighCardTargets],
    [proxy_chunks_from_url(URL, Resp) || URL <- URLs],
    mochiweb_response:write_chunk(<<>>, Resp).

proxy_chunks_from_url(URL, Resp) ->
    Options = [{connect_timeout, ?METRICS_TIMEOUT},
               {partial_download, [{window_size, ?WINDOW_SIZE},
                                   {part_size, ?PART_SIZE}]}],
    Headers = [menelaus_rest:special_auth_header()],
    case lhttpc:request(URL, 'GET', Headers, [], ?METRICS_TIMEOUT, Options) of
        {ok, {{200, _}, _Hdrs, Req}} when is_pid(Req) ->
            case proxy_chunks(Req, Resp) of
                ok -> ok;
                {error, Error} ->
                    ?log_error("Got error while reading chunks from ~s:~n~p",
                               [URL, Error])
            end;
        Bad ->
            ?log_error("Http get for ~s returned:~n~p", [URL, Bad]),
            ok
    end.

proxy_chunks(Req, Resp) ->
    case lhttpc:get_body_part(Req, ?METRICS_TIMEOUT) of
        {ok, {http_eob, _Trailers}} -> ok;
        {ok, Bin} when is_binary(Bin) ->
            mochiweb_response:write_chunk(Bin, Resp),
            proxy_chunks(Req, Resp);
        {error, _} = Error ->
            Error
    end.

%% It is supposed to be used by local prometheus to collect ns_server metrics
handle_get_local_metrics(Req) ->
    Resp = mochiweb_request:respond({200, [], chunked}, Req),
    ns_server_stats:report_prom_stats(fun (M) -> report_metric(M, Resp) end),
    mochiweb_response:write_chunk(<<>>, Resp).

handle_create_snapshot(Req) ->
    menelaus_util:ensure_local(Req),
    Settings = prometheus_cfg:settings(),
    Timeout = proplists:get_value(snapshot_timeout_msecs, Settings),
    case prometheus:create_snapshot(Timeout, Settings) of
        {ok, Response} ->
            menelaus_util:reply_text(Req, Response, 200);
        {error, Reason} ->
            menelaus_util:reply_text(Req, Reason, 500)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

report_metric({Metric, Labels, Value}, Resp) ->
    Line =
        [name_to_iolist(Metric), <<"{">>,
         lists:join(<<",">>,[[K, <<"=\"">>, V, <<"\"">>] || {K, V} <- Labels]),
         <<"} ">>, prometheus:format_value(Value), <<"\n">>],
    mochiweb_response:write_chunk(Line, Resp);
report_metric({Prefix, Metric, Labels, Value}, Resp) ->
    Prefixed = [Prefix, <<"_">>, name_to_iolist(Metric)],
    report_metric({Prefixed, Labels, Value}, Resp).

name_to_iolist(A) when is_atom(A) -> atom_to_binary(A, latin1);
name_to_iolist(A) -> A.
