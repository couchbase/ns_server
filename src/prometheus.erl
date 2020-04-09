-module(prometheus).

-include("ns_common.hrl").
-include("../lhttpc/lhttpc.hrl").

-export([range_query/6, format_value/1, parse_value/1]).

range_query(Query, Start, End, Step, Timeout, Settings) ->
    Addr = proplists:get_value(listen_addr, Settings),
    URL = io_lib:format("http://~s/api/v1/query_range", [Addr]),
    Body = mochiweb_util:urlencode(
             [{query, Query}, {start, Start}, {'end', End},
              {step, integer_to_list(Step) ++ "s"},
              {timeout, integer_to_list(Timeout) ++ "s"}]),
    Headers = [{"Content-Type", "application/x-www-form-urlencoded"}],
    case post(lists:flatten(URL), Headers, Body, 5000) of
        {ok, json, {Data}} ->
            Res = proplists:get_value(<<"result">>, Data, {[]}),
            {ok, Res};
        {error, Reason} ->
            ?log_error("Prometheus query_range request failed:~n"
                       "URL: ~s~nHeaders: ~p~nBody: ~s~nReason: ~s",
                       [URL, Headers, Body, Reason]),
            {error, Reason}
    end.

post(URL, Headers, Body, Timeout) ->
    case lhttpc:request(URL, 'post', Headers, Body, Timeout) of
        {ok, {{Code, CodeText}, ReplyHeaders, Reply}} ->
            case proplists:get_value("Content-Type", ReplyHeaders) of
                "application/json" ->
                    try ejson:decode(Reply) of
                        {JSON} ->
                            case proplists:get_value(<<"status">>, JSON) of
                                <<"success">> ->
                                    R = proplists:get_value(<<"data">>, JSON),
                                    {ok, json, R};
                                <<"error">> ->
                                    E = proplists:get_value(<<"error">>, JSON),
                                    {error, E}
                            end
                    catch
                        _:_ ->
                            R = misc:format_bin("Invalid json: ~s", [Reply]),
                            {error, R}
                    end;
                _ ->
                    case Code of
                        200 -> {ok, text, Reply};
                        _ when Reply =/= <<>> -> {error, Reply};
                        _ -> {error, CodeText}
                    end
            end;
        {error, Error} ->
            #lhttpc_url{host = H, port = P} = lhttpc_lib:parse_url(URL),
            case ns_error_messages:connection_error_message(Error, H, P) of
                undefined -> {error, misc:format_bin("~p", [Error])};
                Bin -> {error, Bin}
            end
    end.

format_value(undefined) -> <<"NaN">>;
format_value(infinity) -> <<"Inf">>;
format_value(neg_infinity) -> <<"-Inf">>;
format_value(N) when is_integer(N) -> integer_to_binary(N);
format_value(N) -> float_to_binary(N).

parse_value(<<"NaN">>) -> undefined;
parse_value(<<"Inf">>) -> infinity;
parse_value(<<"-Inf">>) -> neg_infinity;
parse_value(B) ->
    try
        binary_to_float(B)
    catch
        _:_ -> binary_to_integer(B)
    end.
