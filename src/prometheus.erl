-module(prometheus).

-include("ns_common.hrl").

-export([query_range/6, query_range_async/7, query/4,
         format_value/1, parse_value/1, format_promql/1]).

query_range(Query, Start, End, Step, Timeout, Settings) ->
    Self = self(),
    Ref = make_ref(),
    ok = query_range_async(Query, Start, End, Step, Timeout, Settings,
                           fun (Res) -> Self ! {Ref, Res} end),
    receive
        {Ref, Res} -> Res
    after Timeout ->
        {error, timeout}
    end.

query_range_async(Query, Start, End, Step, Timeout, Settings, Handler)
                  when is_integer(Step) ->
    StepStr = integer_to_list(Step) ++ "s",
    query_range_async(Query, Start, End, StepStr, Timeout, Settings, Handler);
query_range_async(Query, Start, End, Step, Timeout, Settings, Handler) ->
    case proplists:get_value(enabled, Settings) of
        true ->
            Addr = proplists:get_value(listen_addr, Settings),
            {Username, Password} = proplists:get_value(prometheus_creds,
                                                       Settings),
            URL = lists:flatten(io_lib:format("http://~s/api/v1/query_range",
                                              [Addr])),
            TimeoutStr = integer_to_list(max(Timeout div 1000, 1)) ++ "s",
            Body = [{query, Query}, {start, Start}, {'end', End}, {step, Step},
                    {timeout, TimeoutStr}],
            BodyEncoded = mochiweb_util:urlencode(Body),
            Headers = [{"Content-Type", "application/x-www-form-urlencoded"}],
            HeadersWithAuth = menelaus_rest:add_basic_auth(Headers, Username,
                                                          Password),
            AFamily = proplists:get_value(afamily, Settings),
            HandlerWrap =
                fun ({ok, json, {Data}}) ->
                        Res = proplists:get_value(<<"result">>, Data, {[]}),
                        Handler({ok, Res});
                    ({error, Reason}) ->
                        ?log_error("Prometheus query_range request failed:~n"
                                   "URL: ~s~nHeaders: ~p~nBody: ~s~nReason: ~p",
                                   [URL, Headers, BodyEncoded, Reason]),
                        Handler({error, Reason});
                    (Unhandled) ->
                        ?log_error("Unexpected query_async result: ~p~n"
                                   "URL: ~s~nHeaders: ~p~nBody: ~s",
                                   [Unhandled, URL, Headers, BodyEncoded]),
                        Handler({error, {unexpected, Unhandled}})
                end,
            post_async(URL, HeadersWithAuth, BodyEncoded, AFamily, Timeout,
                       HandlerWrap);
        false ->
            Handler({error, <<"Stats backend is disabled">>})
    end.

query(Query, Time, Timeout, Settings) ->
    Self = self(),
    Ref = make_ref(),
    ok = query_async(Query, Time, Timeout, Settings,
                     fun (Res) -> Self ! {Ref, Res} end),
    receive
        {Ref, Res} -> Res
    after Timeout ->
        {error, timeout}
    end.

query_async(Query, Time, Timeout, Settings, Handler) ->
    case proplists:get_value(enabled, Settings) of
        true ->
            Addr = proplists:get_value(listen_addr, Settings),
            URL = lists:flatten(io_lib:format("http://~s/api/v1/query",
                                [Addr])),
            TimeoutStr = integer_to_list(max(Timeout div 1000, 1)) ++ "s",
            Body = mochiweb_util:urlencode(
                     [{query, Query}, {timeout, TimeoutStr}] ++
                     [{time, Time} || Time =/= undefined]),
            {Username, Password} = proplists:get_value(prometheus_creds,
                                                       Settings),
            Headers = [{"Content-Type", "application/x-www-form-urlencoded"}],
            HeadersWithAuth = menelaus_rest:add_basic_auth(Headers, Username,
                                                           Password),
            AFamily = proplists:get_value(afamily, Settings),
            HandlerWrap =
                fun ({ok, json, {Data}}) ->
                        Res = proplists:get_value(<<"result">>, Data, {[]}),
                        Handler({ok, Res});
                    ({error, Reason}) ->
                        ?log_error("Prometheus query request failed:~n"
                                   "URL: ~s~nHeaders: ~p~nBody: ~s~nReason: ~p",
                                   [URL, Headers, Body, Reason]),
                        Handler({error, Reason});
                    (Unhandled) ->
                        ?log_error("Unexpected query_async result: ~p~n"
                                   "URL: ~s~nHeaders: ~p~nBody: ~s",
                                   [Unhandled, URL, Headers, Body]),
                        Handler({error, {unexpected, Unhandled}})
                end,
            post_async(URL, HeadersWithAuth, Body, AFamily, Timeout,
                       HandlerWrap);
        false ->
            Handler({error, <<"Stats backend is disabled">>})
    end.

post_async(URL, Headers, Body, AFamily, Timeout, Handler) ->
    Receiver = fun (Res) ->
                   try
                       handle_post_async_reply(Handler, Res)
                   catch
                       Class:Error ->
                           ?log_error("Exception in httpc receiver ~p:~p~n~p",
                                      [Class, Error, erlang:get_stacktrace()])
                   end
                end,
    HttpOptions = [{timeout, Timeout}, {connect_timeout, Timeout}],
    Options = [{sync, false}, {receiver, Receiver},
               {socket_opts, [{ipfamily, AFamily}]}],
    Req = {URL, Headers, "application/x-www-form-urlencoded", Body},
    {ok, _} = httpc:request('post', Req, HttpOptions, Options),
    ok.

handle_post_async_reply(UserHandler, {_Ref, {error, R}}) ->
    UserHandler({error, R});
handle_post_async_reply(UserHandler,
                        {_Ref, {{_, Code, CodeText}, Headers, Reply}}) ->
    case proplists:get_value("content-type", Headers) of
        "application/json" ->
            try ejson:decode(Reply) of
                {JSON} ->
                    case proplists:get_value(<<"status">>, JSON) of
                        <<"success">> ->
                            R = proplists:get_value(<<"data">>, JSON),
                            UserHandler({ok, json, R});
                        <<"error">> ->
                            E = proplists:get_value(<<"error">>, JSON),
                            UserHandler({error, E})
                    end
            catch
                _:_ ->
                    R = misc:format_bin("Invalid json in reply: ~s", [Reply]),
                    UserHandler({error, R})
            end;
        _ ->
            case Code of
                200 -> UserHandler({ok, text, Reply});
                _ when Reply =/= <<>> -> UserHandler({error, Reply});
                _ -> UserHandler({error, CodeText})
            end
    end;
handle_post_async_reply(UserHandler, Unhandled) ->
    ?log_error("Unhandled response from httpc: ~p", [Unhandled]),
    UserHandler({error, {unexpected, Unhandled}}).

format_value(undefined) -> <<"NaN">>;
format_value(infinity) -> <<"Inf">>;
format_value(neg_infinity) -> <<"-Inf">>;
format_value(B) when is_binary(B) -> B;
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

format_promql(AST) ->
    iolist_to_binary(format_promql_ast(AST)).

format_promql_ast({call, F, By, Args}) when is_atom(F) ->
    format_promql_ast({call, atom_to_list(F), By, Args});
format_promql_ast({call, F, By, Args}) ->
    ByStr =
        case By of
            {by, L} -> [" by (", lists:join(",", L) ,") "];
            {without, L} -> [" without (", lists:join(",", L) ,") "];
            none -> []
        end,
    [F, ByStr, "(", lists:join(",", [format_promql_ast(E) || E <- Args]), ")"];
format_promql_ast({Op, Exprs}) when Op =:= 'or'; Op =:= 'and' ->
    OpStr = " " ++ atom_to_list(Op) ++ " ",
    lists:join(OpStr, [format_promql_ast(E) || E <- Exprs]);
format_promql_ast({range_vector, Expr, Duration}) ->
    [format_promql_ast(Expr), "[", Duration, "]"];
format_promql_ast({Labels}) when is_list(Labels) ->
    LabelsIOLists =
      lists:map(
        fun ({re, Name, Value}) ->
                [Name, "=~`", Value, "`"];
            ({eq, Name, Value}) ->
                [Name, "=`", Value, "`"]
        end, Labels),
    ["{" ++ lists:join(",", LabelsIOLists) ++ "}"];
format_promql_ast(N) when is_integer(N) ->
    erlang:integer_to_list(N);
format_promql_ast(X) when is_float(X) ->
    erlang:float_to_list(X).
