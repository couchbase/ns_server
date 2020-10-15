-module(prometheus).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([query_range/6, query_range_async/7, query/4,
         format_value/1, parse_value/1, format_promql/1,
         create_snapshot/2]).

create_snapshot(Timeout, Settings) ->
    case post("/api/v1/admin/tsdb/snapshot", [], Timeout, Settings) of
        {ok, json, {Data}} ->
            SnapshotName = proplists:get_value(<<"name">>, Data, {[]}),
            StoragePath = proplists:get_value(storage_path, Settings),
            FullStoragePath = path_config:component_path(data, StoragePath),
            {ok, filename:join([FullStoragePath, "snapshots", SnapshotName])};
        {error, Reason} ->
            {error, Reason}
    end.

query_range(Query, Start, End, Step, Timeout, Settings) ->
    wait_async(
      fun (H) ->
          query_range_async(Query, Start, End, Step, Timeout, Settings, H)
      end, Timeout).

query_range_async(Query, Start, End, Step, Timeout, Settings, Handler)
                  when is_integer(Step) ->
    StepStr = integer_to_list(Step) ++ "s",
    query_range_async(Query, Start, End, StepStr, Timeout, Settings, Handler);
query_range_async(Query, Start, End, Step, Timeout, Settings, Handler) ->
    TimeoutStr = integer_to_list(max(Timeout div 1000, 1)) ++ "s",
    Body = [{query, Query}, {start, Start}, {'end', End}, {step, Step},
            {timeout, TimeoutStr}],
    HandlerWrap =
        fun ({ok, json, {Data}}) ->
                Res = proplists:get_value(<<"result">>, Data, {[]}),
                Handler({ok, Res});
            ({error, Reason}) ->
                Handler({error, Reason})
        end,
    post_async("/api/v1/query_range", Body, Timeout, Settings, HandlerWrap).

query(Query, Time, Timeout, Settings) ->
    wait_async(fun (H) -> query_async(Query, Time, Timeout, Settings, H) end,
               Timeout).

query_async(Query, Time, Timeout, Settings, Handler) ->
    TimeoutStr = integer_to_list(max(Timeout div 1000, 1)) ++ "s",
    Body = [{query, Query}, {timeout, TimeoutStr}] ++
           [{time, Time} || Time =/= undefined],
    HandlerWrap =
        fun ({ok, json, {Data}}) ->
                Res = proplists:get_value(<<"result">>, Data, {[]}),
                Handler({ok, Res});
            ({error, Reason}) ->
                Handler({error, Reason})
        end,
    post_async("/api/v1/query", Body, Timeout, Settings, HandlerWrap).

post(Path, Body, Timeout, Settings) ->
    wait_async(fun (H) -> post_async(Path, Body, Timeout, Settings, H) end,
               Timeout).

%% Wait in a separate process in order to correctly handle (ignore)
%% late replies in case when request times out.
wait_async(F, Timeout) ->
    misc:executing_on_new_process(
      fun () ->
          Self = self(),
          Ref = make_ref(),
          F(fun (Res) -> Self ! {Ref, Res} end),
          receive
              {Ref, Res} -> Res
          after Timeout ->
              {error, timeout}
          end
      end).

post_async(Path, Body, Timeout, Settings, Handler) ->
    case proplists:get_value(enabled, Settings) of
        true ->
            Addr = proplists:get_value(addr, Settings),
            URL = lists:flatten(io_lib:format("http://~s~s", [Addr, Path])),
            BodyEncoded = mochiweb_util:urlencode(Body),
            {Username, Password} = proplists:get_value(prometheus_creds,
                                                       Settings),
            Headers = [menelaus_rest:basic_auth_header(Username, Password)],
            AFamily = proplists:get_value(afamily, Settings),
            Receiver =
                fun (Res) ->
                    try
                        case handle_post_async_reply(Res) of
                            {ok, _, _} = Reply -> Handler(Reply);
                            {error, Reason} = Reply ->
                                ?log_error("Prometheus http request failed:~n"
                                           "URL: ~s~nBody: ~s~nReason: ~p",
                                           [URL, BodyEncoded, Reason]),
                                Handler(Reply)
                        end
                    catch
                        Class:Error:ST ->
                            ?log_error("Exception in httpc receiver ~p:~p~n"
                                       "Stacktrace: ~p~nRes: ~w",
                                       [Class, Error, ST, Res])
                    end
                end,
            HttpOptions = [{timeout, Timeout}, {connect_timeout, Timeout}],
            Options = [{sync, false}, {receiver, Receiver},
                       {socket_opts, [{ipfamily, AFamily}]}],
            Req = {URL, Headers, "application/x-www-form-urlencoded",
                   BodyEncoded},
            {ok, _} = httpc:request('post', Req, HttpOptions, Options);
        false ->
            Handler({error, <<"Stats backend is disabled">>})
    end,
    ok.

handle_post_async_reply({_Ref, {error, R}}) ->
    {error, R};
handle_post_async_reply({_Ref, {{_, Code, CodeText}, Headers, Reply}}) ->
    case proplists:get_value("content-type", Headers) of
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
                    R = misc:format_bin("Invalid json in reply: ~s", [Reply]),
                    {error, R}
            end;
        _ ->
            case Code of
                200 -> {ok, text, Reply};
                _ when Reply =/= <<>> -> {error, Reply};
                _ -> {error, CodeText}
            end
    end;
handle_post_async_reply(Unhandled) ->
    ?log_error("Unhandled response from httpc: ~p", [Unhandled]),
    {error, {unexpected, Unhandled}}.

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

-define(BINOP(Op), Op =:= 'or'; Op =:= 'and'; Op =:= 'unless'; Op =:= '/';
                   Op =:= '+';  Op =:= '-';   Op =:= '/';      Op =:= '*';
                   Op =:= '%';  Op =:= '^';   Op =:= '==';     Op =:= '!=';
                   Op =:= '>';  Op =:= '<';   Op =:= '>=';     Op =:= '<=').

-define(AGGREGATION_OP(Op), Op =:= sum;     Op =:= min;   Op =:= max;
                            Op =:= avg;     Op =:= group; Op =:= stddev;
                            Op =:= stdvar;  Op =:= count; Op =:= count_values;
                            Op =:= bottomk; Op =:= topk;  Op =:= quantile).

-define(MERGE_LABEL, <<"name">>).

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
format_promql_ast({Op, Exprs}) when ?BINOP(Op) ->
    format_promql_ast({Op, [], Exprs});
format_promql_ast({Op, Opts, Exprs0}) when ?BINOP(Op) ->
    Exprs = case Op of
                'or' -> merge_or_operands(Exprs0);
                _ -> Exprs0
            end,
    OptsIOList = lists:map(fun ({T, L}) ->
                               [atom_to_list(T), "(", lists:join(",", L), ") "]
                           end, Opts),
    OpStr = " " ++ atom_to_list(Op) ++ " " ++ OptsIOList,
    lists:join(OpStr, lists:map(fun ({O, _} = E) when ?BINOP(O) ->
                                        ["(", format_promql_ast(E), ")"];
                                    ({O, _, _} = E) when ?BINOP(O) ->
                                        ["(", format_promql_ast(E), ")"];
                                    (E) ->
                                        format_promql_ast(E)
                                end, Exprs));
format_promql_ast({range_vector, Expr, Duration}) ->
    [format_promql_ast(Expr), "[", Duration, "]"];
format_promql_ast({Labels}) when is_list(Labels) ->
    LabelsIOLists =
      lists:map(
        fun ({re, Name, Value}) ->
                [Name, "=~`", Value, "`"];
            ({eq_any, Name, [_|_] = Values}) ->
                [Name, "=~`", lists:join("|", Values), "`"];
            ({eq, Name, Value}) ->
                [Name, "=`", Value, "`"]
        end, Labels),
    ["{" ++ lists:join(",", LabelsIOLists) ++ "}"];
format_promql_ast(Bin) when is_binary(Bin) ->
    <<"`", Bin/binary, "`">>;
format_promql_ast(N) when is_integer(N) ->
    erlang:integer_to_list(N);
format_promql_ast(X) when is_float(X) ->
    erlang:float_to_list(X).

%% Transform "f({name=`m1`, ...}) or f({name=`m2`, ...} or ..." to
%% "f({name=~`m1|m1|...`, ...})" as it works faster.
%% Note: it's correct only if function 'f' commutes with 'or'
merge_or_operands(List) ->
    Sorted = lists:usort(
               fun (A, B) ->
                   comparable(A) =< comparable(B)
               end, List),
    merge_or_operands_sorted(Sorted, []).

merge_or_operands_sorted([], Res) -> lists:reverse(Res);
merge_or_operands_sorted([E], Res) -> merge_or_operands_sorted([], [E | Res]);
merge_or_operands_sorted([E1, E2 | T], Res) ->
    case merge_or_operands(E1, E2) of
        match -> merge_or_operands_sorted([E1 | T], Res);
        {merged, E} -> merge_or_operands_sorted([E | T], Res);
        conflict -> merge_or_operands_sorted([E2 | T], [E1 | Res])
    end.

merge_or_operands({Op, [Op1, Scalar]}, {Op, [Op2, Scalar]})
                                                    when (Op =:= '*' orelse
                                                          Op =:= '/'),
                                                         is_number(Scalar) ->
    case merge_or_operands(Op1, Op2) of
        match -> match;
        conflict -> conflict;
        {merged, M} -> {merged, {Op, [M, Scalar]}}
    end;
merge_or_operands({call, F, By, Args1}, {call, F, By, Args2})
                                        when length(Args1) == length(Args2) ->
    case commute_with_or(F, By) of
        true ->
            {NewArgs, Res} =
                lists:mapfoldl(
                  fun ({_, _}, conflict) ->
                          {undefined, conflict};
                      ({A1, A2}, Status) ->
                          case merge_or_operands(A1, A2) of
                              match -> {A1, match};
                              conflict -> {undefined, conflict};
                              {merged, M} when Status =:= match -> {M, merged};
                              {merged, _} -> {undefined, conflict}
                          end
                  end, match, lists:zip(Args1, Args2)),
            case Res of
                conflict -> conflict;
                merged -> {merged, {call, F, By, NewArgs}};
                match -> match
            end;
        false ->
            conflict
    end;
merge_or_operands({range_vector, E1, D}, {range_vector, E2, D}) ->
    case merge_or_operands(E1, E2) of
        match -> match;
        conflict -> conflict;
        {merged, E} -> {merged, {range_vector, E, D}}
    end;
merge_or_operands({L1}, {L2}) when is_list(L1), is_list(L2) ->
    case {extract_merge_label(L1), extract_merge_label(L2)} of
        {{Names, Rest}, {Names, Rest}} ->
            match;
        {{Names1, Rest}, {Names2, Rest}} ->
            NewNames = lists:umerge(Names1, Names2),
            {merged, {[{eq_any, ?MERGE_LABEL, NewNames} | Rest]}};
        _ ->
            conflict
    end;
merge_or_operands(Q, Q) -> match;
merge_or_operands(_, _) -> conflict.

comparable({List}) when is_list(List) ->
    case extract_merge_label(List) of
        {Names, Rest} -> {{lists:usort(Rest)}, Names};
        not_found -> {{lists:usort(List)}, []}
    end;
comparable({Op, List}) when ?BINOP(Op) ->
    comparable({Op, [], List});
comparable({Op, Opts, Args}) when ?BINOP(Op) ->
    {NewArgs, NewNames} = comparable(Args),
    {{Op, Opts, NewArgs}, NewNames};
comparable({call, F, By, Args}) when is_atom(F) ->
    comparable({call, atom_to_binary(F, latin1), By, Args});
comparable({call, F, By, Args}) ->
    {NewArgs, NewNames} = comparable(Args),
    {{call, F, By, NewArgs}, NewNames};
comparable({range_vector, Expr, Duration}) ->
    {NewExpr, Names} = comparable(Expr),
    {{range_vector, NewExpr, Duration}, Names};
comparable(L) when is_list(L) ->
    lists:mapfoldl(
      fun (A, Acc) ->
          {NewA, Names} = comparable(A),
          {NewA, Acc ++ Names}
      end, [], L);
comparable(Const) when is_number(Const); is_binary(Const) ->
    {Const, []}.

commute_with_or(F, {by, List}) when ?AGGREGATION_OP(F) ->
    lists:member(?MERGE_LABEL, List);
commute_with_or(F, none) when ?AGGREGATION_OP(F) -> false;
commute_with_or(_, none) -> true.

extract_merge_label(Props) ->
    case lists:keytake(?MERGE_LABEL, 2, Props) of
        {value, {eq, _, N}, Rest} -> {[N], Rest};
        {value, {eq_any, _, NL}, Rest} -> {lists:usort(NL), Rest};
        _ -> not_found
    end.

-ifdef(TEST).
format_promql_test() ->
    ?assertEqual(format_promql({[]}), <<"{}">>),
    ?assertEqual(format_promql({[{eq, <<"label1">>, <<"val1">>},
                                 {eq_any, <<"label2">>, [<<"opt1">>,
                                                         <<"opt2">>,
                                                         <<"opt3">>]},
                                 {re, <<"label3">>, "re"}]}),
                 <<"{label1=`val1`,label2=~`opt1|opt2|opt3`,label3=~`re`}">>),
    ?assertEqual(format_promql({call, sum, {by, [<<"label1">>, <<"label2">>]},
                                [{[{eq, <<"name">>, <<"metric">>}]}]}),
                 <<"sum by (label1,label2) ({name=`metric`})">>),
    ?assertEqual(format_promql({'or', [{[{eq, <<"label1">>, <<"val1">>}]},
                                       {[{eq, <<"label2">>, <<"val2">>}]}]}),
                 <<"{label1=`val1`} or {label2=`val2`}">>),
    ?assertEqual(format_promql({'/', [{ignoring, [<<"l1">>, <<"l2">>]},
                                      {group_left, [<<"l3">>, <<"l4">>]}],
                                     [{[{eq, <<"l1">>, <<"v1">>}]},
                                      {[{eq, <<"l2">>, <<"v2">>}]}]}),
                 <<"{l1=`v1`} / ignoring(l1,l2) group_left(l3,l4) "
                   "{l2=`v2`}">>),
    ?assertEqual(format_promql({call, label_replace, none,
                                [{[]}, <<"l1">>, <<"l2">>, <<>>, <<>>]}),
                 <<"label_replace({},`l1`,`l2`,``,``)">>),
    ?assertEqual(format_promql({call, vector, none, [1]}), <<"vector(1)">>),
    ?assertEqual(format_promql({call, rate, none,
                                [{range_vector, {[]}, <<"1m">>}]}),
                 <<"rate({}[1m])">>),
    ?assertEqual(format_promql({'*', [{'+', [{[{eq, <<"l1">>, <<"v1">>}]},
                                             {[{eq, <<"l2">>, <<"v2">>}]}]},
                                      {'+', [{[{eq, <<"l3">>, <<"v3">>}]},
                                             {[{eq, <<"l4">>, <<"v4">>}]}]}]}),
                <<"({l1=`v1`} + {l2=`v2`}) * ({l3=`v3`} + {l4=`v4`})">>),
    ?assertEqual(format_promql({'or', [{[{eq, <<"l1">>, <<"v1">>}]},
                                       {[{eq, <<"l1">>, <<"v1">>}]}]}),
                <<"{l1=`v1`}">>),
    ?assertEqual(format_promql({'or', [{[{eq, <<"name">>, <<"v1">>}]},
                                       {[{eq, <<"name">>, <<"v2">>}]}]}),
                <<"{name=~`v1|v2`}">>),
    ?assertEqual(format_promql({'or', [{[{eq, <<"name">>, <<"v1">>}]},
                                       {[{eq, <<"name">>, <<"v2">>},
                                         {eq, <<"l2">>, <<"v3">>}]}]}),
                <<"{name=`v1`} or {name=`v2`,l2=`v3`}">>),
    ?assertEqual(format_promql(
                   {'or', [{call, irate, none,
                            [{range_vector,
                              {[{eq, <<"name">>, <<"v1">>},
                                {eq, <<"l1">>, <<"v2">>}]},
                              <<"1m">>}]},
                           {[{eq, <<"name">>, <<"v2">>},
                             {eq, <<"l1">>, <<"v2">>}]},
                           {call, irate, none,
                            [{range_vector,
                              {[{eq, <<"l1">>, <<"v2">>},
                                {eq_any, <<"name">>, [<<"v2">>,<<"v3">>]}]},
                              <<"1m">>}]}]}),
                 <<"{name=`v2`,l1=`v2`} or "
                   "irate({name=~`v1|v2|v3`,l1=`v2`}[1m])">>).
-endif.
