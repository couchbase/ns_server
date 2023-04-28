%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% @doc generic handlers for settings management endpoints
%%
%% User module is supposed to define param specs. For example:
%%
%% Params = [{"path.to.myParam1", #{cfg_name => param_name1, type => int}},
%%           {"path.to.myParam2", #{cfg_name => param_name2, type => bool}},
%%           {"path.to.myParam3", #{cfg_name => param_name3, type => my_type}}]
%%
%% Cfg_name could be either atom or list of atoms. If list of atoms is used it
%% means the value is expected to be saved in nested proplist.
%% Param type should be either standard (defined in this module), or "custom" -
%% defined in user's module. For example:
%%
%% type_spec(my_type) -> #{validators => [Validator],
%%                         formatter => Formatter}
%%
%% (note that user defined types have precedence over standard types)
%%
%% After that handle_get and handle_post functions can be called to handle get
%% and set operations for described above params.
%%
%% When http GET is received, handle_get can be used to format provided values
%% as json and send http response. For example:
%% handle_get([], Params, fun type_spec/1, [{param_name1, 123}], Req)
%% will reply 200 with the following json body:
%% {"path": {"to": {"myParam1": 123}}}
%%
%% handle_get(["path"], Params, fun type_spec/1, [{param_name1, 123}], Req)
%% will reply 200 with the following json body:
%% {"to": {"myParam1": 123}}
%%
%% handle_get(["path", "to"], Params, fun type_spec/1, [{param_name1, 123}],
%%            Req)
%% will reply 200 with the following json body:
%% {"myParam1": 123}
%%
%% handle_get(["path", "to", "myParam1"], Params, fun type_spec/1,
%%            [{param_name1, 123}], Req)
%% will reply 200 with the following json body: 123
%%
%% When POST /path is received, handle_post can be used to parse post body. It
%% calls user provided fun and passes parsed params to it. ApplyFun is supposed
%% to save the received params. For example:
%%
%% POST / with body: {"path": {"to": {"myParam2": true}}}
%% handle_post(ApplyFun, [], Params, fun type_spec/1, Req)
%%
%% POST /path with body: {"to": {"myParam2": true}}
%% handle_post(ApplyFun, ["path"], Params, fun type_spec/1, Req)
%%
%% In all the examples above handle_post will call ApplyFun with
%% [{[param_name1], true}]

-module(menelaus_web_settings2).

-export([prepare_json/4, handle_get/5, handle_post/5, handle_post/7]).

-include("ns_common.hrl").
-include("cut.hrl").
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export_type([param_spec/0, type_spec/0]).

-type param_spec() :: {JSONName :: string(), #{cfg_name => [atom()] | atom(),
                                               type := type_spec_name()}}.

-type type_spec_name() :: term().
-type validator() :: fun ((_Name, State) -> State) | type_spec_name().
-type formatter() :: fun ((_Term) -> _JSONTerm) | type_spec_name().
-type type_spec() :: #{validators => [validator()],
                       formatter => formatter()}.

-spec type_spec(Name :: type_spec_name()) -> type_spec().
type_spec(bool) ->
    #{validators => [fun validator:boolean/2], formatter => existing_atom};
type_spec(pos_int) ->
    #{validators => [int, greater_than(_, 0, _)], formatter => int};
type_spec(non_neg_int) ->
    #{validators => [int, greater_than(_, -1, _)], formatter => int};
type_spec(int) ->
    #{validators => [fun validator:integer/2]};
type_spec({int, Min, Max}) ->
    #{validators => [?cut(validator:integer(_1, Min, Max, _2))],
      formatter => int};
type_spec(existing_atom) ->
    #{validators => [fun existing_atom/2]};
type_spec(string) ->
    #{validators => [fun validator:string/2],
      formatter => fun (V) -> {value, list_to_binary(V)} end};
type_spec({one_of, Type, List}) ->
    #{validators => [validator:one_of(_, List, _), Type], formatter => Type};
type_spec(password) ->
    #{validators => [string, ?cut(validator:convert(_1, fun (P) ->
                                                            {password, P}
                                                        end, _2))],
      formatter => fun ({password, ""}) -> {value, <<>>};
                       ({password, _}) -> {value, <<"**********">>}
                   end};
type_spec(not_supported) ->
    #{validators => [fun not_supported/2],
      formatter => fun (_) -> ignore end};
type_spec({string_list, Separator}) ->
    #{validators => [validate_string_list(Separator, _, _)],
      formatter => fun (L) -> {value, [list_to_binary(M) || M <- L]} end}.

validate_string_list(Separator, Name, State) ->
    case validator:is_json(State) of
          true -> validator:string_array(Name, State);
          false -> validator:token_list(Name, Separator, State)
    end.

not_supported(Name, State) ->
    validator:validate(
      fun (_) -> {error, "modification not supported"} end,
      Name, State).

prepare_json(Path, ParamSpecs, UserTypesFun, Values) ->
    TypesFuns = [UserTypesFun, fun type_spec/1],
    Res = lists:filtermap(
            fun ({Name, #{type := Type} = Spec}) ->
                NameTokens = split_key(Name),
                case extract_key(Path, NameTokens) of
                    {ok, Keys} ->
                        FormattedKey = [list_to_binary(K) || K <- Keys],
                        InternalName = cfg_key(Name, Spec),
                        Formatter = extract_formatter(Type, TypesFuns),
                        case extract_value(InternalName, Values) of
                            not_found ->
                                case maps:find(default, Spec) of
                                    {ok, Default} ->
                                        {true, {FormattedKey, Default}};
                                    error ->
                                        false
                                end;
                            {value, Value} ->
                                case Formatter(Value) of
                                    {value, FormattedValue} ->
                                        {true, {FormattedKey, FormattedValue}};
                                    ignore ->
                                        false
                                end
                        end;
                    error -> false
                end
            end, ParamSpecs),
    group_elements(Res, ?cut({_})).

handle_get(Path, ParamSpecs, UserTypesFun, Values, Req) ->
    menelaus_util:reply_json(
      Req, prepare_json(Path, ParamSpecs, UserTypesFun, Values)).

handle_post(ApplyFun, Path, ParamSpecs, UserTypesFun, Req) ->
    handle_post(ApplyFun, Path, ParamSpecs, UserTypesFun, [], [], Req).

%% Note about Predefined and Defaults:
%% If some setting is mandatory, it must be present in Req or in Predefined,
%% Usually "Predefined" are the setting that were set by this endpoint
%% before.
%% Defaults are only used when values are passed to the "is mandatory" fun.
handle_post(ApplyFun, Path, ParamSpecs, UserTypesFun, Predefined, Defaults,
            Req) ->
    TypesFuns = [UserTypesFun, fun type_spec/1],
    ValidatorsProplist =
        lists:filtermap(
              fun ({Name, #{type := Type}}) ->
                  NameTokens = split_key(Name),
                  case extract_key(Path, NameTokens) of
                      {ok, Keys} ->
                          {true, {Keys, extract_validators(Type, TypesFuns)}};
                      error -> false
                  end
              end, ParamSpecs),

    AllPossibleKeys = [Keys || {Keys, _} <- ValidatorsProplist],
    Validators = [fun (S) -> F(join_key(Keys), S) end
                    || {Keys, Funs} <- ValidatorsProplist, F <- Funs],
    Params = parse_params(AllPossibleKeys, Req),

    validator:handle(
      fun (Props) ->
          Props2 =
              lists:map(
                fun ({Key, Value}) ->
                    FullKey = join_key(Path ++ split_key(atom_to_list(Key))),
                    Spec = proplists:get_value(FullKey, ParamSpecs),
                    InternalKey = cfg_key(FullKey, Spec),
                    {InternalKey, Value}
                end, Props),
          ExtraValidators = mandatory_validators(Path, Props2, ParamSpecs,
                                                 Predefined, Defaults),
          validator:handle(
            fun (_) ->
                ApplyFun(Props2, Req)
            end, Req,
            [{atom_to_list(K), V} || {K, V} <- Props],
            ExtraValidators)
      end, Req, Params, Validators ++ [validator:unsupported(_)]).

%% Returns list of validators that check that all mandatory values are present
mandatory_validators(Path, Props2, ParamSpecs, Predefined, Defaults) ->
    AllPropsIncludingPredefined =
        lists:foldl(
          fun ({Name, #{} = Spec}, Acc) ->
              InternalKey = cfg_key(Name, Spec),
              case proplists:get_all_values(InternalKey, Props2) of
                  [] ->
                      case extract_value(InternalKey, Predefined) of
                          not_found ->
                              case extract_value(InternalKey, Defaults) of
                                  not_found ->
                                      Acc;
                                  {value, V} ->
                                      Acc#{cfg_key_as_is(Name, Spec) => V}
                              end;
                          {value, V} ->
                              Acc#{cfg_key_as_is(Name, Spec) => V}
                      end;
                  [V] ->
                      Acc#{cfg_key_as_is(Name, Spec) => V}
              end
          end, maps:from_list(Props2), ParamSpecs),
    lists:filtermap(
      fun ({Name, #{mandatory := F} = Spec}) ->
              case (F == true) orelse
                   (is_function(F) andalso F(AllPropsIncludingPredefined)) of
                  true ->
                      InternalKey = cfg_key(Name, Spec),
                      case extract_value(InternalKey, Predefined) of
                          not_found ->
                              NameTokens = split_key(Name),
                              Keys = extract_relative_key(Path, NameTokens),
                              ParamName = join_key(Keys),
                              {true, validator:required(ParamName, _)};
                          {value, _} ->
                              false
                      end;
                  false ->
                      false
              end;
          ({_Name, _Spec}) ->
              false
      end, ParamSpecs).

parse_params(AllPossibleKeys, Req) ->
    Type =
        case mochiweb_request:get_primary_header_value("content-type", Req) of
            "application/json" -> json;
            "application/x-www-form-urlencoded" -> form;
            "text/plain" -> text;
            undefined -> text;
            CT ->
                S = io_lib:format("Unsupported content-type: ~p", [CT]),
                menelaus_util:web_exception(400,  S)
        end,

    Params =
        case Type of
            text -> [{[],  mochiweb_request:recv_body(Req)}];
            form when AllPossibleKeys == [""] -> %% Full key is passed in path
                                                 %% and body contains only value
                Body = mochiweb_request:recv_body(Req),
                [{[], mochiweb_util:unquote(Body)}];
            form ->
                lists:map(fun ({Key, Val}) ->
                              KeyTokens = string:split(Key, "/", all),
                              {KeyTokens, Val}
                          end, mochiweb_request:parse_post(Req));
            json ->
                Body = case mochiweb_request:recv_body(Req) of
                           <<>> -> <<"{}">>; %% treat empty body as an empty
                                             %% object due to backward compat
                                             %% reasons
                           B -> B
                       end,
                JSON = try
                           ejson:decode(Body)
                       catch
                           _:_ ->
                               menelaus_util:web_exception(400, "Invalid JSON")
                       end,
                flatten_json(AllPossibleKeys, JSON, [])
        end,
    validator:add_input_type(Type, [{join_key(KL), V} || {KL, V} <- Params]).

flatten_json([], Value, Path) -> [{Path, Value}];
flatten_json([[]], Value, Path) -> [{Path, Value}];
flatten_json(AllPossibleKeys, {JSON}, Path) when is_list(JSON) ->
    lists:flatmap(
      fun ({KeyBin, Value}) ->
          KeyStr = binary_to_list(KeyBin),
          NewPossibleKeys = lists:filtermap(
                              fun ([K | Tail]) when K == KeyStr -> {true, Tail};
                                  (_) -> false
                              end, AllPossibleKeys),
          flatten_json(NewPossibleKeys, Value, Path ++ [KeyStr])
      end, JSON);
flatten_json(_AllPossibleKeys, _JSON, _Path) ->
    menelaus_util:web_exception(400, "JSON object is expected").

group_elements([{[], Value}], _) -> Value;
group_elements(Proplist, GroupFormatter) ->
    Groupped = misc:groupby_map(fun ({[Head | Tail], Value}) ->
                                    {Head, {Tail, Value}}
                                end, Proplist),
    GroupFormatter(lists:map(
                     fun ({Key, Values}) ->
                         {Key, group_elements(Values, GroupFormatter)}
                     end, Groupped)).

extract_formatter(Type, TypesFuns) ->
    extract_formatter(Type, TypesFuns, []).
extract_formatter(Type, [], _) -> error({unknown_type, Type});
extract_formatter(Type, [F | Tail], TypesSeen) ->
    case lists:member(Type, TypesSeen) of
        true -> error({circular_dependency, Type});
        false -> ok
    end,
    try F(Type) of
        #{formatter := Formatter} when is_function(Formatter) -> Formatter;
        #{formatter := SubType} ->
            extract_formatter(SubType, [F | Tail], [Type|TypesSeen]);
        #{} -> fun (V) -> {value, V} end
    catch
        error:function_clause -> extract_formatter(Type, Tail, TypesSeen)
    end.

extract_validators(Type, TypesFuns) ->
    extract_validators(Type, TypesFuns, []).
extract_validators(Type, [], _) -> error({unknown_type, Type});
extract_validators(Type, [F | Tail], TypesSeen) ->
    case lists:member(Type, TypesSeen) of
        true -> error({circular_dependency, Type});
        false -> ok
    end,
    try F(Type) of
        #{validators := Validators} ->
            lists:flatmap(
              fun (Fun) when is_function(Fun) -> [Fun];
                  (SubType) ->
                      extract_validators(SubType, [F | Tail], [Type | TypesSeen])
              end, Validators);
        #{} -> []
    catch
        error:function_clause -> extract_validators(Type, Tail, TypesSeen)
    end.

extract_value([], Value) -> {value, Value};
extract_value([Key | Tail], PropList) ->
    case proplists:get_all_values(Key, PropList) of
        [] -> not_found;
        [Value] -> extract_value(Tail, Value)
    end.

extract_key([], Tokens) -> {ok, Tokens};
extract_key(_Path, []) -> error;
extract_key([El | Path], [El | Tokens]) -> extract_key(Path, Tokens);
extract_key(_, _) -> error.

extract_relative_key([], Tokens) -> Tokens;
extract_relative_key([El | Path], [El | Tokens]) ->
    extract_relative_key(Path, Tokens);
extract_relative_key(Path, Tokens) ->
    ["[upper-level]" || _ <- Path] ++ Tokens.

existing_atom(Name, State) ->
    validator:convert(
      Name,
      fun (Bin) when is_binary(Bin) ->
              erlang:binary_to_existing_atom(Bin, latin1);
          (Str) ->
              erlang:list_to_existing_atom(Str)
      end, State).

greater_than(Name, N, State) ->
    validator:validate(
      fun (V) when V > N -> {value, V};
          (_) -> {error, io_lib:format("Value must be greater than ~p", [N])}
      end, Name, State).

split_key("") -> [];
split_key(K) -> string:split(K, ".", all).

join_key(K) -> lists:flatten(lists:join(".", K)).

cfg_key(Name, Spec) ->
    case cfg_key_as_is(Name, Spec) of
        List when is_list(List) -> List;
        Key -> [Key]
    end.

cfg_key_as_is(Name, Spec) ->
    maps:get(cfg_key, Spec, list_to_atom(Name)).

-ifdef(TEST).

test_params() ->
    [{"key1.key2-1.key3-1", #{cfg_key => ckey1, type => int}},
     {"key1.key2-2.key3-1", #{cfg_key => [ckey2_1, ckey2_2], type => int}},
     {"key1.key2-2.key3-2", #{cfg_key => [ckey3], type => custom}}].

test_type_spec(custom) ->
    #{validators => [int, validator:validate(
                            fun (Int) ->
                                ?assertEqual(Int, 42),
                                {value, 42}
                            end, _, _)],
      formatter => fun (Int) -> ?assertEqual(Int, 42), {value, 42} end}.

prepare_json_test() ->
    Prepare =
        fun (Path, Values) ->
            J = prepare_json(Path, test_params(), fun test_type_spec/1, Values),
            binary_to_list(ejson:encode(J))
        end,
    ?assertEqual("{}", Prepare([], [])),
    ?assertEqual("{\"key1\":{\"key2-1\":{\"key3-1\":1},"
                            "\"key2-2\":{\"key3-1\":2,\"key3-2\":42}}}",
                 Prepare([],
                         [{ckey1, 1},{ckey2_1, [{ckey2_2, 2}]}, {ckey3, 42}])),
    ?assertEqual("{\"key2-1\":{\"key3-1\":1},"
                  "\"key2-2\":{\"key3-1\":2,\"key3-2\":42}}",
                 Prepare(["key1"],
                         [{ckey1, 1},{ckey2_1, [{ckey2_2, 2}]}, {ckey3, 42}])),
    ?assertEqual("{\"key3-1\":2,\"key3-2\":42}",
                 Prepare(["key1", "key2-2"],
                         [{ckey1, 1},{ckey2_1, [{ckey2_2, 2}]}, {ckey3, 42}])),
    ?assertEqual("42",
                 Prepare(["key1", "key2-2", "key3-2"],
                         [{ckey1, 1},{ckey2_1, [{ckey2_2, 2}]}, {ckey3, 42}])).

with_request(Fun) ->
    meck:new(mochiweb_request, [passthrough]),
    meck:new(menelaus_util, [passthrough]),
    Ets = ets:new(test_ets, [set, public]),
    try
        Req = make_ref(),
        meck:expect(mochiweb_request, recv_body,
                    fun (R) when R == Req ->
                        [{_, Body}] = ets:lookup(Ets, body),
                        Body
                    end),
        meck:expect(mochiweb_request, parse_post,
                    fun (R) when R == Req ->
                        [{_, ContType}] = ets:lookup(Ets, content_type),
                        case ContType == "application/x-www-form-urlencoded" of
                            true ->
                                [{_, Body}] = ets:lookup(Ets, body),
                                mochiweb_util:parse_qs(Body);
                            false -> []
                        end
                    end),
        meck:expect(mochiweb_request, get_primary_header_value,
                    fun ("content-type", R) when R == Req ->
                        [{_, ContType}] = ets:lookup(Ets, content_type),
                        ContType
                    end),
        meck:expect(mochiweb_request, parse_qs,
                    fun (R) when R == Req -> [] end),
        meck:expect(menelaus_util, reply_json,
                    fun (R, {[{errors, Errors}]}, 400) when R == Req ->
                        error({validation_failed, Errors})
                    end),
        Fun(fun (ContType) -> ets:insert(Ets, {content_type, ContType}) end,
            fun (Body) -> ets:insert(Ets, {body, Body}) end, Req)
    after
        ets:delete(Ets),
        meck:unload(menelaus_util),
        meck:unload(mochiweb_request)
    end.

handle_post_test() ->
    with_request(
      fun (SetContType, SetBody, Req) ->
          HandlePost =
              fun (Path, ContType, Body, ExpectedResult) ->
                  SetContType(ContType),
                  SetBody(Body),
                  handle_post(fun (Parsed, Req2) when Req == Req2 ->
                                  ?assertEqual(ExpectedResult, Parsed)
                              end, Path, test_params(),
                              fun test_type_spec/1, Req)
              end,
          HandlePost([],
                     "application/x-www-form-urlencoded",
                     <<"key1.key2-1.key3-1=1&key1.key2-2.key3-1=2&"
                       "key1.key2-2.key3-2=42">>,
                     [{[ckey1], 1}, {[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1"],
                     "application/x-www-form-urlencoded",
                     <<"key2-1.key3-1=1&key2-2.key3-1=2&key2-2.key3-2=42">>,
                     [{[ckey1], 1}, {[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1", "key2-2"],
                     "application/x-www-form-urlencoded",
                     <<"key3-1=2&key3-2=42">>,
                     [{[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1", "key2-2", "key3-2"],
                     "application/x-www-form-urlencoded",
                     <<"42">>,
                     [{[ckey3], 42}]),

          HandlePost([],
                     "application/json",
                     <<"{\"key1\": {\"key2-1\": {\"key3-1\": 1}, "
                                   "\"key2-2\": {\"key3-1\": 2, "
                                                "\"key3-2\": 42}}}">>,
                     [{[ckey1], 1}, {[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1"],
                     "application/json",
                     <<"{\"key2-1\": {\"key3-1\": 1}, "
                        "\"key2-2\": {\"key3-1\": 2, \"key3-2\": 42}}">>,
                     [{[ckey1], 1}, {[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1", "key2-2"],
                     "application/json",
                     <<"{\"key3-1\": 2, \"key3-2\": 42}">>,
                     [{[ckey2_1, ckey2_2], 2}, {[ckey3], 42}]),
          HandlePost(["key1", "key2-2", "key3-2"],
                     "application/json",
                     <<"42">>,
                     [{[ckey3], 42}])
      end).

mandatory_test() ->
    Params = [{"K1.K2.K3", #{cfg_key => [k1, k2], type => int}},
              {"K1.K4", #{cfg_key => [t1, t2, t3], type => int,
                          %% This key is mandatory if K1.K2.K3 == 4
                          mandatory => fun (#{[k1, k2] := 4}) -> true;
                                           (#{}) -> false
                                       end}},
              {"K2.K4", #{cfg_key => t4, type => int,
                          %% This key is mandatory if K2.K2 is undefined
                          mandatory => fun (#{t3 := _}) -> false;
                                           (#{}) -> true
                                       end}},
              {"K2.K5", #{cfg_key => t3, type => int}}],

    with_request(
      fun (SetContType, SetBody, Req) ->
          SetContType("application/x-www-form-urlencoded"),
          Succ =
              fun (Path, Body, Predefined, Defaults, ExpectedResult) ->
                  SetBody(Body),
                  handle_post(fun (Parsed, Req2) when Req == Req2 ->
                                  ?assertEqual(ExpectedResult, Parsed)
                              end, Path, Params,
                              fun test_type_spec/1, Predefined, Defaults, Req)
              end,
          Fail =
              fun (Path, Body, Predefined, Defaults, ExpectedError) ->
                  SetBody(Body),
                  ?assertError(
                    {validation_failed, ExpectedError},
                    handle_post(fun (_Parsed, Req2) when Req == Req2 ->
                                    ?assert(false)
                                end, Path, Params,
                                fun test_type_spec/1,
                                Predefined, Defaults, Req))
              end,


          Fail([], <<"">>, [], [],
               {[{"K2.K4",<<"The value must be supplied">>}]}),
          Succ([], <<"K2.K5=1">>, [], [],
               [{[t3], 1}]),
          Succ([], <<"K1.K2.K3=3&K2.K5=1">>, [], [],
               [{[k1, k2], 3}, {[t3], 1}]),
          Fail([], <<"K1.K2.K3=3">>, [], [],
               {[{"K2.K4",<<"The value must be supplied">>}]}),
          Succ([], <<"K1.K2.K3=3&K2.K4=2">>, [], [],
               [{[k1, k2], 3}, {[t4], 2}]),
          Fail([], <<"K1.K2.K3=4&K2.K5=1">>, [], [],
               {[{"K1.K4",<<"The value must be supplied">>}]}),
          Succ([], <<"K1.K2.K3=4&K2.K5=1&K1.K4=2">>, [], [],
               [{[k1, k2], 4}, {[t3], 1}, {[t1, t2, t3], 2}]),
          Fail([], <<"K1.K2.K3=4">>, [], [],
               {[{"K2.K4",<<"The value must be supplied">>},
                 {"K1.K4",<<"The value must be supplied">>}]}),
          Succ([], <<"K1.K2.K3=4&K2.K4=1&K1.K4=2">>, [], [],
               [{[k1, k2], 4}, {[t4], 1}, {[t1, t2, t3], 2}]), 

          Fail(["K1"], <<"">>, [], [],
               {[{"[upper-level].K2.K4",<<"The value must be supplied">>}]}),
          Fail(["K1"], <<"K2.K3=3">>, [], [],
               {[{"[upper-level].K2.K4",<<"The value must be supplied">>}]}),
          Fail(["K1"], <<"K2.K3=4">>, [], [],
               {[{"[upper-level].K2.K4",<<"The value must be supplied">>},
                 {"K4",<<"The value must be supplied">>}]}),

          Succ(["K1"], <<"">>, [{t4, 2}], [], []),
          Fail(["K1"], <<"">>, [], [{t4, 2}],
               {[{"[upper-level].K2.K4",<<"The value must be supplied">>}]}),
          Succ(["K1"], <<"K2.K3=3">>, [{t4, 2}], [],
               [{[k1, k2], 3}]),
          Succ(["K1"], <<"K2.K3=4">>, [{t1, [{t2, [{t3, 4}]}]}, {t4, 1}], [],
               [{[k1, k2], 4}]),

          Fail([], <<"K2.K4=1">>, [{k1, [{k2, 4}]}], [],
               {[{"K1.K4",<<"The value must be supplied">>}]}),
          Fail([], <<"K2.K4=1">>, [], [{k1, [{k2, 4}]}],
               {[{"K1.K4",<<"The value must be supplied">>}]}),
          Succ([], <<"K2.K4=1">>, [{t1, [{t2, [{t3, 2}]}]}], [{k1, [{k2, 4}]}],
               [{[t4], 1}]),
          Fail([], <<"K2.K4=1">>, [], [{k1, [{k2, 4}]},
                                       {t1, [{t2, [{t3, 2}]}]}],
               {[{"K1.K4",<<"The value must be supplied">>}]})
      end).
-endif.
