%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% Removes private keys from log events (MB-62357).
%%
%% TLS connection processes keep the decrypted private key in their state, and
%% if that state ends up in a crash reason, the crash reports print the key.
%% ale_error_logger_handler passes every event through redact_report/2.
%%
%% Keys are found by their public_key record tags (ssl's {'PrivateKeyInfo',
%% Der} form included) and by PEM private key headers at the start of
%% binaries and strings.
%%
%% A term without keys is returned as is, and nothing is allocated for it
%% except map iterators. Otherwise only the containers on the way to a key are
%% copied. The stack grows with the nesting depth only.

-module(ale_redact).

-export([remove_private_keys/1, redact_report/2]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-endif.

-define(REDACTED, '*** redacted ***').
-define(REDACTED_PEM(Type), "*** " ++ Type ++ " PEM REDACTED ***").

%% Removes private keys from a logger message ({report, R}, {string, S} or
%% {Format, Args}). Never fails: if removing them fails, returns a
%% {Format, Args} message that describes the failure and has no part of Msg.
-spec redact_report(term(), logger:metadata()) -> term().
redact_report(Msg, Meta) ->
    redact_report(Msg, Meta, fun remove_private_keys/1).

redact_report(Msg, Meta, Redact) ->
    try
        Redact(Msg)
    catch
        Class:Reason:Stacktrace ->
            {"Log message dropped: failed to remove private keys from it~n"
             "  Error: ~p:~p~n"
             "  Stacktrace: ~p~n"
             "  Message: ~p~n"
             "  Logged from: ~p~n",
             [Class, reason_tag(Reason), strip_stacktrace(Stacktrace),
              msg_kind(Msg), maps:with([mfa, file, line, pid, domain], Meta)]}
    end.

reason_tag(Reason) when is_atom(Reason) ->
    Reason;
reason_tag(Reason) when is_tuple(Reason), tuple_size(Reason) > 0,
                        is_atom(element(1, Reason)) ->
    {element(1, Reason), '...'};
reason_tag(_) ->
    '...'.

%% Frames can have the arguments (which can be the message) instead of the
%% arity: replace them with their number.
strip_stacktrace(Stacktrace) ->
    strip_frames(Stacktrace, []).

%% Don't count on the stacktrace type.
-dialyzer({no_match, [strip_frames/2, strip_frame/1, arity/1]}).

strip_frames([Frame | Rest], Acc) ->
    strip_frames(Rest, [strip_frame(Frame) | Acc]);
strip_frames([], Acc) ->
    lists:reverse(Acc);
strip_frames(_, Acc) ->
    lists:reverse(Acc, '...').

strip_frame({M, F, ArityOrArgs, Location}) when is_atom(M), is_atom(F) ->
    {M, F, arity(ArityOrArgs), Location};
strip_frame({Fun, ArityOrArgs, Location}) when is_function(Fun) ->
    {Fun, arity(ArityOrArgs), Location};
strip_frame(_) ->
    '...'.

arity(Arity) when is_integer(Arity) -> Arity;
arity(List) when is_list(List) -> length(List);
arity(_) -> '...'.

%% Format strings and atom report labels are code, not data, so they can be
%% shown.
msg_kind({report, #{label := Label}}) ->
    case is_atom(Label) orelse
        (is_tuple(Label) andalso
         lists:all(fun erlang:is_atom/1, tuple_to_list(Label))) of
        true -> {report, Label};
        false -> report
    end;
msg_kind({report, _}) ->
    report;
msg_kind({string, _}) ->
    string;
msg_kind({Format, _Args}) when is_list(Format) ->
    case io_lib:printable_unicode_list(Format) of
        true -> {format, Format};
        false -> format
    end;
msg_kind(_) ->
    unknown.

%% Returns Term with every private key in it replaced. Can fail.
-spec remove_private_keys(term()) -> term().
remove_private_keys(Term) ->
    case redact(Term) of
        unchanged ->
            Term;
        {changed, NewTerm} ->
            NewTerm
    end.

%% Returns unchanged or {changed, NewTerm}.
redact(T) when is_tuple(T) ->
    case is_private_key(T) of
        true ->
            {changed, {element(1, T), ?REDACTED}};
        false ->
            redact_tuple(T, tuple_size(T), unchanged)
    end;
redact([_ | _] = L) ->
    case pem_private_key(L) of
        false ->
            redact_list(L, L, 0, unchanged);
        Type ->
            {changed, ?REDACTED_PEM(Type)}
    end;
redact(B) when is_binary(B) ->
    case pem_private_key(B) of
        false ->
            unchanged;
        Type ->
            {changed, list_to_binary(?REDACTED_PEM(Type))}
    end;
redact(M) when is_map(M) ->
    redact_map(maps:next(maps:iterator(M)), M, unchanged);
redact(_) ->
    unchanged.

%% New is unchanged until an element changes, then it's the new tuple.
redact_tuple(_T, 0, unchanged) ->
    unchanged;
redact_tuple(_T, 0, New) ->
    {changed, New};
redact_tuple(T, I, New) ->
    case redact(element(I, T)) of
        unchanged ->
            redact_tuple(T, I - 1, New);
        {changed, E} ->
            Base = case New of
                       unchanged -> T;
                       _ -> New
                   end,
            redact_tuple(T, I - 1, setelement(I, Base, E))
    end.

%% Tail recursive. Run is the part of the list after the last change, RunLen
%% is how many of its elements were walked. Acc is unchanged until the first
%% change, then the new list up to Run, reversed. Run is reused at the end.
redact_list([H | T], Run, RunLen, Acc) ->
    case redact(H) of
        unchanged ->
            redact_list(T, Run, RunLen + 1, Acc);
        {changed, NewH} ->
            redact_list(T, T, 0, [NewH | copy_run(Run, RunLen, Acc)])
    end;
redact_list([], _Run, _RunLen, unchanged) ->
    unchanged;
redact_list([], Run, _RunLen, Acc) ->
    {changed, lists:reverse(Acc, Run)};
redact_list(ImproperTail, Run, RunLen, Acc) ->
    case {redact(ImproperTail), Acc} of
        {unchanged, unchanged} ->
            unchanged;
        {unchanged, _} ->
            {changed, lists:reverse(Acc, Run)};
        {{changed, NewTail}, _} ->
            {changed, lists:reverse(copy_run(Run, RunLen, Acc), NewTail)}
    end.

%% Adds the first N elements of Run to Acc, reversed.
copy_run(Run, N, unchanged) ->
    copy_run(Run, N, []);
copy_run(_Run, 0, Acc) ->
    Acc;
copy_run([H | T], N, Acc) ->
    copy_run(T, N - 1, [H | Acc]).

redact_map(none, _M, unchanged) ->
    unchanged;
redact_map(none, _M, New) ->
    {changed, New};
redact_map({K, V, Iter}, M, New) ->
    case {redact(K), redact(V)} of
        {unchanged, unchanged} ->
            redact_map(maps:next(Iter), M, New);
        {RK, RV} ->
            Base = case New of
                       unchanged -> M;
                       _ -> New
                   end,
            NewV = case RV of
                       unchanged -> V;
                       {changed, NV} -> NV
                   end,
            New1 = case RK of
                       unchanged ->
                           Base#{K := NewV};
                       {changed, NK} ->
                           (maps:remove(K, Base))#{NK => NewV}
                   end,
            redact_map(maps:next(Iter), M, New1)
    end.

%% Returns the type of the PEM private key the binary or string starts with,
%% or false.
pem_private_key(<<"-----BEGIN PRIVATE KEY-----", _/binary>>) ->
    "PKCS8";
pem_private_key(<<"-----BEGIN ENCRYPTED PRIVATE KEY-----", _/binary>>) ->
    "ENCRYPTED PKCS8";
pem_private_key(<<"-----BEGIN RSA PRIVATE KEY-----", _/binary>>) -> "RSA";
pem_private_key(<<"-----BEGIN EC PRIVATE KEY-----", _/binary>>) -> "EC";
pem_private_key(<<"-----BEGIN DSA PRIVATE KEY-----", _/binary>>) -> "DSA";
pem_private_key(<<"-----BEGIN OPENSSH PRIVATE KEY-----", _/binary>>) ->
    "OPENSSH";
pem_private_key("-----BEGIN PRIVATE KEY-----" ++ _) -> "PKCS8";
pem_private_key("-----BEGIN ENCRYPTED PRIVATE KEY-----" ++ _) ->
    "ENCRYPTED PKCS8";
pem_private_key("-----BEGIN RSA PRIVATE KEY-----" ++ _) -> "RSA";
pem_private_key("-----BEGIN EC PRIVATE KEY-----" ++ _) -> "EC";
pem_private_key("-----BEGIN DSA PRIVATE KEY-----" ++ _) -> "DSA";
pem_private_key("-----BEGIN OPENSSH PRIVATE KEY-----" ++ _) -> "OPENSSH";
pem_private_key(_) -> false.

%% public_key private key records (EdDSA keys are #'ECPrivateKey'{}) and
%% ssl's {Tag, Der} form.
is_private_key(T) when tuple_size(T) >= 2 ->
    case element(1, T) of
        'RSAPrivateKey' -> true;
        'DSAPrivateKey' -> true;
        'ECPrivateKey' -> true;
        'ML-DSAPrivateKey' -> true;
        'SLH-DSAPrivateKey' -> true;
        'PrivateKeyInfo' -> true;
        'OneAsymmetricKey' -> true;
        _ -> false
    end;
is_private_key(_) ->
    false.

-ifdef(TEST).
rsa_key() ->
    public_key:generate_key({rsa, 1024, 65537}).

%% The shape of the reason in MB-62357: the connection state, with the key in
%% connection_env's cert_key_alts, inside a badmatch.
mb62357_reason(Key) ->
    CertKeyAlts = #{rsa => [#{certs => [<<"cert">>], private_key => Key}],
                    ecdsa => [], eddsa => [], dsa => []},
    State = {state, {static_env, server}, {connection_env, CertKeyAlts},
             #{certs_keys => [#{key => {'PrivateKeyInfo', <<"der">>}}]}},
    {badmatch, {stop, {shutdown, dist_closed}, State}}.

mb62357_reason_test() ->
    R = remove_private_keys(mb62357_reason(rsa_key())),
    ?assertEqual(
       {badmatch,
        {stop, {shutdown, dist_closed},
         {state, {static_env, server},
          {connection_env,
           #{rsa => [#{certs => [<<"cert">>],
                       private_key => {'RSAPrivateKey', ?REDACTED}}],
             ecdsa => [], eddsa => [], dsa => []}},
          #{certs_keys => [#{key => {'PrivateKeyInfo', ?REDACTED}}]}}}},
       R).

other_key_types_test() ->
    EC = public_key:generate_key({namedCurve, secp256r1}),
    Ed = public_key:generate_key({namedCurve, ed25519}),
    ECDer = public_key:der_encode('ECPrivateKey', EC),
    ?assertEqual([{ec, {'ECPrivateKey', ?REDACTED}},
                  {ed, {'ECPrivateKey', ?REDACTED}},
                  {der, {'ECPrivateKey', ?REDACTED}}],
                 remove_private_keys([{ec, EC}, {ed, Ed},
                                      {der, {'ECPrivateKey', ECDer}}])).

nested_structures_test() ->
    Key = rsa_key(),
    R = {'RSAPrivateKey', ?REDACTED},
    %% improper list, map key, deep tuple
    ?assertEqual([a, {b, [R]} | {c, #{R => v}}],
                 remove_private_keys([a, {b, [Key]} | {c, #{Key => v}}])).

no_key_test() ->
    Terms = [{report, #{label => {supervisor, progress},
                        report => [{started, [{pid, self()}]}]}},
             {"~p ~p", [1, {'RSAPrivateKey'}]},
             {string, "just a string"},
             [a | b],
             #{a => [{b, <<"c">>}]},
             <<"binary">>,
             <<"-----BEGIN CERTIFICATE-----\nMIIB\n">>,
             "-----BEGIN CERTIFICATE-----\nMIIB\n",
             %% only the start of a binary or a string is checked
             <<"key: -----BEGIN PRIVATE KEY-----\nMIIB\n">>,
             "key: -----BEGIN PRIVATE KEY-----\nMIIB\n"],
    [?assert(Term =:= remove_private_keys(Term)) || Term <- Terms].

%% A key at the end of a long list is found.
long_list_test() ->
    Key = rsa_key(),
    L = lists:duplicate(1000000, {a, [b]}) ++ [Key],
    ?assertEqual({'RSAPrivateKey', ?REDACTED},
                 lists:last(remove_private_keys(L))).

%% The stack doesn't grow with the number of keys in a list.
many_keys_test() ->
    Key = {'PrivateKeyInfo', <<"der">>},
    R = {'PrivateKeyInfo', ?REDACTED},
    N = 100000,
    L = [a | lists:duplicate(N, Key)] ++ [b, Key | c],
    Self = self(),
    Pid = spawn(fun () ->
                        receive go -> ok end,
                        Self ! {result, self(), remove_private_keys(L)}
                end),
    1 = erlang:trace(Pid, true, [garbage_collection]),
    Pid ! go,
    Res = receive {result, Pid, Res0} -> Res0 end,
    ?assertEqual([a | lists:duplicate(N, R)] ++ [b, R | c], Res),
    Ref = erlang:trace_delivered(Pid),
    receive {trace_delivered, Pid, Ref} -> ok end,
    Stacks = collect_gc_stacks(Pid),
    ?assert(Stacks =/= []),
    ?assert(lists:max(Stacks) < 1000).

collect_gc_stacks(Pid) ->
    receive
        {trace, Pid, _, Info} ->
            [proplists:get_value(stack_size, Info, 0) |
             collect_gc_stacks(Pid)]
    after 0 ->
            []
    end.

%% Only the containers on the way to a key are copied, the rest of the result
%% is the original term.
sharing_test() ->
    Key = rsa_key(),
    R = {'RSAPrivateKey', ?REDACTED},
    Same = fun erts_debug:same/2,
    Clean = {[1, 2], #{a => "b"}, <<"bin">>},
    ?assert(Same(Clean, remove_private_keys(Clean))),
    Tail = [x, {y}, "z"],
    Map = #{a => {b}, key => Key, c => [d]},
    T = {Clean, [p, Key, q, Key | Tail], Map, [Key | improper], {Key, Clean}},
    Out = remove_private_keys(T),
    {Clean1, [p, R, q, R | Tail1], Map1, [R | improper], {R, Clean2}} = Out,
    ?assert(Same(Clean, Clean1)),
    ?assert(Same(Clean, Clean2)),
    ?assert(Same(Tail, Tail1)),
    ?assertEqual(Map#{key := R}, Map1),
    ?assert(Same(maps:get(a, Map), maps:get(a, Map1))),
    ?assert(Same(maps:get(c, Map), maps:get(c, Map1))).

pem_test() ->
    Key = rsa_key(),
    RSA = public_key:pem_encode(
            [public_key:pem_entry_encode('RSAPrivateKey', Key)]),
    PKCS8 = public_key:pem_encode(
              [{'PrivateKeyInfo', public_key:der_encode('PrivateKeyInfo', Key),
                not_encrypted}]),
    ?assertEqual({report, #{rsa => <<"*** RSA PEM REDACTED ***">>,
                            pkcs8 => <<"*** PKCS8 PEM REDACTED ***">>,
                            list => ["*** RSA PEM REDACTED ***"],
                            improper => [a | <<"*** RSA PEM REDACTED ***">>]}},
                 remove_private_keys({report, #{rsa => RSA, pkcs8 => PKCS8,
                                                list => [binary_to_list(RSA)],
                                                improper => [a | RSA]}})),
    Headers = [{"PRIVATE KEY", "PKCS8"},
               {"ENCRYPTED PRIVATE KEY", "ENCRYPTED PKCS8"},
               {"RSA PRIVATE KEY", "RSA"},
               {"EC PRIVATE KEY", "EC"},
               {"DSA PRIVATE KEY", "DSA"},
               {"OPENSSH PRIVATE KEY", "OPENSSH"}],
    [begin
         Pem = "-----BEGIN " ++ Label ++ "-----\nc2VjcmV0\n",
         Redacted = "*** " ++ Type ++ " PEM REDACTED ***",
         ?assertEqual(list_to_binary(Redacted),
                      remove_private_keys(list_to_binary(Pem))),
         ?assertEqual(Redacted, remove_private_keys(Pem))
     end || {Label, Type} <- Headers].

format({Format, Args}) ->
    lists:flatten(io_lib:format(Format, Args)).

%% ~p breaks long terms over lines, so whitespace is ignored.
contains(Text, Part) ->
    NoSpace = fun (S) -> re:replace(S, "\\s+", "", [global, {return, list}])
              end,
    string:find(NoSpace(Text), NoSpace(Part)) =/= nomatch.

redact_test_fail(never_matches) ->
    ok.

%% A failure is reported without any part of the message.
redact_failure_test() ->
    Key = rsa_key(),
    #'RSAPrivateKey'{privateExponent = D} = Key,
    Secret = integer_to_list(D),
    Msg = {report, #{label => {gen_statem, terminate},
                     reason => {state, Key}}},
    Meta = #{mfa => {some_module, some_fun, 3}, file => "some_module.erl",
             line => 42, pid => self(), domain => [otp],
             time => logger:timestamp()},
    Failures =
        [%% the message is in the arguments of the top frame
         fun (M) -> redact_test_fail(M) end,
         %% ... in the reason
         fun (M) -> erlang:error({badmatch, M}) end,
         %% not an error
         fun (M) -> throw(M) end],
    lists:foreach(
      fun (Fail) ->
              Text = format(redact_report(Msg, Meta, Fail)),
              ?assertNot(contains(Text, Secret)),
              ?assert(contains(Text, "Log message dropped")),
              ?assert(contains(Text, "{report,{gen_statem,terminate}}")),
              ?assert(contains(Text, "{some_module,some_fun,3}")),
              ?assert(contains(Text, "some_module.erl")),
              ?assert(contains(Text, "ale_redact.erl"))
      end, Failures),
    Text = format(redact_report(Msg, Meta, hd(Failures))),
    ?assert(contains(Text, "error:function_clause")),
    ?assert(contains(Text, "{ale_redact,redact_test_fail,1,")).

strip_stacktrace_test() ->
    Fun = fun lists:sum/1,
    Location = [{file, "m.erl"}, {line, 1}],
    ?assertEqual(
       [{m, f, 2, Location},
        {m, f, 3, Location},
        {Fun, 1, Location},
        '...',
        {m, f, '...', Location}],
       strip_stacktrace(
         [{m, f, [secret, secret], Location},
          {m, f, 3, Location},
          {Fun, [secret], Location},
          {not_a_frame, secret},
          {m, f, secret, Location}])),
    ?assertEqual([{m, f, 0, []} | '...'],
                 strip_stacktrace([{m, f, 0, []} | secret])),
    ?assertEqual('...', strip_stacktrace(secret)).

msg_kind_test() ->
    ?assertEqual({report, {supervisor, progress}},
                 msg_kind({report, #{label => {supervisor, progress}}})),
    ?assertEqual(report, msg_kind({report, #{label => {x, rsa_key()}}})),
    ?assertEqual(report, msg_kind({report, [{a, b}]})),
    ?assertEqual({format, "~p: ~p"}, msg_kind({"~p: ~p", [a, b]})),
    ?assertEqual(format, msg_kind({[secret], []})),
    ?assertEqual(string, msg_kind({string, "text"})),
    ?assertEqual(unknown, msg_kind(secret)).

-endif.
