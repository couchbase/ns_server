%% @author Couchbase <info@couchbase.com>
%% @copyright 2011-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(ale_error_logger_handler).

-export([log/4]).

-ifdef(TEST).
-export([log/2]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-endif.

-define(DEPTH_LIMIT, 50).

get_log(_Level, {string, Msg}, _Meta) ->
    {"~ts", [Msg]};
get_log(Level, {report, Msg}, Meta) ->
    handle_report(Level, Msg, Meta);
get_log(_Level, {Format, Args}, _Meta) when is_list(Format), is_list(Args) ->
    {Format, Args}.

get_title(Level) ->
    string:uppercase(atom_to_list(Level)) ++ " REPORT".

format_header(Title) ->
    {"~n=========================~s=========================~n", [Title]}.

get_header(_Level, #{logger_formatter := #{title := Title}}) ->
    format_header(Title);
get_header(Level, _) ->
    format_header(get_title(Level)).

handle_report(Level, Report, Meta) ->
    {HF, HA} = get_header(Level, Meta),
    {RF, RA} = handle_report_inner(Report, Meta),
    {HF ++ RF, HA ++ RA}.

handle_report_inner(Report, Meta) ->
    case maps:get(report_cb, Meta, fun logger:format_otp_report/1) of
        RCBFun when is_function(RCBFun, 1) ->
            try RCBFun(Report) of
                {F, A} when is_list(F), is_list(A) ->
                    {F, A};
                Other ->
                    {"REPORT_CB ERROR: ~tp; Returned: ~tp", [Report, Other]}
            catch C:R ->
                      {"REPORT_CB CRASH: ~tp; Reason: ~tp", [Report, {C, R}]}
            end;
        RCBFun when is_function(RCBFun, 2) ->
            try RCBFun(Report, #{depth => ?DEPTH_LIMIT,
                                 chars_limit => unlimited,
                                 single_line => false}) of
                Chardata when (is_list(Chardata) orelse is_binary(Chardata)) ->
                    {"~ts", [Chardata]};
                Other ->
                    {"REPORT_CB ERROR: ~tp; Returned: ~tp", [Report, Other]}
            catch C:R ->
                      {"REPORT_CB CRASH: ~tp; Reason: ~tp", [Report, {C, R}]}
            end
    end.

log(Logger, Level, Msg, Meta) ->
    {Format, Args} = get_log(Level, ale_redact:redact_report(Msg, Meta), Meta),
    do_log(Logger, get_ale_level(Level), Format, Args).

get_ale_level(LoggerLevel) ->
    case LoggerLevel of
        emergency -> critical;
        alert -> critical;
        critical -> critical;
        error -> error;
        warning -> warn;
        notice -> info;
        info -> info;
        debug -> debug;
        _ -> info
    end.

do_log(Logger, LogLevel, Fmt, Args) ->
    Huge = [erts_debug:flat_size(A) > 1024 * 1024 || A <- Args],

    case lists:member(true, Huge) of
        true ->
            StrippedArgs = [case H of
                                true ->
                                    <<"too huge">>;
                                false ->
                                    A
                            end || {A, H} <- lists:zip(Args, Huge)],

            ale:log(Logger, warn,
                    "Preventing an attempt to log something quite huge~n"
                    "  Format string: ~s~n"
                    "  Log level: ~p~n"
                    "  Arguments: ~p~n",
                    [Fmt, LogLevel, StrippedArgs]);
        false ->
            ale:log(Logger, LogLevel, Fmt, Args)
    end.

-ifdef(TEST).
%% Test logger handler: sends the events to the test process.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.

%% The text we log for Event, with or without redacting it.
format(#{level := Level, msg := Msg, meta := Meta}, Redact) ->
    Msg1 = case Redact of
               true -> ale_redact:redact_report(Msg, Meta);
               false -> Msg
           end,
    {Format, Args} = get_log(Level, Msg1, Meta),
    lists:flatten(io_lib:format(Format, Args)).

%% ~p breaks long terms over lines, so whitespace is ignored.
contains(Text, Part) ->
    NoSpace = fun (S) -> re:replace(S, "\\s+", "", [global, {return, list}])
              end,
    string:find(NoSpace(Text), NoSpace(Part)) =/= nomatch.

%% A TLS connection process crashes with its state in the reason, as in
%% MB-62357: the reports have the key, what we log doesn't.
redact_ssl_connection_crash_test_() ->
    {timeout, 60, fun redact_ssl_connection_crash/0}.

redact_ssl_connection_crash() ->
    {ok, _} = application:ensure_all_started(ssl),
    #{cert := Cert, key := Key} =
        public_key:pkix_test_root_cert("ale_error_logger_handler_test",
                                       [{key, {rsa, 1024, 65537}}]),
    #'RSAPrivateKey'{privateExponent = D} = Key,
    Secret = integer_to_list(D),
    {ok, LSock} =
        ssl:listen(0, [{cert, Cert},
                       {key, {'RSAPrivateKey',
                              public_key:der_encode('RSAPrivateKey', Key)}},
                       {active, false}]),
    {ok, {_, Port}} = ssl:sockname(LSock),
    Self = self(),
    Acceptor = spawn_link(fun () ->
                                  {ok, T} = ssl:transport_accept(LSock),
                                  {ok, _} = ssl:handshake(T),
                                  Self ! accepted,
                                  receive stop -> ok end
                          end),
    {ok, Client} = ssl:connect("localhost", Port, [{verify, verify_none},
                                                   {active, false}]),
    receive accepted -> ok end,
    [Server] = server_connections(Port),
    ok = logger:add_handler(?MODULE, ?MODULE, #{config => #{pid => self()},
                                                level => all}),
    try
        %% The real crash needs a dist connection and the right timing, so
        %% terminate the process with the same reason instead.
        {_, State} = sys:get_state(Server),
        catch sys:terminate(Server,
                            {badmatch, {stop, {shutdown, dist_closed}, State}},
                            5000),
        Events = collect_events(),
        %% the gen_statem, proc_lib and supervisor reports
        ?assert(length(Events) >= 3),
        Leaky = [E || E <- Events, contains(format(E, false), Secret)],
        ?assert(length(Leaky) >= 3),
        lists:foreach(
          fun (E) ->
                  Text = format(E, true),
                  ?assertNot(contains(Text, Secret)),
                  %% redacting didn't fail
                  ?assertNot(contains(Text, "Log message dropped")),
                  ?assertEqual(lists:member(E, Leaky),
                               contains(Text, "*** redacted ***"))
          end, Events)
    after
        logger:remove_handler(?MODULE),
        ssl:close(Client),
        ssl:close(LSock),
        unlink(Acceptor),
        exit(Acceptor, kill)
    end.

%% Server side connection processes of the listener on Port. ssl labels them
%% {tls, server, Port}, or {tls, server, SNIHostname, Port}.
server_connections(Port) ->
    [P || {_, Sup, _, _} <- supervisor:which_children(tls_connection_sup),
          {receiver, P, _, _} <- supervisor:which_children(Sup),
          {dictionary, D} <- [process_info(P, dictionary)],
          Label <- [proplists:get_value('$process_label', D)],
          is_tuple(Label),
          element(2, Label) =:= server,
          element(tuple_size(Label), Label) =:= Port].

collect_events() ->
    receive
        {logged, Event} ->
            [Event | collect_events()]
    after 1000 ->
            []
    end.
-endif.
