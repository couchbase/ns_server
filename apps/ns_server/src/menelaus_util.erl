%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Web server for menelaus.

-module(menelaus_util).
-author('Northscale <info@northscale.com>').

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").
-include("menelaus_web.hrl").
-include("pipes.hrl").
-include("rbac.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([redirect_permanently/2,
         reply/2,
         reply/3,
         reply/4,
         reply_ok/3,
         reply_ok/4,
         reply_text/3,
         reply_text/4,
         reply_json/2,
         reply_json/3,
         reply_json/4,
         parse_json/1,
         reply_not_found/1,
         reply_text_404/0,
         reply_password_expired/1,
         handle_request/2,
         hibernate/4,
         serve_file/3,
         serve_file/4,
         serve_static_file/4,
         parse_boolean/1,
         get_option/2,
         local_addr/1,
         concat_url_path/1,
         concat_url_path/2,
         bin_concat_path/1,
         bin_concat_path/2,
         parse_validate_boolean/1,
         parse_validate_boolean_field/3,
         parse_validate_number/3,
         parse_validate_number/4,
         parse_validate_port_number/1,
         validate_email_address/1,
         encode_json/1,
         is_valid_positive_integer/1,
         is_valid_positive_integer_in_range/3,
         format_server_time/1,
         format_server_time/2,
         ensure_local/1,
         ensure_local/2,
         reply_global_error/2,
         reply_error/3,
         require_auth/1,
         send_chunked/3,
         handle_streaming/2,
         handle_streaming/3,
         assert_is_enterprise/0,
         assert_is_enterprise/1,
         assert_is_dev_preview/0,
         assert_profile_flag/2,
         assert_is_76/0,
         assert_is_morpheus/0,
         assert_config_profile_flag/1,
         assert_not_config_profile_flag/1,
         choose_node_consistently/2,
         compute_sec_headers/0,
         web_exception/2,
         web_json_exception/2,
         global_error_exception/2,
         require_permission/2,
         server_error_report/4,
         proxy_req/6,
         respond/2,
         survive_web_server_restart/1]).

%% Internal exports.
-export([wake_up/4]).

%% used by parse_validate_number
-export([list_to_integer/1, list_to_float/1]).

%% for hibernate
-export([handle_streaming_wakeup/7]).

%% External API

-define(CACHE_CONTROL, "Cache-Control").  %% TODO: Move to an HTTP header file.
-define(BASE_HEADERS, [{"Server", "Couchbase Server"}]).
-define(SEC_HEADERS,  [{"X-Content-Type-Options", "nosniff"},
                       {"X-Frame-Options", "DENY"},
                       {"X-Permitted-Cross-Domain-Policies", "none"},
                       {"X-XSS-Protection", "1; mode=block"}]).
-define(NO_CACHE_HEADERS,
        [{?CACHE_CONTROL, "no-cache,no-store,must-revalidate"},
         {"Expires", "Thu, 01 Jan 1970 00:00:00 GMT"},
         {"Pragma", "no-cache"}]).
-define(PART_SIZE, 100000).
-define(WINDOW_SIZE, 5).

%% when proxing http request we should not proxy these headers because they
%% will be set by us if needed
-define(PROXY_DROP_RESP_HEADERS, ["content-length",
                                  "transfer-encoding",
                                  "www-authenticate"]).
compute_sec_headers() ->
    compute_sec_headers(ns_config:read_key_fast(secure_headers, [])).

compute_sec_headers(Headers) ->
    case proplists:get_value(enabled, Headers, true) of
        false ->
            [];
        true ->
            H1 = misc:update_proplist(?SEC_HEADERS, Headers),
            [{K, V} || {K, V} <- H1, V =/= disable, K =/= enabled]
    end.

response_headers(Req, Headers) ->
    response_headers(
      menelaus_auth:get_resp_headers(Req) ++ Headers).

%% response_header takes a proplist of headers or pseudo-header
%% descripts and augments it with response specific headers.
%% Since any given header can only be specified once, headers at the front
%% of the proplist have priority over the same header later in the
%% proplist.
%% The following pseudo-headers are supported:
%%   {allow_cache, true}  -- Enables long duration caching
%%   {allow_cache, false} -- Disables cache via multiple headers
%% If neither allow_cache or the "Cache-Control" header are specified
%% {allow_cache, false} is applied.
-spec response_headers([{string(),string()}|{atom(), atom()}]) ->
                              [{string(), string()}].
response_headers(Headers) ->
    {Expanded, _} =
        lists:foldl(
          fun({allow_cache, _}, {Acc, _CacheControl = true}) ->
                  {Acc, true};
             ({allow_cache, _Value = true}, {Acc, _}) ->
                  {[{?CACHE_CONTROL, "max-age=30000000"} | Acc], true};
             ({allow_cache, _Value = false}, {Acc, _}) ->
                  {?NO_CACHE_HEADERS ++ Acc, true};
             ({Header = ?CACHE_CONTROL, Value}, {Acc, _}) ->
                  {[{Header, Value} | Acc], true};
             ({Header, Value}, {Acc, CacheControl}) when is_list(Header) ->
                  {[{Header, Value} | Acc], CacheControl}
          end, {[], false},
          Headers ++ [{allow_cache, false} | ?BASE_HEADERS] ++
              compute_sec_headers()),
    lists:ukeysort(1, lists:reverse(Expanded)).

%% mostly extracted from mochiweb_request:maybe_redirect/3
redirect_permanently(Path, Req) ->
    Scheme = case mochiweb_request:get(socket, Req) of
                 {ssl, _} ->
                     "https://";
                 _ ->
                     "http://"
             end,
    Location =
        case mochiweb_request:get_header_value("host", Req) of
            undefined -> Path;
            X -> Scheme ++ X ++ Path
        end,

    %% fallback default set to true from morpheus -> onward.
    case ns_config:read_key_fast(use_relative_web_redirects,
                                 cluster_compat_mode:is_cluster_morpheus()) of
        true ->
            reply_redirect(Path, Req); %% uses relative redirect
        false ->
            reply_redirect(Location, Req) %% standard absolute redirect
    end.

%% NOTE: must use root-relative paths (starting with "/") or absolute URLS.
reply_redirect(Path, Req) ->
    LocationBin = list_to_binary(Path),
    Top = <<"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
            "<html><head>"
            "<title>301 Moved Permanently</title>"
            "</head><body>"
            "<h1>Moved Permanently</h1>"
            "<p>The document has moved <a href=\"">>,
    Bottom = <<"\">here</a>.</p></body></html>\n">>,
    Body = <<Top/binary, LocationBin/binary, Bottom/binary>>,
    reply(Req, Body, 301, [{"Location", Path},
                           {"Content-Type", "text/html"}]).

reply_not_found(Req) ->
    reply_not_found(Req, []).

reply_not_found(Req, ExtraHeaders) ->
    reply_text(Req, reply_text_404(), 404, ExtraHeaders).

%% do not change the text, because unfortunately some clients parse it
%% to distihgush between different kinds of 404's
reply_text_404() ->
    "Requested resource not found.\r\n".

reply_text(Req, Message, Code) ->
    reply_text(Req, Message, Code, []).

reply_text(Req, Message, Code, ExtraHeaders) ->
    reply(Req, Message, Code, [{"Content-Type", "text/plain"} | ExtraHeaders]).

reply_json(Req, Body) ->
    reply_ok(Req, "application/json", encode_json(Body)).

reply_json(Req, Body, Code) ->
    reply(Req, encode_json(Body), Code, [{"Content-Type", "application/json"}]).

reply_json(Req, Body, Code, ExtraHeaders) ->
    reply(Req, encode_json(Body), Code,
          [{"Content-Type", "application/json"} | ExtraHeaders]).

server_error_report(Req, Type, What, Stack) ->
    Report = ["web request failed",
              {path, mochiweb_request:get(path, Req)},
              {method, mochiweb_request:get(method, Req)},
              {type, Type}, {what, What},
              {trace, Stack}],
    {<<"Unexpected server error, request logged.">>, Report}.

reply_server_error_before_close(Req, Type, What, Stack) ->
    {Msg, Report} = server_error_report(Req, Type, What, Stack),
    ?log_error("Server error during processing: ~p", [Report]),
    reply_json(Req, [Msg], 500, [{"Connection", "close"}]).

-spec reply_password_expired(mochiweb_request()) -> mochiweb_response().
reply_password_expired(Req) ->
    Msg = {[{message, <<"Password expired">>},
            {passwordExpired, true}]},
    menelaus_util:reply_json(Req, Msg, 403).

hibernate(Req, M, F, A) when is_atom(M), is_atom(F), is_list(A) ->
    erlang:hibernate(?MODULE, wake_up, [Req, M, F, A]).

wake_up(Req, M, F, A) ->
    handle_request(Req, fun() -> erlang:apply(M, F, A) end).

handle_request(Req, Fun) ->
    try
        Fun()
    catch
        exit:normal ->
            erlang:exit(normal);
        exit:{timeout,_}:Stack ->
            {_Msg, Report} = server_error_report(Req, exit, timeout, Stack),
            ?log_error("Server error during processing: ~p", [Report]),
            reply_text(Req, "Service is temporarily unavailable", 503),
            erlang:exit(normal);
        throw:{web_json_exception, StatusCode, Json} ->
            reply_json(Req, Json, StatusCode);
        throw:{web_exception, StatusCode, Message, ExtraHeaders} ->
            reply_text(Req, Message, StatusCode, ExtraHeaders);
        Type:What:Stack ->
            reply_server_error_before_close(Req, Type, What, Stack),
            %% An unexpected error has occurred. Exit so as to not leave any
            %% residual state (e.g. late messages) around.
            erlang:exit(normal)
    end.

log_web_hit(Peer, Req, Resp) ->
    catch count_web_hit(Req, Resp),
    Level = case menelaus_auth:get_user_id(Req) of
                [$@ | _] ->
                    debug;
                _ ->
                    case mochiweb_request:get(path, Req) of
                        "/_goxdcr/" ++ _ -> debug;
                        _ -> info
                    end
            end,
    try
        ale:xlog(?ACCESS_LOGGER, Level, {Peer, Req, Resp}, "", [])
    catch
        error:undef ->
            ok
    end.

count_web_hit(Req, Resp) ->
    User = case menelaus_auth:get_user_id(Req) of
               "@" ++ _ = N -> N;
               "" -> "-";
               _ -> "other" %% We should not disclose real usernames in stats
           end,
    Scheme = mochiweb_request:get(scheme, Req),
    Method = mochiweb_request:get(method, Req),
    Code = mochiweb_response:get(code, Resp),
    Path = case Method of
               "RPCCONNECT" -> "/*";
               _ ->
                   case string:lexemes(mochiweb_request:get(path, Req), "/") of
                       _ when Code >= 400, Code < 500 -> "/*";
                       [] ->
                           "/";
                       ["pools"] ->
                           "/pools";
                       ["pools", "default", P | _] ->
                           "/pools/default/" ++ P ++ "/*";
                       [P | _] ->
                           "/" ++ P ++ "/*"
                   end
           end,
    ResponseTime = menelaus_web:response_time_ms(Req),
    ns_server_stats:notify_counter(
      {<<"http_requests">>, [{scheme, Scheme}, {method, Method}, {path, Path},
                             {user, User}, {code, Code}]}),
    ns_server_stats:notify_histogram(<<"http_requests">>, ResponseTime).

reply_ok(Req, ContentType, Body) ->
    reply_ok(Req, ContentType, Body, []).

reply_ok(Req, ContentType, Body, ExtraHeaders) ->
    Peer = mochiweb_request:get(peer, Req),
    Resp = mochiweb_request:ok(
             {ContentType, response_headers(Req, ExtraHeaders), Body}, Req),
    log_web_hit(Peer, Req, Resp),
    Resp.

reply(Req, Code) ->
    reply(Req, [], Code, []).

reply(Req, Code, ExtraHeaders) ->
    reply(Req, [], Code, ExtraHeaders).

reply(Req, Body, Code, ExtraHeaders) ->
    respond(Req, {Code, response_headers(Req, ExtraHeaders), Body}).

respond(Req, RespTuple) ->
    Peer = mochiweb_request:get(peer, Req),
    Resp = mochiweb_request:respond(RespTuple, Req),
    log_web_hit(Peer, Req, Resp),
    Resp.

-include_lib("kernel/include/file.hrl").

%% Originally from mochiweb_request.erl maybe_serve_file/2
%% and modified to handle user-defined content-type
serve_static_file(Req, {DocRoot, Path}, ContentType, ExtraHeaders) ->
    serve_static_file(Req, filename:join(DocRoot, Path),
                      ContentType, ExtraHeaders);
serve_static_file(Req, File, ContentType, ExtraHeaders) ->
    case file:read_file_info(File) of
        {ok, FileInfo} ->
            LastModified = httpd_util:rfc1123_date(FileInfo#file_info.mtime),
            case mochiweb_request:get_header_value("if-modified-since", Req) of
                LastModified ->
                    reply(Req, 304, ExtraHeaders);
                _ ->
                    case file:open(File, [raw, binary]) of
                        {ok, IoDevice} ->
                            Res = reply_ok(Req, ContentType,
                                           {file, IoDevice},
                                           [{"last-modified", LastModified}
                                            | ExtraHeaders]),
                            file:close(IoDevice),
                            Res;
                        _ ->
                            reply_not_found(Req, ExtraHeaders)
                    end
            end;
        {error, _} ->
            reply_not_found(Req, ExtraHeaders)
    end.

serve_file(Req, File, Root) ->
    serve_file(Req, File, Root, []).

serve_file(Req, File, Root, ExtraHeaders) ->
    Peer = mochiweb_request:get(peer, Req),
    Resp = mochiweb_request:serve_file(
             File, Root,
             response_headers(Req, ExtraHeaders ++ [{allow_cache, true}]), Req),
    log_web_hit(Peer, Req, Resp),
    Resp.

get_option(Option, Options) ->
    {proplists:get_value(Option, Options),
     proplists:delete(Option, Options)}.

parse_json(Req) ->
    ejson:decode(mochiweb_request:recv_body(Req)).

parse_boolean(Value) ->
    case Value of
        true -> true;
        false -> false;
        <<"true">> -> true;
        <<"false">> -> false;
        <<"1">> -> true;
        <<"0">> -> false;
        1 -> true;
        0 -> false
    end.

url_path_iolist(Path, Props) when is_binary(Path) ->
    do_url_path_iolist(Path, Props);
url_path_iolist(Segments, Props) ->
    Path = [[$/, mochiweb_util:quote_plus(S)] || S <- Segments],
    do_url_path_iolist(Path, Props).

do_url_path_iolist(Path, Props) ->
    case Props of
        [] ->
            Path;
        _ ->
            QS = mochiweb_util:urlencode(Props),
            [Path, $?, QS]
    end.

concat_url_path(Segments) ->
    concat_url_path(Segments, []).
concat_url_path(Segments, Props) ->
    lists:flatten(url_path_iolist(Segments, Props)).

bin_concat_path(Segments) ->
    bin_concat_path(Segments, []).
bin_concat_path(Segments, Props) ->
    iolist_to_binary(url_path_iolist(Segments, Props)).

parse_validate_boolean_field(JSONName, CfgName, Params) ->
    case proplists:get_value(JSONName, Params) of
        undefined -> [];
        "true" -> [{ok, CfgName, true}];
        "false" -> [{ok, CfgName, false}];
        _ -> [{error, JSONName,
               iolist_to_binary(io_lib:format("~s is invalid", [JSONName]))}]
    end.

-spec parse_validate_boolean(string()) -> invalid | {ok, boolean()}.
parse_validate_boolean(Value) ->
    case Value of
        "true" -> {ok, true};
        "false" -> {ok, false};
        _ -> invalid
    end.

-spec parse_validate_number(string(), (integer() | undefined),
                            (integer() | undefined)) ->
                                   invalid | too_small | too_large |
                                   {ok, integer()}.
parse_validate_number(String, Min, Max) ->
    parse_validate_number(String, Min, Max, list_to_integer).

list_to_integer(A) -> erlang:list_to_integer(A).

list_to_float(A) -> try erlang:list_to_integer(A)
                    catch _:_ ->
                            erlang:list_to_float(A)
                    end.

-spec parse_validate_number(string(), (number() | undefined),
                            (number() | undefined),
                            list_to_integer | list_to_float) ->
                                   invalid | too_small | too_large |
                                   {ok, integer()}.
parse_validate_number(String, Min, Max, Fun) ->
    Parsed = (catch menelaus_util:Fun(string:strip(String))),
    if
        is_number(Parsed) ->
            if
                Min =/= undefined andalso Parsed < Min -> too_small;
                Max =/= undefined andalso Max =/= infinity andalso
                  Parsed > Max -> too_large;
                true -> {ok, Parsed}
            end;
       true -> invalid
    end.

parse_validate_port_number(StringPort) ->
    case parse_validate_number(StringPort, 1024, 65535) of
        {ok, Port} ->
            Port;
        invalid ->
            throw({error, [<<"Port must be a number.">>]});
        _ ->
            throw({error,
                   [<<"The port number must be greater than 1023 and less "
                      "than 65536.">>]})
    end.

%% does a simple email address validation
validate_email_address(Address) ->
    %%" "hm, even erlang-mode is buggy :("),
    {ok, RE} = re:compile("^[^@]+@.+$", [multiline]),
    RV = re:run(Address, RE),
    case RV of
        {match, _} -> true;
        _ -> false
    end.

%% Extract the local address of the socket used for the request
local_addr(Req) ->
    Socket = mochiweb_request:get(socket, Req),
    {ok, {Address, _Port}} = network:sockname(Socket),
    misc:maybe_add_brackets(inet:ntoa(Address)).

encode_json(JSON) ->
    try
        ejson:encode(JSON)
    catch T:E:Stack ->
            ?log_debug("errored while sending:~n~p", [JSON]),
            erlang:raise(T, E, Stack)
    end.

is_valid_positive_integer(String) ->
    Int = (catch erlang:list_to_integer(String)),
    (is_integer(Int) andalso (Int > 0)).

is_valid_positive_integer_in_range(String, Min, Max) ->
    Int = (catch erlang:list_to_integer(String)),
    (is_integer(Int) andalso (Int >= Min) andalso (Int =< Max)).

format_server_time(DateTime) ->
    format_server_time(DateTime, 0).

format_server_time({{YYYY, MM, DD}, {Hour, Min, Sec}}, MicroSecs) ->
    list_to_binary(
      io_lib:format("~4.4.0w-~2.2.0w-~2.2.0wT~2.2.0w:~2.2.0w:~2.2.0w.~3.3.0wZ",
                    [YYYY, MM, DD, Hour, Min, Sec, MicroSecs div 1000])).

web_exception(Code, Message) ->
    web_exception(Code, Message, []).

web_exception(Code, Message, ExtraHeaders) ->
    erlang:throw({web_exception, Code, Message, ExtraHeaders}).

web_json_exception(Code, Json) ->
    erlang:throw({web_json_exception, Code, Json}).

global_error_exception(Code, Msg) ->
    Json = {[{errors, {[{<<"_">>, Msg}]}}]},
    web_json_exception(Code, Json).

require_permission(Req, Permission) ->
    case menelaus_auth:has_permission(Permission, Req) of
        true ->
            ok;
        false ->
            ns_audit:access_forbidden(Req),
            ns_server_stats:notify_counter(<<"rest_request_access_forbidden">>),
            web_json_exception(
              403, menelaus_web_rbac:forbidden_response([Permission]))
    end.

ensure_local(Req) ->
    ensure_local(Req, undefined).

ensure_local(Req, ExtraMsg) ->
    Socket = mochiweb_request:get(socket, Req),
    Address = case mochiweb_socket:peername(Socket) of
                  {ok, {Addr, _Port}} ->
                      inet_parse:ntoa(Addr);
                  {error, enotconn} ->
                      web_exception(500, "Cannot determine peer")
              end,
    case misc:is_localhost(Address) of
        true ->
            ok;
        false ->
            BasicMsg = "API is accessible from localhost only",
            Msg = case ExtraMsg of
                      undefined -> BasicMsg;
                      _ -> io_lib:format("~s (~s)", [BasicMsg, ExtraMsg])
                  end,
            web_exception(400, lists:flatten(Msg))
    end.

reply_global_error(Req, Error) ->
    reply_error(Req, "_", Error).

reply_error(Req, Field, Error) ->
    reply_json(
      Req, {[{errors, {[{iolist_to_binary([Field]),
                         iolist_to_binary([Error])}]}}]}, 400).

require_auth(Req) ->
    %% We need this for browsers that display auth
    %% dialog when faced with 401 with
    %% WWW-Authenticate header response, even via XHR
    case mochiweb_request:get_header_value("invalid-auth-response", Req) == "on"
         orelse ns_config:read_key_fast(disable_www_authenticate, false) of
        true ->
            ns_server_stats:notify_counter(<<"rest_request_auth_failure">>),
            reply(Req, 401);
        _ ->
            case proplists:get_value("WWW-Authenticate",
                                     menelaus_auth:get_resp_headers(Req)) of
                undefined ->
                    reply(Req, 401,
                          [{"WWW-Authenticate",
                            "Basic realm=\"Couchbase Server Admin / REST\""}]);
                _ ->
                    %% Header is already set (by scram-sha auth for example)
                    ns_server_stats:notify_counter(
                      <<"rest_request_auth_failure">>),
                    reply(Req, 401)
            end
    end.

send_chunked(Req, StatusCode, ExtraHeaders) ->
    ?make_consumer(
       begin
           Resp = respond(
                    Req, {StatusCode, response_headers(Req, ExtraHeaders),
                          chunked}),
           pipes:foreach(?producer(),
                         fun (Part) ->
                             mochiweb_response:write_chunk(Part, Resp)
                         end),
           mochiweb_response:write_chunk(<<>>, Resp)
       end).

handle_streaming(FetchDataFun, Req) ->
    %% Register to get config state change messages.
    menelaus_event:register_watcher(self()),
    DataBody =
      fun (LastRes, Update) ->
          {notify_watcher, UpdateID} = Update,
          Res = FetchDataFun(stable, UpdateID),
          case Res =:= LastRes of
            true ->
                no_data;
            false ->
                ResNormal = case Res of
                                {just_write, Stuff} ->
                                    Stuff;
                                _ ->
                                    FetchDataFun(unstable, UpdateID)
                            end,
                Encoded = case ResNormal of
                              {write, Bin} -> Bin;
                              _ -> encode_json(ResNormal)
                          end,
                {Res, Encoded}
          end
      end,
    handle_streaming(Req, DataBody, notify_watcher).

handle_streaming(Req, DataBody, NotifyTag) ->
    validator:handle(
      fun (Params) ->
              Timer = misc:create_timer(heartbeat),
              Heartbeat =
                  case proplists:get_value(heartbeat, Params) of
                      undefined -> undefined;
                      H -> H * 1000
                  end,
              HTTPRes = reply_ok(Req, "application/json; charset=utf-8",
                                 chunked),
              Sock = mochiweb_request:get(socket, Req),
              mochiweb_socket:setopts(Sock, [{active, true}]),
              handle_streaming(Req, DataBody, HTTPRes, undefined,
                               {NotifyTag, undefined}, Heartbeat, Timer)
      end, Req, qs,
      [validator:integer(heartbeat, 1, infinity, _)]).

register_heartbeat(undefined, Timer) ->
    Timer;
register_heartbeat(Heartbeat, Timer) ->
    misc:arm_timer(Heartbeat, Timer).

handle_streaming(Req, DataBody, HTTPRes, LastRes, {NotifyTag, _} = Update,
                 Heartbeat, Timer) ->
    {Res, NewTimer} =
        try streaming_inner(DataBody, HTTPRes, LastRes, Update, Heartbeat,
                            Timer)
        catch exit:Type:Stack ->
                maybe_log_exit(Type),
                mochiweb_response:write_chunk("", HTTPRes),
                erlang:raise(exit, Type, Stack)
        end,
    request_tracker:hibernate(Req, ?MODULE, handle_streaming_wakeup,
                              [Req, DataBody, HTTPRes, Res, NotifyTag,
                               Heartbeat, NewTimer]).

maybe_log_exit(normal) ->
    ok;
maybe_log_exit(Type) ->
    ?log_warning("Received abnormal 'EXIT' message of type: ~p", [Type]).

send_data(Data, HTTPRes) ->
    mochiweb_response:write_chunk(Data, HTTPRes),
    send_separator(HTTPRes).

send_separator(HTTPRes) ->
    mochiweb_response:write_chunk("\n\n\n\n", HTTPRes).

streaming_inner(DataBody, HTTPRes, LastRes, Update, Heartbeat, Timer) ->
    case Update of
        {_, heartbeat} ->
            send_separator(HTTPRes),
            {LastRes, register_heartbeat(Heartbeat, Timer)};
        _ ->
            case DataBody(LastRes, Update) of
                no_data ->
                    {LastRes, Timer};
                {Res, Data} ->
                    send_data(Data, HTTPRes),
                    {Res, register_heartbeat(Heartbeat, Timer)}
            end
    end.

flush_notifications(NotifyTag, Value) ->
    receive
        {NotifyTag, NewValue} ->
            flush_notifications(NotifyTag, NewValue)
    after 0 ->
        Value
    end.

handle_streaming_wakeup(Req, DataBody, HTTPRes, Res, NotifyTag, Heartbeat,
                        Timer) ->
    NewValue =
        receive
            {NotifyTag, Value} ->
                timer:sleep(50),
                flush_notifications(NotifyTag, Value);
            heartbeat ->
                heartbeat;
            _ ->
                exit(normal)
        after 25000 ->
                timeout
        end,
    handle_streaming(Req, DataBody, HTTPRes, Res,
                     {NotifyTag, NewValue}, Heartbeat, Timer).

param_error_prefix(ParamName) ->
    io_lib:format("Parameter ~p requires ", [ParamName]).

assert_is_enterprise() ->
    assert(fun cluster_compat_mode:is_enterprise/0,
           "This http API endpoint requires enterprise edition",
           [{"X-enterprise-edition-needed", 1}]).

assert_is_enterprise(ParamName) ->
    assert(fun cluster_compat_mode:is_enterprise/0,
           [param_error_prefix(ParamName), "enterprise edition"],
           [{"X-enterprise-edition-needed", 1}]).

assert_is_dev_preview() ->
    assert(fun cluster_compat_mode:is_developer_preview/0,
           "This http API endpoint requires developer preview to be enabled").

assert_profile_flag(Flag, ParamName) ->
    assert(?cut(config_profile:get_bool(Flag)),
           [param_error_prefix(ParamName),
            io_lib:format("config profile flag ~p to be set.", [Flag])]).

assert_is_76() ->
    assert_cluster_version(fun cluster_compat_mode:is_cluster_76/0).

assert_is_morpheus() ->
    assert_cluster_version(fun cluster_compat_mode:is_cluster_morpheus/0).

assert_cluster_version(Fun) ->
    assert(
      Fun, "This http API endpoint isn't supported in mixed version clusters").

assert_config_profile_flag(Flag) ->
    assert_config_profile_flag(Flag, fun (X) -> X end).

assert_not_config_profile_flag(Flag) ->
    assert_config_profile_flag(Flag, fun (X) -> not X end).

assert_config_profile_flag(Flag, MapFun) ->
    assert(?cut(MapFun(config_profile:get_bool(Flag))),
           "Operation not allowed in this config profile").

assert(Fun, Error) ->
    assert(Fun, Error, []).

assert(Fun, Error, Headers) ->
    case Fun() of
        true ->
            ok;
        false ->
            web_exception(400, Error, Headers)
    end.

choose_node_consistently(Req, Nodes) ->
    Token = case menelaus_auth:extract_ui_auth_token(Req) of
                not_ui -> undefined;
                {token, T} -> T
            end,
    Memo = menelaus_ui_auth:check(Token),
    Peer = mochiweb_request:get(peer, Req),
    N = erlang:phash2({Memo, Peer}, length(Nodes)) + 1,
    lists:nth(N, Nodes).

proxy_req({Scheme, Host, Port, AFamily}, Path, Headers, Timeout,
          ExtraConnectOpts, Req) when is_atom(Scheme) ->
    Method = mochiweb_request:get(method, Req),
    Body = get_body(Req),
    TLSOpts = case Scheme of
                  https ->
                      ns_ssl_services_setup:tls_client_opts(ns_config:latest(),
                                                            ExtraConnectOpts);
                  http ->
                      []
              end,
    Options = [{partial_download, [{window_size, ?WINDOW_SIZE},
                                   {part_size, ?PART_SIZE}]},
               {connect_options, [AFamily | TLSOpts]}],
    Resp = lhttpc:request(Host, Port, Scheme =:= https, Path, Method, Headers,
                          Body, Timeout, Options),
    RespHeaderFilterFun =
        lists:filter(
            fun ({K, _}) ->
                not lists:member(string:to_lower(K), ?PROXY_DROP_RESP_HEADERS)
            end, _),
    handle_resp(Resp, RespHeaderFilterFun, Req).

get_body(Req) ->
    case mochiweb_request:recv_body(Req) of
        Body when is_binary(Body) ->
            Body;
        undefined ->
            <<>>
    end.

handle_resp({ok, {{StatusCode, _ReasonPhrase}, RcvdHeaders, Pid}},
            RespHeaderFilterFun, Req)
  when is_pid(Pid) ->
    SendHeaders = RespHeaderFilterFun(RcvdHeaders),
    Resp = menelaus_util:reply(Req, chunked, StatusCode, SendHeaders),
    stream_body(Pid, Resp);
handle_resp({ok, {{StatusCode, _ReasonPhrase}, RcvdHeaders, undefined = _Body}},
            RespHeaderFilterFun, Req) ->
    SendHeaders = RespHeaderFilterFun(RcvdHeaders),
    menelaus_util:reply_text(Req, <<>>, StatusCode, SendHeaders);
handle_resp({error, timeout}, _RespHeaderFilterFun, Req) ->
    menelaus_util:reply_text(Req, <<"Gateway Timeout">>, 504);
handle_resp({error, _Reason} = Error, _RespHeaderFilterFun, Req) ->
    ?log_error("http client error ~p~n", [Error]),
    menelaus_util:reply_text(Req, <<"Unexpected server error">>, 500).

stream_body(Pid, Resp) ->
    case lhttpc:get_body_part(Pid) of
        {ok, Part} when is_binary(Part) ->
            mochiweb_response:write_chunk(Part, Resp),
            stream_body(Pid, Resp);
        {ok, {http_eob, _Trailers}} ->
            mochiweb_response:write_chunk(<<>>, Resp)
    end.

survive_web_server_restart(Fun) ->
    %% NOTE: due to required restart we need to protect
    %%       ourselves from 'death signal' of parent
    erlang:process_flag(trap_exit, true),

    %% Ask mochiweb to send "Connection: close" header
    %% otherwise the remote client might try to send another http request
    %% in this connection and get a connection close as the result.
    erlang:put(mochiweb_request_force_close, true),

    Fun(),

    %% NOTE: we have to stop this process because in case of
    %%       ns_server restart it becomes orphan
    erlang:exit(normal).

-ifdef(TEST).
compute_sec_headers_test() ->
    ?assertEqual(lists:sort(?SEC_HEADERS), lists:sort(compute_sec_headers([]))),
    ?assertEqual(lists:sort([{"hdr", "val"} | ?SEC_HEADERS]),
                 lists:sort(compute_sec_headers([{"hdr", "val"}]))),
    ?assertEqual(lists:sort(
                   lists:keystore("X-Frame-Options", 1, ?SEC_HEADERS,
                                  {"X-Frame-Options", "OTHER"})),
                 lists:sort(
                   compute_sec_headers([{"X-Frame-Options", "OTHER"}]))),
    ?assertEqual(lists:sort(
                   lists:keydelete("X-Frame-Options", 1, ?SEC_HEADERS)),
                 lists:sort(
                   compute_sec_headers([{"X-Frame-Options", disable}]))),
    ?assertEqual([], compute_sec_headers([{enabled, false}])),
    ?assertEqual(lists:sort(?SEC_HEADERS),
                 lists:sort(compute_sec_headers([{enabled, true}]))).

response_headers_test() ->
    BaseSecHeaders = ?BASE_HEADERS ++ ?SEC_HEADERS,
    AllHeaders = ?NO_CACHE_HEADERS ++ BaseSecHeaders,
    meck:new(ns_config, [passthrough]),
    meck:expect(ns_config, read_key_fast, fun(secure_headers, []) -> [] end),
    ?assertEqual(lists:keysort(1, AllHeaders),
                 response_headers([])),
    ?assertEqual(lists:keysort(1, AllHeaders),
                 response_headers([{allow_cache, false}])),
    ?assertEqual(lists:keysort(1, [{"Extra", "header"}, {"Foo", "bar"}] ++
                                   AllHeaders),
                 response_headers([{"Foo", "bar"}, {"Extra", "header"}])),
    ?assertEqual(lists:keysort(1, [{"Cache-Control", "max-age=30000000"}] ++
                                   BaseSecHeaders),
                 response_headers([{allow_cache, true}])),
    ?assertEqual(lists:keysort( 1, [{"Cache-Control", "max-age=10"}] ++
                                    BaseSecHeaders),
                 response_headers([{?CACHE_CONTROL, "max-age=10"}])),
    ?assertEqual(lists:keysort(1, [{"Cache-Control", "max-age=10"}] ++
                                   BaseSecHeaders),
                 response_headers([{?CACHE_CONTROL, "max-age=10"},
                                   {allow_cache, true}])),
    ?assertEqual(lists:keysort( 1, [{"Duplicate", "first"}] ++ AllHeaders),
                 response_headers([{"Duplicate", "first"},
                                   {"Duplicate", "second"}])),
    meck:expect(ns_config, read_key_fast, fun(secure_headers, []) ->
                                                  [{enabled, false}] end),
    ?assertEqual(lists:keysort( 1, [{"Duplicate", "first"}] ++
                                    ?NO_CACHE_HEADERS ++ ?BASE_HEADERS),
                 response_headers([{"Duplicate", "first"},
                                   {"Duplicate", "second"}])),
    meck:unload(ns_config).

assert_config_profile_flag_test() ->
    %% implied 'default' profile
    ?assertEqual({web_exception, 400,
                  "Operation not allowed in this config profile", []},
                 catch(assert_config_profile_flag(
                         disable_auto_rebalance_settings))),
    ?assertEqual(ok,
                 assert_not_config_profile_flag(
                   disable_auto_rebalance_settings)).

-endif.
