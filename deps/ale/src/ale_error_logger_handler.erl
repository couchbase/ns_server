%% @author Couchbase <info@couchbase.com>
%% @copyright 2011-2014 Couchbase, Inc.
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

-module(ale_error_logger_handler).

-export([log/4]).

-compile({parse_transform, ale_transform}).

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
    {Format, Args} = get_log(Level, Msg, Meta),
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
