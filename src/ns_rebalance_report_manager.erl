%% @author Couchbase <info@couchbase.com>
%% @copyright 2019 Couchbase, Inc.
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
%% @doc - This module manages the recording, fetching and cleanup of
%% rebalance reports.
-module(ns_rebalance_report_manager).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include_lib("kernel/include/file.hrl").

-define(NUM_REBALANCE_REPORTS, 5).
-define(FETCH_TIMEOUT, 10000).
-define(MAX_DELAY, 10000).

%% APIs.
-export([start_link/0,
         get_rebalance_report/0,
         record_rebalance_report/1]).

%% gen_server2 callbacks.
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-record(state, {report_dir}).

%% -------------------------------------------------------------
%% APIs.
%% -------------------------------------------------------------
start_link() ->
    gen_server2:start_link({local, ?MODULE}, ?MODULE, [], []).

get_rebalance_report() ->
    case ns_config:read_key_fast(rebalance_reports, []) of
        [] ->
            {error, enoent};
        [ReqdReport | _] ->
            gen_server2:call(?MODULE,
                             {get_rebalance_report, ReqdReport, []},
                             ?FETCH_TIMEOUT)
    end.

record_rebalance_report(Report) ->
    gen_server2:call(?MODULE, {record_rebalance_report, Report}, infinity).

%% -------------------------------------------------------------
%% gen_server2 callbacks.
%% -------------------------------------------------------------
init([]) ->
    {ok, LogDir} = application:get_env(ns_server, error_logger_mf_dir),
    Dir = filename:absname(filename:join(LogDir, "rebalance")),
    ok = misc:ensure_writable_dir(Dir),
    Self = self(),
    EventHandler = fun ({rebalance_reports, _ReqdReports}) ->
                           Self ! refresh;
                       (_) ->
                           ok
                   end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),
    Self ! refresh,
    {ok, #state{report_dir = Dir}}.

handle_call({get_rebalance_report, Reqd, Options}, From,
            #state{report_dir = Dir} = State) ->
    Reports = ns_config:read_key_fast(rebalance_reports, []),
    case lists:member(Reqd, Reports) of
        false ->
            {reply, {error, enoent}, State};
        true ->
            gen_server2:async_job(
              fun () ->
                      fetch_rebalance_report(Reqd, Options, Dir)
              end,
              fun (RV, S) ->
                      gen_server2:reply(From, RV),
                      {noreply, S}
              end),
            {noreply, State}
    end;
handle_call({record_rebalance_report, Report}, _From,
            #state{report_dir = Dir} = State) ->
    FileName = "rebalance_report_" ++ misc:timestamp_utc_iso8601() ++ ".json",
    NewReportLocation = {node(), FileName},
    AllReports = [NewReportLocation |
                  ns_config:read_key_fast(rebalance_reports, [])],
    Keep = lists:sublist(AllReports, get_num_rebalance_reports()),
    Path = filename:join(Dir, FileName),
    BinaryReport = ejson:encode(Report),
    ok = misc:atomic_write_file(Path, BinaryReport),
    ns_config:set(rebalance_reports, Keep),
    {reply, ok, State};
handle_call(_, _, State) ->
    {reply, {error, enoent}, State}.

handle_cast(_, State) ->
    {noreply, State}.

handle_info(refresh, #state{report_dir = Dir} = State) ->
    misc:flush(refresh),
    refresh(Dir),
    {noreply, State};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% -------------------------------------------------------------
%% Internal API's.
%% -------------------------------------------------------------

refresh(Dir) ->
    gen_server2:abort_queue(fetch_task),
    ReqdReports = ns_config:read_key_fast(rebalance_reports, []),
    {ok, ListFiles} = file:list_dir(Dir),
    Keep = [FileName || {_Node, FileName} <- ReqdReports],

    Delete = ListFiles -- Keep,
    [file:delete(filename:join(Dir, File)) || File <- Delete],

    Missing = Keep -- ListFiles,
    MissingReports = [lists:keyfind(FN, 2, ReqdReports) || FN <- Missing],
    case MissingReports of
        [] ->
            ok;
        _ ->
            gen_server2:async_job(
              fetch_task,
              fun () ->
                      %% Delay fetch as we don't want a DDOS when
                      %% rebalance finishes.
                      %% Can be 0 - 10 seconds.
                      timer:sleep(rand:uniform(?MAX_DELAY)),
                      fetch_task(MissingReports, Dir)
              end,
              fun (_, S) -> {noreply, S} end)
    end.

%% If configured use that value. num_rebalance_reports is not set by ns_server
%% anywhere. Can only be set by explicit administrative action we provide.
get_num_rebalance_reports() ->
    ns_config:read_key_fast(num_rebalance_reports, ?NUM_REBALANCE_REPORTS).

fetch_task(MissingReports, Dir) ->
    [begin
         case does_file_exist(Dir, FN) of
             true ->
                 ok;
             false ->
                 fetch_rebalance_report_remote({Node, FN}, Dir)
         end
     end || {Node, FN} <- MissingReports, Node =/= node()].

does_file_exist(Dir, FileName) ->
    Path = filename:join(Dir, FileName),
    does_file_exist(Path).

does_file_exist(Path) ->
    case file:read_file_info(Path) of
        {ok, Info} ->
            case Info#file_info.type of
                regular ->
                    true;
                _ ->
                    false
            end;
        _Error ->
            false
    end.

maybe_write_report(Report, Path) ->
    case does_file_exist(Path) of
        true ->
            %% Do nothing, someone already fetched it.
            ok;
        false ->
            ok = misc:atomic_write_file(Path, Report)
    end.

fetch_rebalance_report({Node, _} = ReqdReport, Options, Dir) ->
    RV = case fetch_rebalance_report_local(ReqdReport, Dir) of
             {ok, Report} ->
                 {ok, Report};
             _ when node() =/= Node ->
                 fetch_rebalance_report_remote(ReqdReport, Dir);
             R ->
                 R
         end,
    maybe_compress(RV, Options).

fetch_rebalance_report_local({_Node, FileName}, Dir) ->
    try
        Path = filename:join(Dir, FileName),
        misc:raw_read_file(Path)
    catch
        error:Reason ->
            {error, Reason};
        T:E ->
            ?log_debug("Unexpected exception ~p", [T, E]),
            {error, unexpected_exception}
    end.

fetch_rebalance_report_remote(ReqdReport, Dir) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true -> fetch_rebalance_report_remote_inner(ReqdReport, Dir);
        false -> {error, enoent}
    end.

fetch_rebalance_report_remote_inner({Node, FileName} = ReqdReport, Dir) ->
    case gen_server2:call({?MODULE, Node},
                          {get_rebalance_report, ReqdReport, [{compress, true}]},
                          ?FETCH_TIMEOUT) of
        {ok, R} ->
            Report = zlib:uncompress(R),
            Path = filename:join(Dir, FileName),
            maybe_write_report(Report, Path),
            {ok, Report};
        Err -> Err
    end.

maybe_compress({ok, Report} = Reply, Options) ->
    case proplists:get_bool(compress, Options) of
        true -> {ok, zlib:compress(Report)};
        false -> Reply
    end;
maybe_compress(Reply, _) ->
    Reply.
