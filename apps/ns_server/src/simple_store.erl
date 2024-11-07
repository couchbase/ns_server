%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

%%
%% Simple KV storage using ETS table as front end and file as the back end
%% for persistence.
%% Initialize using simple_store:start_link([your_store_name]).
%% Current consumer is XDCR checkpoints.
%%
-module(simple_store).

-include("ns_common.hrl").

%% APIs

-export([start_link/1,
         get/2, get/3,
         set/3,
         delete/2,
         delete_matching/2,
         clear/1,
         iterate_matching/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

%% Macros

%% Persist the ETS table to file after 10 secs.
%% All updates to the table during that window will automatically get batched
%% and flushed to the file together.
-define(FLUSH_AFTER, 10 * 1000).

%% Max number of unsucessful flush attempts before giving up.
-define(FLUSH_RETRIES, 10).

-record(state, {flush_pending :: undefined | erlang:reference(),
                store_name :: atom()}).

%% Exported APIs

start_link(StoreName) ->
    ProcName = get_proc_name(StoreName),
    gen_server:start_link({local, ProcName}, ?MODULE, StoreName, []).

get(StoreName, Key) ->
    get(StoreName, Key, false).

get(StoreName, Key, Default) ->
    case ets:lookup(StoreName, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            Default
    end.

set(StoreName, Key, Value) ->
    do_work(StoreName, fun update_store/2, [Key, Value]).

delete(StoreName, Key) ->
    do_work(StoreName, fun delete_from_store/2, [Key]).

clear(StoreName) ->
    do_work(StoreName, fun clear_store/2, []).

%% Delete keys with matching prefix
delete_matching(StoreName, KeyPattern) ->
    do_work(StoreName, fun del_matching/2, [KeyPattern]).

%% Return keys with matching prefix
iterate_matching(StoreName, KeyPattern) ->
    ets:foldl(
      fun ({Key, Value}, Acc) ->
              case misc:is_prefix(KeyPattern, Key) of
                  true ->
                      ?metakv_debug("Returning Key ~p.", [Key]),
                      [{Key, Value} | Acc];
                  false ->
                      Acc
              end
      end, [], StoreName).

%% Internal
init(StoreName) ->
    %% Populate the table from the file if the file exists otherwise create
    %% an empty table.
    FilePath = path_config:component_path(data, get_file_name(StoreName)),
    Read =
        case filelib:is_regular(FilePath) of
            true ->
                ?metakv_debug("Reading ~p content from ~s", [StoreName, FilePath]),
                case ets:file2tab(FilePath, [{verify, true}]) of
                    {ok, StoreName} ->
                        true;
                    {error, Error} ->
                        ?metakv_debug("Failed to read ~p content from ~s: ~p",
                                      [StoreName, FilePath, Error]),
                        false
                end;
            false ->
                false
        end,

    case Read of
        true ->
            ok;
        false ->
            ?metakv_debug("Creating Table: ~p", [StoreName]),
            ets:new(StoreName, [named_table, set, protected]),
            ok
    end,
    {ok, #state{flush_pending = undefined, store_name = StoreName}}.

handle_call({work, Fun}, _From, State) ->
    {Res, NewState} = Fun(State),
    {reply, Res, NewState, hibernate};

handle_call(Unhandled, _From, State) ->
    ?log_error("Unhandled call: ~p", [Unhandled]),
    {noreply, State}.

handle_cast(Unhandled, State) ->
    ?log_error("Unhandled cast: ~p", [Unhandled]),
    {noreply, State}.

handle_info({timer, flush, NumRetries}, State) ->
    ?flush({timer, flush, _}),
    {noreply, flush_table(NumRetries, State)};

handle_info(Unhandled, State) ->
    ?log_error("Unhandled info: ~p", [Unhandled]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

do_work(StoreName, Fun, Args) ->
    gen_server:call(
      get_proc_name(StoreName),
      {work, fun (S) -> erlang:apply(Fun, [Args, S]) end},
       infinity).

%% Update the ETS table and schedule a flush to the file.
update_store([Key, Value], #state{store_name = StoreName} = State) ->
    ?metakv_debug("Updating data ~p in table ~p.", [[{Key, Value}], StoreName]),
    ets:insert(StoreName, [{Key, Value}]),
    {ok, schedule_flush(?FLUSH_RETRIES, State)}.

%% Delete from the ETS table and schedule a flush to the file.
delete_from_store([Key], #state{store_name = StoreName} = State) ->
    ?metakv_debug("Deleting key ~p in table ~p.", [Key, StoreName]),
    ets:delete(StoreName, Key),
    {ok, schedule_flush(?FLUSH_RETRIES, State)}.

clear_store([], #state{store_name = StoreName} = State) ->
    ?metakv_debug("Deleting all keys in table ~p.", [StoreName]),
    ets:delete_all_objects(StoreName),
    {ok, schedule_flush(?FLUSH_RETRIES, State)}.

del_matching([KeyPattern], #state{store_name = StoreName} = State) ->
    ets:foldl(
      fun ({Key, _}, _) ->
              case misc:is_prefix(KeyPattern, Key) of
                  true ->
                      ?metakv_debug("Deleting Key ~p.", [Key]),
                      ets:delete(StoreName, Key);
                  false ->
                      ok
              end
      end, undefined, StoreName),
    {ok, schedule_flush(?FLUSH_RETRIES, State)}.

%% Nothing can be done if we failed to flush repeatedly.
schedule_flush(0, #state{store_name = StoreName} = _State) ->
    ?metakv_debug("Tried to flush table ~p ~p times but failed. Giving up.",
                  [StoreName, ?FLUSH_RETRIES]),
    exit(flush_failed);

%% If flush is pending then nothing else to do otherwise schedule a
%% flush to the file for later.
schedule_flush(_NumRetries,
               #state{flush_pending = Ref} = State) when is_reference(Ref) ->
    ?metakv_debug("Flush is already pending."),
    State;
schedule_flush(NumRetries, #state{flush_pending = undefined} = State) ->
    Ref = erlang:send_after(?FLUSH_AFTER, self(), {timer, flush, NumRetries}),
    ?metakv_debug("Successfully scheduled a flush to the file."),
    State#state{flush_pending = Ref}.

%% Flush the table to the file.
flush_table(NumRetries, #state{store_name = StoreName} = State) ->
    NewState = stop_flush_timer(State),
    FilePath = path_config:component_path(data, get_file_name(StoreName)),
    ?metakv_debug("Persisting Table ~p to file ~p.", [StoreName, FilePath]),
    case ets:tab2file(StoreName, FilePath, [{extended_info, [object_count]}]) of
        ok ->
            NewState;
        {error, Error} ->
            ?metakv_debug("Failed to persist table ~p to file ~p with error ~p.",
                          [StoreName, FilePath, Error]),
            %% Reschedule another flush.
            schedule_flush(NumRetries - 1, NewState)
    end.

stop_flush_timer(#state{flush_pending = undefined} = State) -> State;
stop_flush_timer(#state{flush_pending = Ref} = State) when is_reference(Ref) ->
    catch erlang:cancel_timer(Ref),
    State#state{flush_pending = undefined}.

get_proc_name(StoreName) ->
    list_to_atom(get_file_name(StoreName)).

get_file_name(StoreName) ->
    atom_to_list(?MODULE) ++ "_" ++ atom_to_list(StoreName).
