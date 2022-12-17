%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(token_server).

-include("ns_common.hrl").

-behaviour(gen_server).

-export([start_link/4]).
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-export([generate/2, generate/3, maybe_refresh/2,
         check/3, reset_all/1, remove/2,
         purge/2, take/2]).

-define(EXPIRATION_CHECKING_INTERVAL, 15000).

-type token() :: binary().

-record(token_record,
        {token :: token() | '$1',
         %% expiration_timestamp shows when token expires
         expiration_timestamp :: pos_integer() | '_',
         %% refresh_timestamp shows when token can be refreshed/rotated,
         %% undefined means it can't be refreshed/rotated
         refresh_timestamp = no_refresh :: pos_integer() | no_refresh | '_',
         prev_token :: token() | undefined | '_',
         memo :: term()}).

start_link(Module, MaxTokens, ExpirationSeconds, ExpirationCallback) ->
    gen_server:start_link({local, Module}, ?MODULE,
                          [Module, MaxTokens, ExpirationSeconds,
                           ExpirationCallback], []).

tok2bin(Token) when is_list(Token) ->
    list_to_binary(Token);
tok2bin(Token) ->
    Token.

generate(Module, Memo) ->
    generate(Module, Memo, undefined).

generate(Module, Memo, ExpirationTimestampS) ->
    gen_server:call(Module, {generate, Memo, ExpirationTimestampS}, infinity).

maybe_refresh(Module, Token) ->
    gen_server:call(Module, {maybe_refresh, tok2bin(Token)}, infinity).


check(_, undefined, _) ->
    false;
check(Module, Token, local) ->
    %% we do not check if node is part of the cluster for the
    %% local node to avoid 401 during the node rename
    gen_server:call(Module, {check, tok2bin(Token)}, infinity);
check(Module, Token, Node) ->
    case lists:member(Node, ns_node_disco:nodes_actual()) of
        true ->
            gen_server:call({Module, Node}, {check, tok2bin(Token)}, infinity);
        false ->
            false
    end.

reset_all(Module) ->
    gen_server:call(Module, reset_all, infinity).

remove(Module, Token) ->
    gen_server:call(Module, {remove, tok2bin(Token)}, infinity).

take(Module, Token) ->
    gen_server:call(Module, {take, tok2bin(Token)}, infinity).

purge(Module, MemoPattern) ->
    gen_server:cast(Module, {purge, MemoPattern}).

-record(state, {table_by_token,
                table_by_exp,
                max_tokens,
                default_exp_seconds,
                exp_callback}).

init([Module, MaxTokens, ExpirationSeconds, ExpirationCallback]) ->
    ExpTable = list_to_atom(atom_to_list(Module) ++ "_by_expiration"),
    _ = ets:new(Module, [protected, named_table, set,
                         {keypos, #token_record.token}]),
    _ = ets:new(ExpTable, [protected, named_table, ordered_set]),
    Module:init(),
    case ExpirationCallback of
        undefined ->
            ok;
        _ ->
            erlang:send_after(?EXPIRATION_CHECKING_INTERVAL, self(),
                              check_for_expirations)
    end,
    {ok, #state{table_by_token = Module,
                table_by_exp = ExpTable,
                max_tokens = MaxTokens,
                default_exp_seconds = ExpirationSeconds,
                exp_callback = ExpirationCallback}}.

maybe_expire(#state{table_by_token = Table,
                    max_tokens = MaxTokens} = State) ->
    Size = ets:info(Table, size),
    case Size < MaxTokens of
        true ->
            ok;
        _ ->
            expire_oldest(State)
    end.

expire_oldest(#state{table_by_token = Table,
                     table_by_exp = ExpTable,
                     exp_callback = ExpCallback}) ->
    {ExpirationTS, Token} = ets:first(ExpTable),
    Memo = case ExpCallback of
               undefined ->
                   unused;
               _ ->
                   [#token_record{memo = Memo0}] = ets:lookup(Table, Token),
                   Memo0
           end,
    ets:delete(ExpTable, {ExpirationTS, Token}),
    ets:delete(Table, Token),
    maybe_do_callback(ExpCallback, Memo, Token),
    ok.

remove_token(Token, #state{table_by_token = Table,
                           table_by_exp = ExpTable}) ->
    case ets:lookup(Table, Token) of
        [#token_record{token = Token,
                       expiration_timestamp = ExpirationTS,
                       prev_token = ReplacedToken}] ->
            ets:delete(ExpTable, {ExpirationTS, Token}),
            ets:delete(Table, Token),
            ReplacedToken;
        [] ->
            false
    end.

remove_token_with_predecessor(Token, State) ->
    %% NOTE: {maybe_refresh... above is inserting new token when old is
    %% still valid (to give current requests time to finish). But
    %% gladly we also store older and potentially valid token, so we
    %% can delete it as well here
    OlderButMaybeValidToken = remove_token(Token, State),
    case OlderButMaybeValidToken of
        undefined ->
            ok;
        false ->
            ok;
        _ ->
            remove_token(OlderButMaybeValidToken, State)
    end,
    ok.

get_now() ->
    erlang:monotonic_time(second).

do_generate_token(ReplacedToken, Memo, ExpirationTimestampS,
                  #state{table_by_token = Table,
                         table_by_exp = ExpTable,
                         default_exp_seconds = ExpirationSeconds}) ->
    %% NOTE: couch_uuids:random is using crypto-strong random
    %% generator
    Token = couch_uuids:random(),
    {ExpirationTS, RefreshTS} =
        case ExpirationTimestampS of
            undefined ->
                Now = get_now(),
                {Now + ExpirationSeconds, Now + ExpirationSeconds div 2};
            _ ->
                {ExpirationTimestampS, no_refresh}
        end,
    ets:insert(Table, #token_record{token = Token,
                                    expiration_timestamp = ExpirationTS,
                                    refresh_timestamp = RefreshTS,
                                    prev_token = ReplacedToken,
                                    memo = Memo}),
    ets:insert(ExpTable, {{ExpirationTS, Token}}),
    Token.

validate_token_maybe_expire(Token,
                            #state{table_by_token = Table,
                                   exp_callback = ExpCallback} = State) ->
    case ets:lookup(Table, Token) of
        [#token_record{token = Token,
                       expiration_timestamp = ExpirationTS,
                       refresh_timestamp = RefreshTS,
                       memo = Memo}] ->
            Now = get_now(),
            case ExpirationTS < Now of
                true ->
                    remove_token(Token, State),
                    maybe_do_callback(ExpCallback, Memo, Token),
                    false;
                _ ->
                    {RefreshTS, Now, Memo}
            end;
        [] ->
            false
    end.

maybe_do_callback(undefined, _Memo, _Token) ->
    ok;
maybe_do_callback(Callback, Memo, Token) ->
    Callback(Memo, Token).

handle_call(reset_all, _From, #state{table_by_token = Table,
                                     table_by_exp = ExpTable} = State) ->
    ets:delete_all_objects(Table),
    ets:delete_all_objects(ExpTable),
    {reply, ok, State};
handle_call({generate, Memo, ExpirationTimestampS}, _From, State) ->
    maybe_expire(State),
    Token = do_generate_token(undefined, Memo, ExpirationTimestampS, State),
    {reply, Token, State};
handle_call({maybe_refresh, Token}, _From, #state{} = State) ->
    case validate_token_maybe_expire(Token, State) of
        false ->
            {reply, nothing, State};
        {RefreshTS, Now, Memo} ->
            case is_number(RefreshTS) andalso (RefreshTS =< Now) of
                true ->
                    %% NOTE: we take note of current and still valid
                    %% token for correctness of logout
                    %%
                    %% NOTE: condition above ensures that there are at
                    %% most 2 valid tokens per session
                    NewToken = do_generate_token(Token, Memo, undefined, State),
                    {reply, {new_token, NewToken}, State};
                false ->
                    {reply, nothing, State}
            end
    end;
handle_call({remove, Token}, _From, State) ->
    remove_token_with_predecessor(Token, State),
    {reply, ok, State};
handle_call({take, Token}, _From, State) ->
    case validate_token_maybe_expire(Token, State) of
        false ->
            {reply, false, State};
        {_RefreshTS, _Now, Memo} ->
            remove_token_with_predecessor(Token, State),
            {reply, {ok, Memo}, State}
    end;
handle_call({check, Token}, _From, State) ->
    case validate_token_maybe_expire(Token, State) of
        false ->
            {reply, false, State};
        {_RefreshTS, _Now, Memo} ->
            Res =
                case cluster_compat_mode:is_cluster_elixir() of
                    true -> Memo;
                    false ->
                        case Memo of
                            #uisession{user_id = Id} -> Id;
                            _ -> Memo
                        end
                end,
            {reply, {ok, Res}, State}
    end;
handle_call(Msg, From, _State) ->
    erlang:error({unknown_call, Msg, From}).

handle_cast({purge, MemoPattern}, #state{table_by_token = Table} = State) ->
    Tokens = ets:match(Table, #token_record{token = '$1',
                                            memo = MemoPattern,
                                            _ = '_'}),
    ?log_debug("Purge tokens ~p", [Tokens]),
    [remove_token(Token, State) || [Token] <- Tokens],
    {noreply, State};

handle_cast(Msg, _State) ->
    erlang:error({unknown_cast, Msg}).

handle_info(check_for_expirations, State) ->
    do_check_for_expirations(State),
    erlang:send_after(?EXPIRATION_CHECKING_INTERVAL, self(),
                      check_for_expirations),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

do_check_for_expirations(#state{table_by_exp = ExpTable} = State) ->
    case ets:first(ExpTable) of
        '$end_of_table' ->
            ok;
        {ExpirationTS, _Token} ->
            Now = get_now(),
            case ExpirationTS < Now of
                true ->
                    expire_oldest(State),
                    do_check_for_expirations(State);
                false ->
                    ok
            end
    end.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
