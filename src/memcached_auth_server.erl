-module(memcached_auth_server).

-behaviour(gen_server).

-include("ns_common.hrl").
-include("mc_constants.hrl").
-include("mc_entry.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {
    mcd_socket = undefined,
    data = <<>>
}).

-define(RECONNECT_TIMEOUT, 1000).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, Pid :: pid()} | ignore | {error, Error :: term()}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    self() ! reconnect,
    {ok, #s{}}.

handle_call(_Request, _From, State) ->
   {reply, unhandled, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(reconnect, State) ->
    {noreply, reconnect(State)};

handle_info({tcp, Sock, Data}, #s{mcd_socket = Sock, data = Rest} = State) ->
    NewState = process_data(State#s{data = <<Rest/binary, Data/binary>>}),
    inet:setopts(Sock, [{active, once}]),
    {noreply, NewState};

handle_info({tcp_closed, Sock}, #s{mcd_socket = Sock} = State) ->
    ?log_debug("Memcached 'auth provider' connection is closed"),
    {noreply, reconnect(State)};

handle_info({tcp_error, Sock, Reason}, #s{mcd_socket = Sock} = State) ->
    ?log_debug("Error occured on the memcached 'auth provider' socket: ~p",
               [Reason]),
    {noreply, reconnect(State)};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

process_data(#s{mcd_socket = Sock, data = Data} = State) ->
    case mc_binary:decode_packet_ext(Data) of
        {Header, Entry, Rest} ->
            {RespHeader, RespEntry} = process_req(Header, Entry, State),
            case mc_binary:send(Sock, server_res, RespHeader, RespEntry) of
                ok -> process_data(State#s{data = Rest});
                _ -> reconnect(State)
            end;
        need_more_data -> State
    end.

process_req(Header, _, _) ->
    {Header#mc_header{status = ?UNKNOWN_COMMAND}, #mc_entry{}}.

cmd_auth_provider(Sock) ->
    Resp = mc_client_binary:cmd_vocal(?MC_AUTH_PROVIDER, Sock,
                                      {#mc_header{},
                                       #mc_entry{}}),
    case Resp of
        {ok, #mc_header{status = ?SUCCESS}, _} ->
            ok;
        {ok, #mc_header{status = Status}, #mc_entry{data = ErrorBin}} ->
            {error, {Status, ErrorBin}}
    end.

reconnect(State = #s{mcd_socket = OldSock}) ->
    catch gen_tcp:close(OldSock),
    NewState = State#s{mcd_socket = undefined, data = <<>>},
    case connect() of
        {ok, Socket} ->
            NewState#s{mcd_socket = Socket};
        {error, _} ->
            timer:send_after(?RECONNECT_TIMEOUT, self(), reconnect),
            NewState
    end.

connect() ->
    case ns_memcached:connect([{retries, 1}, duplex]) of
        {ok, Sock} ->
            case cmd_auth_provider(Sock) of
                ok ->
                    ?log_debug("Auth provider connection established"),
                    inet:setopts(Sock, [{active, once}]),
                    {ok, Sock};
                {error, Error} ->
                    gen_tcp:close(Sock),
                    ?log_error("Failed to enable 'Auth provider' feature on "
                               "the memcached connection: ~p", [Error]),
                    {error, Error}
            end;
        {error, Reason} ->
            ?log_error("Failed to establish 'Auth provider' connection "
                       "to memcached: ~p", [Reason]),
            {error, Reason}
    end.
