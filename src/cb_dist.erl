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

%% @doc Wraper for *_dist modules. Allows to start/stop listeners dynamically.
-module(cb_dist).

-behaviour(gen_server).

-include_lib("kernel/include/net_address.hrl").
-include_lib("kernel/include/dist_util.hrl").

% dist module callbacks, called from net_kernel
-export([listen/1, accept/1, accept_connection/5,
         setup/5, close/1, select/1, is_node_name/1, childspecs/0]).

% management api
-export([start_link/0,
         get_preferred_dist/1,
         reload_config/0,
         reload_config/1,
         status/0,
         config_path/0,
         address_family/0,
         external_encryption/0,
         external_listeners/0,
         update_config/1,
         proto_to_encryption/1,
         format_error/1,
         netsettings2str/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {listeners = [],
            acceptors = [],
            creation = undefined,
            kernel_pid = undefined,
            config = undefined,
            name = undefined}).

-define(family, ?MODULE).
-define(proto, ?MODULE).

-type socket() :: any().
-type protocol() :: inet_tcp_dist | inet6_tcp_dist |
                    inet_tls_dist | inet6_tls_dist.

%%%===================================================================
%%% API
%%%===================================================================

childspecs() ->
    CBDistSpec = [{?MODULE, {?MODULE, start_link, []},
                   permanent, infinity, worker, [?MODULE]}],
    DistSpecs =
        lists:flatmap(
          fun (Mod) ->
                  case (catch Mod:childspecs()) of
                      {ok, Childspecs} when is_list(Childspecs) -> Childspecs;
                      _ -> []
                  end
          end, [inet_tcp_dist, inet_tls_dist]),
    {ok, DistSpecs ++ CBDistSpec}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec listen(Name :: atom()) ->
    {ok, {LSocket :: any(),
          LocalTcpAddress :: #net_address{},
          Creation :: pos_integer()}}.
listen(Name) when is_atom(Name) ->
    Pid = whereis(?MODULE),
    case gen_server:call(Pid, {listen, Name}, infinity) of
        {ok, Creation} ->
            Addr = #net_address{address = undefined,
                                host = undefined,
                                protocol = ?family,
                                family = ?proto},
            {ok, {Pid, Addr, Creation}};
        {error, _} = Error ->
            Error
    end.

-spec accept(LSocket :: any()) -> AcceptorPid :: pid().
accept(_LSocket) ->
    gen_server:call(?MODULE, {accept, self()}, infinity).

-spec accept_connection(CBDistPid :: pid(),
                        Acceptor :: {pid(), socket()},
                        MyNode :: atom(),
                        Allowed :: any(),
                        SetupTime :: any()) ->
                            {ConPid :: pid(), AcceptorPid :: pid()}.
accept_connection(_, {AcceptorPid, ConnectionSocket}, MyNode, Allowed, SetupTime) ->
    Module = gen_server:call(?MODULE, {get_module_by_acceptor, AcceptorPid},
                             infinity),
    info_msg("Accepting connection from acceptor ~p using module ~p",
             [AcceptorPid, Module]),
    case Module =/= undefined of
        true ->
            ConPid = Module:accept_connection(AcceptorPid, ConnectionSocket,
                                              MyNode, Allowed, SetupTime),
            {ConPid, AcceptorPid};
        false ->
            {spawn_opt(
               fun () ->
                       error_msg("** Connection from unknown acceptor ~p, "
                                 "please reconnect ** ~n", [AcceptorPid]),
                       ?shutdown(no_node)
               end, [link]), AcceptorPid}
    end.

-spec select(Node :: atom()) -> true | false.
select(Node) ->
    try get_preferred_dist(Node) of
        Module -> Module:select(Node)
    catch
        _:Error ->
            error_msg("Select for ~p failed. Couldn't find preferred proto: ~p",
                      [Node, Error]),
            false
    end.

-spec setup(Node :: atom(),
            Type :: hidden | normal,
            MyNode :: atom(),
            LongOrShortNames :: any(),
            SetupTime :: any()) -> ConPid :: pid().
setup(Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    try get_preferred_dist(Node) of
        Module ->
            info_msg("Setting up new connection to ~p using ~p",
                     [Node, Module]),
            Module:setup(Node, Type, MyNode, LongOrShortNames, SetupTime)
    catch
        _:Error ->
            spawn_opt(
              fun () ->
                  error_msg("** Connection to ~p failed. Couldn't find "
                            "preferred proto: ~p", [Node, Error]),
                  ?shutdown2(Node, Error)
              end, [link])
    end.

-spec is_node_name(Node :: atom()) -> true | false.
is_node_name(Node) ->
    select(Node).

-spec close(LSocket :: any()) -> ok.
close(_LSocket) ->
    gen_server:call(?MODULE, close, infinity).

-spec get_preferred_dist(TargetNode :: atom() | string()) -> protocol().
get_preferred_dist(TargetNode) ->
    case gen_server:call(?MODULE, {get_preferred, TargetNode}, infinity) of
        {ok, Res} -> Res;
        {exception, {_, E, _}} -> erlang:error(E)
    end.

reload_config() ->
    gen_server:call(?MODULE, reload_config, infinity).

reload_config(Node) when is_atom(Node) ->
    gen_server:call({?MODULE, Node}, reload_config, infinity).

status() ->
    gen_server:call(?MODULE, status).

config_path() ->
    case application:get_env(kernel, dist_config_file) of
        {ok, F} -> F;
        _ ->
            error_msg("Path to cb_dist config is not set", []),
            erlang:error(no_dist_config_file)
    end.

address_family() ->
    proto_to_family(conf(preferred_external_proto, get_config())).

external_encryption() ->
    proto_to_encryption(conf(preferred_external_proto, get_config())).

external_listeners() ->
    L = conf(external_listeners, get_config()),
    lists:usort([proto2netsettings(Proto) || Proto <- L]).

get_config() ->
    try status() of
        Status -> proplists:get_value(config, Status, [])
    catch
        exit:{noproc, {gen_server, call, _}} ->
            read_config(config_path(), true)
    end.

update_config(Props) ->
    gen_server:call(?MODULE, {update_config, Props}, infinity).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Config = read_config(config_path(), true),
    info_msg("Starting cb_dist with config ~p", [Config]),
    process_flag(trap_exit,true),
    {ok, #s{config = Config, creation = rand:uniform(4) - 1}}.

handle_call({listen, Name}, _From, #s{creation = Creation} = State) ->
    State1 = State#s{name = Name},

    Protos0 = get_protos(State1),

    %% On unpatched erlang ipv6 listener automatically tries to listen on
    %% ipv4 as well (on linux and mac only) which prevents ipv4 listener
    %% to start later. To work around that start the ipv4 listener before
    %% the ipv6 one.
    OrderFun =
        fun (inet_tcp_dist, _) -> true;
            (_, inet_tcp_dist) -> false;
            (A, B) -> A =< B
        end,
    Protos = lists:sort(OrderFun, Protos0),

    Required = [R || R <- get_required_protos(State1), lists:member(R, Protos)],

    info_msg("Initial protos: ~p, required protos: ~p", [Protos, Required]),

    Listeners =
        lists:filtermap(
            fun (Module) ->
                    case listen_proto(Module, Name) of
                        {ok, Res} -> {true, {Module, Res}};
                        _Error -> false
                    end
            end, Protos),
    NotStartedRequired = Required -- [M || {M, _} <- Listeners],
    State2 = State1#s{listeners = Listeners},
    case NotStartedRequired of
        [] -> {reply, {ok, Creation}, State2};
        _ ->
            error_msg("Failed to start required dist listeners ~p. "
                      "Net kernel will not start", [NotStartedRequired]),
            close_listeners(State2),
            {reply, {error, {not_started, NotStartedRequired}}, State}
    end;

handle_call({accept, KernelPid}, _From, #s{listeners = Listeners} = State) ->
    Acceptors =
        lists:map(
            fun ({Module, {LSocket, _Addr, _Creation}}) ->
                {Module:accept(LSocket), Module}
            end,
            Listeners),
    {reply, self(), State#s{acceptors = Acceptors, kernel_pid = KernelPid}};

handle_call({get_module_by_acceptor, AcceptorPid}, _From,
            #s{acceptors = Acceptors} = State) ->
    Module = proplists:get_value(AcceptorPid, Acceptors),
    {reply, Module, State};

handle_call({get_preferred, Target}, _From, #s{name = Name,
                                               config = Config} = State) ->
    try cb_epmd:is_local_node(Target) of
        IsLocalDest ->
            IsLocalSource = cb_epmd:is_local_node(Name),
            Res =
                case IsLocalDest or IsLocalSource of
                    true -> conf(preferred_local_proto, Config);
                    false -> conf(preferred_external_proto, Config)
                end,
            {reply, {ok, Res}, State}
    catch
        C:E ->
            {reply, {exception, {C, E, erlang:get_stacktrace()}}, State}
    end;

handle_call(close, _From, State) ->
    {stop, normal, ok, close_listeners(State)};

handle_call(reload_config, _From, State) ->
    handle_reload_config(State);

handle_call(status, _From, #s{listeners = Listeners,
                              acceptors = Acceptors,
                              name = Name,
                              config = Config} = State) ->
    {reply, [{name, Name},
             {config, Config},
             {listeners, Listeners},
             {acceptors, Acceptors}], State};

handle_call({update_config, Props}, _From, #s{config = Cfg} = State) ->
    case store_config(import_props_to_config(Props, Cfg)) of
        ok -> handle_reload_config(State);
        {error, _} = Error -> {reply, Error, State}
    end;

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({accept, AcceptorPid, ConSocket, _Family, _Protocol},
            #s{kernel_pid = KernelPid} = State) ->
    info_msg("Accepted new connection from ~p", [AcceptorPid]),
    KernelPid ! {accept, self(), {AcceptorPid, ConSocket}, ?family, ?proto},
    {noreply, State};

handle_info({KernelPid, controller, {ConPid, AcceptorPid}},
            #s{kernel_pid = KernelPid} = State) ->
    AcceptorPid ! {self(), controller, ConPid},
    {noreply, State};

handle_info({'EXIT', Kernel, Reason}, State = #s{kernel_pid = Kernel}) ->
    error_msg("received EXIT from kernel, stoping: ~p", [Reason]),
    {stop, Reason, State};

handle_info({'EXIT', From, Reason}, State) ->
    error_msg("received EXIT from ~p, stoping: ~p", [From, Reason]),
    {stop, {'EXIT', From, Reason}, State};

handle_info(Info, State) ->
    error_msg("received unknown message: ~p", [Info]),
    {noreply, State}.

terminate(Reason, State) ->
    error_msg("terminating with reason: ~p", [Reason]),
    close_listeners(State),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

close_listeners(#s{listeners = Listeners} = State) ->
    Protos = [M || {M, _} <- Listeners],
    lists:foldl(fun (M, S) -> remove_proto(M, S) end, State, Protos).

%% inet_*_dist modules use inet_dist_listen_min and inet_dist_listen_max to
%% choose port for listening. Since we need them to choose Port we set those
%% variables to Port, call listen function, and then change variables back.
with_dist_port(noport, _Fun) -> ignore;
with_dist_port(Port, Fun) ->
    OldMin = application:get_env(kernel,inet_dist_listen_min),
    OldMax = application:get_env(kernel,inet_dist_listen_max),
    try
        application:set_env(kernel, inet_dist_listen_min, Port),
        application:set_env(kernel, inet_dist_listen_max, Port),
        Fun()
    after
        case OldMin of
            undefined -> application:unset_env(kernel, inet_dist_listen_min);
            {ok, V1} -> application:set_env(kernel, inet_dist_listen_min, V1)
        end,
        case OldMax of
            undefined -> application:unset_env(kernel, inet_dist_listen_max);
            {ok, V2} -> application:set_env(kernel, inet_dist_listen_max, V2)
        end
    end.

add_proto(Mod, #s{name = NodeName, listeners = Listeners,
                  acceptors = Acceptors} = State) ->
    case can_add_proto(Mod, State) of
        ok ->
            case listen_proto(Mod, NodeName) of
                {ok, L = {LSocket, _, _}} ->
                    try
                        APid = Mod:accept(LSocket),
                        true = is_pid(APid),
                        State#s{listeners = [{Mod, L}|Listeners],
                                acceptors = [{APid, Mod}|Acceptors]}
                    catch
                        _:E ->
                            ST = erlang:get_stacktrace(),
                            catch Mod:close(LSocket),
                            error_msg(
                              "Accept failed for protocol ~p with reason: ~p~n"
                              "Stacktrace: ~p", [Mod, E, ST]),
                            State
                    end;
                _Error -> State
            end;
        {error, Reason} ->
            error_msg("Ignoring ~p listener, reason: ~p", [Mod, Reason]),
            State
    end.

remove_proto(Mod, #s{listeners = Listeners, acceptors = Acceptors} = State) ->
    info_msg("Closing listener ~p", [Mod]),
    {LSocket, _, _} = proplists:get_value(Mod, Listeners),
    [erlang:unlink(P) || {P, M} <- Acceptors, M =:= Mod],
    catch Mod:close(LSocket),
    case lists:member(Mod, [inet_tls_dist, inet6_tls_dist]) of
        true ->
            %% *_tls_dist modules don't close proxy socket when Mod:close/1
            %% is called, so we have to restart proxy process to make sure that
            %% those sockets are closed
            supervisor:terminate_child(ssl_dist_sup, ssl_tls_dist_proxy),
            supervisor:restart_child(ssl_dist_sup, ssl_tls_dist_proxy);
        false -> ok
    end,
    State#s{listeners = proplists:delete(Mod, Listeners),
            acceptors = [{P, M} || {P, M} <- Acceptors, M =/= Mod]}.

listen_proto(Module, NodeName) ->
    NameStr = atom_to_list(NodeName),
    Port = cb_epmd:port_for_node(Module, NameStr),
    info_msg("Starting ~p listener on ~p...", [Module, Port]),
    ListenFun =
        fun () ->
                case Module:listen(NodeName) of
                    {ok, _} = Res ->
                        case maybe_register_on_epmd(Module, NodeName, Port) of
                            ok -> Res;
                            {error, _} = Error -> Error
                        end;
                    Error -> Error
                end
        end,
    case with_dist_port(Port, ListenFun) of
        {ok, Res} -> {ok, Res};
        ignore ->
            info_msg("Ignoring starting dist ~p on port ~p", [Module, Port]),
            ignore;
        Error ->
            error_msg("Failed to start dist ~p on port ~p with reason: ~p",
                      [Module, Port, Error]),
            Error
    end.

%% Backward compat: we need to register ns_server non tls port on epmd to allow
%% old nodes to find this node
%% This code can be dropped if upgrade from Alice is not supported
maybe_register_on_epmd(Module, NodeName, PortNo)
  when Module =:= inet_tcp_dist;
       Module =:= inet6_tcp_dist ->
    case cb_epmd:node_type(atom_to_list(NodeName)) of
        ns_server ->
            Family = proto_to_family(Module),
            case erl_epmd:register_node(NodeName, PortNo, Family) of
                {ok, _} -> ok;
                {error, already_registered} -> ok;
                Error -> Error
            end;
        _ ->
            ok
    end;
maybe_register_on_epmd(_Module, _NodeName, _PortNo) ->
    ok.

can_add_proto(P, #s{listeners = L}) ->
    case is_valid_protocol(P) of
        true ->
            case proplists:is_defined(P, L) of
                false ->
                    HasInet6Tls = proplists:is_defined(inet6_tls_dist, L),
                    HasInetTls = proplists:is_defined(inet_tls_dist, L),
                    case P of
                        inet6_tls_dist when HasInetTls ->
                            {error, {already_has, inet_tls_dist}};
                        inet_tls_dist when HasInet6Tls ->
                            {error, {already_has, inet6_tls_dist}};
                        _ ->
                            ok
                    end;
                true ->
                    {error, already_enabled}
            end;
        false ->
            {error, invalid_protocol}
    end.

is_valid_protocol(P) ->
    lists:member(P, [inet_tcp_dist, inet6_tcp_dist, inet_tls_dist,
                     inet6_tls_dist]).

conf(Prop, Conf) ->
    proplists:get_value(Prop, Conf, proplists:get_value(Prop, defaults())).

defaults() ->
    [{preferred_external_proto, inet_tcp_dist},
     {preferred_local_proto, inet_tcp_dist},
     {local_listeners, [inet_tcp_dist, inet6_tcp_dist]},
     {external_listeners, [inet_tcp_dist, inet6_tcp_dist]}].

transform_old_to_new_config(Dist) ->
    DistType = list_to_atom((atom_to_list(Dist) ++ "_dist")),
    true = is_valid_protocol(DistType),
    [{preferred_external_proto, DistType},
     {preferred_local_proto, DistType}].

read_config(File, IgnoreReadError) ->
    case read_terms_from_file(File) of
        {ok, {dist_type, Dist}} ->
            transform_old_to_new_config(Dist);
        {ok, {dist_type, _, Dist}} ->
            transform_old_to_new_config(Dist);
        {ok, Val} ->
            Val;
        {error, read_error} when IgnoreReadError ->
            [];
        {error, Reason} ->
            error_msg("Can't read cb_dist config file ~p: ~p", [File, Reason]),
            erlang:error({invalid_cb_dist_config, File, Reason})
    end.

%% can't use file:consult here because file server might not be started
%% by the moment we need to read config
read_terms_from_file(F) ->
    case erl_prim_loader:get_file(F) of
        %% Backward compat: pre-madhatter installer creates empty dist_cfg file
        {ok, <<>>, _} -> {ok, []};
        {ok, Bin, _} ->
            try {ok, misc:parse_term(Bin)}
            catch
                _:_ -> {error, invalid_format}
            end;
        error -> {error, read_error}
    end.

handle_reload_config(#s{listeners = Listeners} = State) ->
    try read_config(config_path(), true) of
        Cfg ->
            info_msg("Reloading configuration: ~p", [Cfg]),
            State1 = State#s{config = Cfg},
            CurrentProtos = [M || {M, _} <- Listeners],
            NewProtos = get_protos(State1),
            ToAdd = NewProtos -- CurrentProtos,
            ToRemove = CurrentProtos -- NewProtos,
            State2 = lists:foldl(fun (P, S) -> remove_proto(P, S) end,
                                 State1, ToRemove),
            State3 = lists:foldl(fun (P, S) -> add_proto(P, S) end,
                                 State2, ToAdd),
            NewCurrentProtos = [M || {M, _} <- State3#s.listeners],
            Required = [R || R <- get_required_protos(State3),
                             lists:member(R, get_protos(State3))],
            NotStartedRequired = Required -- NewCurrentProtos,
            case NotStartedRequired of
                [] ->
                    L = [proto2netsettings(Proto) || Proto <- NewCurrentProtos],
                    {reply, {ok, L}, State3};
                _ ->
                    error_msg("Failed to start required dist listeners ~p",
                              [NotStartedRequired]),
                    {reply, {error, {not_started, NotStartedRequired}}, State3}
            end
    catch
        _:Error -> {reply, {error, Error}, State}
    end.

get_protos(#s{name = Name, config = Config}) ->
    Protos =
        case cb_epmd:is_local_node(Name) of
            true ->
                conf(local_listeners, Config);
            false ->
                conf(external_listeners, Config) ++
                    conf(local_listeners, Config)
        end,
    lists:usort(Protos).

get_required_protos(#s{name = Name, config = Config}) ->
    Local = conf(preferred_local_proto, Config),
    Ext = conf(preferred_external_proto, Config),
    case {cb_epmd:node_type(atom_to_list(Name)), cb_epmd:is_local_node(Name)} of
        {executioner, _} -> [];
        {_, true} -> [Local];
        {_, false} -> lists:usort([Local, Ext])
    end.

info_msg(F, A) -> error_logger:info_msg("cb_dist: " ++ F, A).
error_msg(F, A) -> error_logger:error_msg("cb_dist: " ++ F, A).

proto_to_family(inet_tcp_dist) -> inet;
proto_to_family(inet_tls_dist) -> inet;
proto_to_family(inet6_tcp_dist) -> inet6;
proto_to_family(inet6_tls_dist) -> inet6.

proto_to_encryption(inet_tcp_dist) -> false;
proto_to_encryption(inet_tls_dist) -> true;
proto_to_encryption(inet6_tcp_dist) -> false;
proto_to_encryption(inet6_tls_dist) -> true.

validate_config_file(CfgFile) ->
    try
        Cfg = read_config(CfgFile, false),
        is_list(Cfg) orelse throw(not_list),
        ([E || {_, _} = E <- Cfg] == Cfg) orelse throw(not_proplist),
        Unknown = proplists:get_keys(Cfg) -- proplists:get_keys(defaults()),
        (Unknown == []) orelse throw({unknown_props, Unknown}),
        ExtPreferred = conf(preferred_external_proto, Cfg),
        is_valid_protocol(ExtPreferred)
            orelse throw(invalid_preferred_external_proto),
        LocalPreferred = conf(preferred_local_proto, Cfg),
        is_valid_protocol(LocalPreferred)
            orelse throw(invalid_preferred_local_proto),
        LocalListeners = conf(local_listeners, Cfg),
        ExternalListeners = conf(external_listeners, Cfg),
        Invalid = [L || L <- LocalListeners, not is_valid_protocol(L)] ++
                  [L || L <- ExternalListeners, not is_valid_protocol(L)],
        (Invalid == []) orelse throw({invalid_listeners, Invalid}),
        length(lists:usort(LocalListeners)) == length(LocalListeners)
            orelse throw(not_unique_listeners),
        length(lists:usort(ExternalListeners)) == length(ExternalListeners)
            orelse throw(not_unique_listeners),
        lists:member(ExtPreferred, ExternalListeners ++ LocalListeners)
            orelse throw({missing_preferred_external_listener, ExtPreferred}),
        lists:member(LocalPreferred, LocalListeners)
            orelse throw({missing_preferred_local_listener, LocalPreferred}),
        ok
    catch
        _:E -> {error, E}
    end.

import_props_to_config(Props, Cfg) ->
    CurListeners = proplists:get_value(external_listeners, Cfg),
    CurAFamily = proto_to_family(conf(preferred_external_proto, Cfg)),
    CurNEncr = proto_to_encryption(conf(preferred_external_proto, Cfg)),
    NewAFamily = proplists:get_value(afamily, Props, CurAFamily),
    NewNEncr = proplists:get_value(nodeEncryption, Props, CurNEncr),
    PrefExt = netsettings2proto({NewAFamily, NewNEncr}),
    PrefLocal = netsettings2proto({NewAFamily, false}),
    Listeners =
        case proplists:get_value(externalListeners, Props) of
            undefined -> CurListeners;
            L -> [netsettings2proto(E) || E <- L]
        end,
    [{external_listeners, Listeners}     || Listeners =/= undefined] ++
    [{preferred_external_proto, PrefExt} || PrefExt   =/= undefined] ++
    [{preferred_local_proto, PrefLocal}  || PrefLocal =/= undefined].

store_config(DCfgFile, DCfg) ->
    DirName = filename:dirname(DCfgFile),
    FileName = filename:basename(DCfgFile),
    TmpPath = path_config:tempfile(DirName, FileName, ".tmp"),
    Data = io_lib:format("~p.~n", [DCfg]),
    try
        case misc:write_file(TmpPath, Data) of
            ok ->
                case validate_config_file(TmpPath) of
                    ok -> misc:atomic_rename(TmpPath, DCfgFile);
                    Y -> Y
                end;
            X ->
                X
        end
    after
        (catch file:delete(TmpPath))
    end.

store_config(Cfg) ->
    CfgFile = cb_dist:config_path(),
    case store_config(CfgFile, Cfg) of
        ok ->
            info_msg("Updated cb_dist config ~p: ~p", [CfgFile, Cfg]),
            ok;
        {error, Reason} ->
            error_msg("Failed to save cb_dist config to ~p with reason: ~p",
                      [CfgFile, Reason]),
            {error, Reason}
    end.

format_error({not_started, Protocols}) ->
    PS = string:join([proto2str(P) || P <- Protocols], ", "),
    io_lib:format("Failed to start the following required listeners: ~p", [PS]);
format_error({invalid_cb_dist_config, File, invalid_format}) ->
    io_lib:format("Invalid format of cb_dist config file (~s)", [File]);
format_error({invalid_cb_dist_config, File, read_error}) ->
    io_lib:format("Can't read cb_dist config file ~s", [File]);
format_error({invalid_cb_dist_config, File, Reason}) ->
    io_lib:format("Can't read cb_dist config file ~s (~p)", [File, Reason]);
format_error({missing_preferred_external_listener, Proto}) ->
    io_lib:format("Missing ~s listener (needed for external communication)",
                  [proto2str(Proto)]);
format_error({missing_preferred_local_listener, Proto}) ->
    io_lib:format("Missing ~s listener (needed for local communication)",
                  [proto2str(Proto)]);
format_error(Unknown) ->
    io_lib:format("~p", [Unknown]).

netsettings2str(S) -> proto2str(netsettings2proto(S)).

proto2str(inet_tcp_dist) -> "TCP-ipv4";
proto2str(inet_tls_dist) -> "TLS-ipv4";
proto2str(inet6_tcp_dist) -> "TCP-ipv6";
proto2str(inet6_tls_dist) -> "TLS-ipv6".

netsettings2proto({inet, false}) -> inet_tcp_dist;
netsettings2proto({inet, true}) -> inet_tls_dist;
netsettings2proto({inet6, false}) -> inet6_tcp_dist;
netsettings2proto({inet6, true}) -> inet6_tls_dist.

proto2netsettings(inet_tcp_dist) -> {inet, false};
proto2netsettings(inet6_tcp_dist) -> {inet6, false};
proto2netsettings(inet_tls_dist) -> {inet, true};
proto2netsettings(inet6_tls_dist) -> {inet6, true}.

