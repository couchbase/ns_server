% Copyright (c) 2009, NorthScale, Inc.
% All rights reserved.

-module(mc_pool).

-behaviour(gen_server).

-include_lib("eunit/include/eunit.hrl").

-include("mc_constants.hrl").

-include("mc_entry.hrl").

-compile(export_all).

-record(mc_pool, {id,     % Pool id.
                  addrs,  % [mc_addr:create()*].
                  config, % A PoolConfig from ns_config:get().
                  buckets % [mc_bucket:create()*].
                  }).

%% API
-export([start_link/1, reconfig/2, reconfig/3,
         get_bucket/2,
         auth_to_bucket/3]).

%% gen_server callbacks
-export([init/1, terminate/2, code_change/3,
         handle_call/3, handle_cast/2, handle_info/2]).

start_link(Name) ->
    gen_server:start_link({local, name_to_server_name(Name)},
                          ?MODULE, Name, []).

reconfig(PoolName, PoolConfig) ->
    gen_server:call(name_to_server_name(PoolName),
                    {reconfig, PoolName, PoolConfig}).

reconfig(PoolPid, PoolName, PoolConfig) ->
    gen_server:call(PoolPid,
                    {reconfig, PoolName, PoolConfig}).

bucket_choose_addr({mc_pool_bucket, PoolName, BucketName}, Key) ->
    gen_server:call(name_to_server_name(PoolName),
                    {bucket_choose_addr, BucketName, Key}).

bucket_choose_addrs({mc_pool_bucket, PoolName, BucketName}, Key, N) ->
    gen_server:call(name_to_server_name(PoolName),
                    {bucket_choose_addrs, BucketName, Key, N}).

% -------------------------------------------------------

init(Name) -> build_pool(Name, ns_config:get()).

terminate(_Reason, _State)     -> ok.
code_change(_OldVsn, State, _) -> {ok, State}.
handle_cast(stop, State)       -> {stop, shutdown, State}.
handle_info(_Info, State)      -> {noreply, State}.

handle_call({get_bucket, BucketId}, _From, State) ->
    case get_bucket(State, BucketId) of
        {ok, _Bucket} -> {reply, create_bucket_handle(State#mc_pool.id,
                                                      BucketId),
                          State};
        _             -> {reply, error, State}
    end;

handle_call({auth_to_bucket, Mech, AuthData}, _From, State) ->
    case auth_to_bucket(State, Mech, AuthData) of
        {ok, Bucket} -> {reply, create_bucket_handle(State#mc_pool.id,
                                                     mc_bucket:id(Bucket)),
                         State};
        _            -> {reply, error, State}
    end;

handle_call({bucket_choose_addr, BucketId, Key}, _From, State) ->
    case get_bucket(State, BucketId) of
        {ok, Bucket} -> {reply, mc_bucket:choose_addr(Bucket, Key),
                         State};
        _            -> {reply, error, State}
    end;

handle_call({bucket_choose_addrs, BucketId, Key, N}, _From, State) ->
    case get_bucket(State, BucketId) of
        {ok, Bucket} -> {reply, mc_bucket:choose_addrs(Bucket, Key, N),
                         State};
        _            -> {reply, error, State}
    end;

handle_call({reconfig, Name, WantPoolConfig}, _From,
            #mc_pool{config = CurrPoolConfig} = State) ->
    case WantPoolConfig =:= CurrPoolConfig of
        true -> {reply, ok, State};
        false ->
            case build_pool(Name, ns_config:get(), WantPoolConfig) of
                {ok, Pool} ->
                    {reply, ok, Pool};
                error ->
                    ns_log:log(?MODULE, 0002, "reconfig error: ~p", [Name]),
                    NoopPool = create(Name, [], [], []),
                    {reply, error, NoopPool}
            end
    end;

handle_call(_, _From, State) ->
    {reply, ok, State}.

%% API for pool.

create(Id, Addrs, Config, Buckets) ->
    #mc_pool{id = Id, addrs = Addrs, config = Config, buckets = Buckets}.

build_pool(Name, NSConfig) ->
    case ns_config:search_prop(NSConfig, pools, Name) of
        undefined ->
            ns_log:log(?MODULE, 0001, "missing pool config: ~p", [Name]),
            error;
        PoolConfig ->
            build_pool(Name, NSConfig, PoolConfig)
    end.

build_pool(Name, NSConfig, PoolConfig) ->
    case ns_port_server:get_port_server_param(NSConfig, memcached, "-p") of
        false ->
            ns_log:log(?MODULE, 0003, "missing memcached port"),
            error;
        {value, MemcachedPortStr} ->
            MP = list_to_integer(MemcachedPortStr),
            Nodes = ns_node_disco:nodes_actual_proper(),
            create_pool(Name, PoolConfig, MP, Nodes)
    end.

create_pool(Name, PoolConfig, MemcachedPort, Nodes) ->
    % {buckets, [
    %   {"default", [
    %     {auth_plain, undefined},
    %     {size_per_node, 64}, % In MB.
    %     {cache_expiration_range, {0,600}}
    %   ]}
    % ]}
    BucketConfigs = proplists:get_value(buckets, PoolConfig, []),
    Buckets =
        lists:foldl(
          fun({BucketName, BucketConfig}, Acc) ->
                  case mc_bucket:get_bucket_auth(BucketConfig) of
                      error -> Acc;
                      BucketAuth ->
                          BucketAddrs = nodes_to_addrs(Nodes, MemcachedPort,
                                                       binary,
                                                       BucketAuth),
                          Bucket = mc_bucket:create(BucketName,
                                                    BucketAddrs,
                                                    BucketConfig,
                                                    BucketAuth),
                          [Bucket | Acc]
                  end;
             (X, Acc) ->
                  ns_log:log(?MODULE, 0004, "bucket config error: ~p", [X]),
                  Acc
          end,
          [], BucketConfigs),
    PoolAddrs = nodes_to_addrs(Nodes, MemcachedPort, binary, undefined),
    Pool = create(Name, PoolAddrs, PoolConfig, Buckets),
    {ok, Pool}.

% Returns {ok, Bucket} or false.

get_bucket({mc_pool, Name}, BucketId) ->
    gen_server:call(name_to_server_name(Name), {get_bucket, BucketId});

get_bucket(PoolPid, BucketId) when is_pid(PoolPid) ->
    gen_server:call(PoolPid, {get_bucket, BucketId});

get_bucket(#mc_pool{buckets = Buckets}, BucketId) ->
    search_bucket(BucketId, Buckets).

auth_to_bucket({mc_pool, Name}, Mech, AuthData) ->
    gen_server:call(name_to_server_name(Name),
                    {auth_to_bucket, Mech, AuthData});

auth_to_bucket(PoolPid, Mech, AuthData) when is_pid(PoolPid) ->
    gen_server:call(PoolPid,
                    {auth_to_bucket, Mech, AuthData});

auth_to_bucket(#mc_pool{} = Pool,
               "PLAIN", {BucketName, AuthName, AuthPswd}) ->
    case get_bucket(Pool, BucketName) of
        {ok, Bucket} ->
            case mc_bucket:auth(Bucket) of
                {"PLAIN", {AuthName, AuthPswd}} -> {ok, Bucket};
                {"PLAIN", {_ForName,
                           AuthName, AuthPswd}} -> {ok, Bucket};
                _NotPlain                       -> error
            end;
        _ -> error
    end;

auth_to_bucket(#mc_pool{}, _Mech, _AuthData) ->
    error.

% ------------------------------------------------

name_to_server_name(Name) ->
    list_to_atom(atom_to_list(?MODULE) ++ "-" ++ Name).

% A bucket handle allows an extra level of indirection, so we can
% change our bucket state independently of the caller's immutable
% handle.

create_bucket_handle(PoolId, BucketId) ->
    {mc_pool_bucket, PoolId, BucketId}.

nodes_to_addrs(Nodes, Port, Kind, Auth) ->
    PortStr = integer_to_list(Port),
    lists:map(fun(Node) ->
                  % Node is an atom like some_name@host.foo.bar.com
                  [_Name, Host | _] = string:tokens(atom_to_list(Node), "@"),
                  Location = lists:concat([Host, ":", PortStr]),
                  mc_addr:create(Location, Kind, Auth)
              end,
              Nodes).

% ------------------------------------------------

search_bucket(_BucketId, []) -> false;
search_bucket(BucketId, [Bucket | Rest]) ->
    case mc_bucket:id(Bucket) =:= BucketId of
        true  -> {ok, Bucket};
        false -> search_bucket(BucketId, Rest)
    end.

foreach_bucket(#mc_pool{buckets = Buckets}, VisitorFun) ->
    lists:foreach(VisitorFun, Buckets).

% ------------------------------------------------

get_bucket_test() ->
    B1 = mc_bucket:create("default", [mc_addr:local(ascii)], []),
    Addrs = [mc_addr:local(ascii)],
    P1 = create(p1, Addrs, config,
                [mc_bucket:create("default", Addrs, [])]),
    ?assertMatch({ok, B1}, get_bucket(P1, "default")),
    ok.

foreach_bucket_test() ->
    B1 = mc_bucket:create("default", [mc_addr:local(ascii)], []),
    Addrs = [mc_addr:local(ascii)],
    P1 = create(p1, Addrs, config,
                [mc_bucket:create("default", Addrs, [])]),
    foreach_bucket(P1, fun (B) ->
                           ?assertMatch(B1, B)
                       end),
    ok.

