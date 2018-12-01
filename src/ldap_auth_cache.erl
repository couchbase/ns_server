-module(ldap_auth_cache).

-behaviour(active_cache).

%% API
-export([start_link/0, authenticate/2, user_groups/1, flush/0]).

%% gen_server callbacks
-export([init/1, translate_options/1]).

-include("ns_common.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    active_cache:start_link(?MODULE, ?MODULE, [], opts()).

authenticate(Username, Pass) ->
    Key = {auth, {Username, crypto:hash(sha256, Pass)}},
    Fun = fun () -> ldap_auth:authenticate(Username, Pass) end,
    active_cache:get_value(?MODULE, Key, Fun).

user_groups(Username) ->
    Key = {groups, Username},
    Fun = fun () ->
                  case ldap_auth:user_groups(Username) of
                      {ok, L} -> L;
                      {error, Reason} -> erlang:error(Reason)
                  end
          end,
    active_cache:get_value(?MODULE, Key, Fun).

flush() ->
    active_cache:flush(?MODULE).

%%%===================================================================
%%% callbacks
%%%===================================================================

init([]) ->
    EventHandler =
        fun ({ldap_settings, _}) ->
                active_cache:reload_opts(?MODULE, update);
            ({external_auth_polling_interval, _}) ->
                active_cache:reload_opts(?MODULE, update);
            (_) -> ok
        end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),
    ok.

translate_options(_) -> opts().

%%%===================================================================
%%% Internal functions
%%%===================================================================

opts() ->
    Get = fun (K) -> ldap_util:get_setting(K) end,
    [{renew_interval, infinity},
     {max_size, Get(max_cache_size)},
     {value_lifetime, Get(cache_value_lifetime)},
     {max_parallel_procs, Get(max_parallel_connections)}].
