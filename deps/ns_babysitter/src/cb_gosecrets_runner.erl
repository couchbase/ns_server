%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_gosecrets_runner).

-behaviour(gen_server).

-include("ns_common.hrl").
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0, start_link/1]).
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-export([decrypt/2,
         encrypt/2,
         change_password/2,
         get_keys_ref/1,
         rotate_data_key/1,
         maybe_clear_backup_key/2,
         get_state/1,
         os_pid/1]).

data_key_store_path() ->
    filename:join(path_config:component_path(data, "config"), "encrypted_data_keys").

gosecrets_cfg_path() ->
    filename:join(path_config:component_path(data, "config"), "gosecrets.cfg").

port_file_path() ->
    filename:join(path_config:component_path(data),
                  "couchbase-server.babysitter.smport").

encrypt(Name, Data) ->
    gen_server:call(Name, {encrypt, Data}, infinity).

decrypt(Name, Data) ->
    gen_server:call(Name, {decrypt, Data}, infinity).

change_password(Name, NewPassword) ->
    gen_server:call(Name, {change_password, ?HIDE(NewPassword)}, infinity).

get_keys_ref(Name) ->
    gen_server:call(Name, get_keys_ref, infinity).

get_state(Name) ->
    gen_server:call(Name, get_state, infinity).

rotate_data_key(Name) ->
    gen_server:call(Name, rotate_data_key, infinity).

maybe_clear_backup_key(Name, DataKey) ->
    gen_server:call(Name, {maybe_clear_backup_key, DataKey}, infinity).

os_pid(Name) ->
    gen_server:call(Name, gosecrets_os_pid).

start_link() ->
    start_link(gosecrets_cfg_path()).

start_link(ConfigPath) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [ConfigPath], []).

prompt_the_password(State, Retries) ->
    StdIn =
        case application:get_env(handle_ctrl_c) of
            {ok, true} ->
                erlang:open_port({fd, 0, 1}, [in, stream, binary, eof]);
            _ ->
                undefined
        end,
    try
        prompt_the_password(State, Retries, StdIn)
    after
        case StdIn of
            undefined ->
                ok;
            _ ->
                port_close(StdIn)
        end
    end.

prompt_the_password(State, MaxRetries, StdIn) ->
    case open_udp_socket() of
        {ok, Socket} ->
            try
                save_port_file(Socket),
                prompt_the_password(State, MaxRetries, StdIn,
                                    Socket, _RetriesLeft = MaxRetries)
            after
                file:delete(port_file_path()),
                catch gen_udp:close(Socket)
            end;
        {error, Error} ->
            {error, {udp_socket_open_failed, Error}}
    end.

prompt_the_password(State, MaxRetries, StdIn, Socket, RetriesLeft) ->
    {ok, {Addr, Port}} = inet:sockname(Socket),
    ?log_debug("Waiting for the master password to be supplied (UDP: ~p:~b). "
               "Attempt ~p", [Addr, Port, MaxRetries - RetriesLeft + 1]),
    receive
        {StdIn, M} ->
            ?log_error("Password prompt interrupted: ~p", [M]),
            {error, interrupted};
        {udp, Socket, FromAddr, FromPort, Password} ->
            case call_init(?HIDE(Password), State) of
                ok ->
                    gen_udp:send(Socket, FromAddr, FromPort, <<"ok">>),
                    ok;
                {wrong_password, _} when RetriesLeft > 1 ->
                    gen_udp:send(Socket, FromAddr, FromPort, <<"retry">>),
                    timer:sleep(1000),
                    prompt_the_password(State, MaxRetries, StdIn,
                                        Socket, RetriesLeft - 1);
                {Reply, _Reason} when Reply == error;
                                      Reply == wrong_password  ->
                    gen_udp:send(Socket, FromAddr, FromPort, <<"auth_failure">>),
                    {error, auth_failure}
            end
    end.

init([GosecretsCfgPath]) ->
    DatakeyPath = data_key_store_path(),
    case filelib:is_file(GosecretsCfgPath) of
        true -> ok;
        false ->
            Cfg = {[{encryptionService,
                     {[{keyStorageType, file},
                       {keyStorageSettings,
                        {[{path, list_to_binary(DatakeyPath)},
                          {encryptWithPassword, true},
                          {passwordSource, env},
                          {passwordSettings,
                           {[{envName, <<"CB_MASTER_PASSWORD">>}]}}]}}]}}]},
            CfgJson = ejson:encode(Cfg),
            ?log_debug("Writing ~s: ~s", [GosecretsCfgPath, CfgJson]),
            case misc:atomic_write_file(GosecretsCfgPath, CfgJson) of
                ok -> ok;
                {error, Error} ->
                    ?log_error("Could not write file '~s': ~s (~p)",
                               [GosecretsCfgPath, file:format_error(Error),
                                Error]),
                    erlang:error({write_failed, GosecretsCfgPath, Error})
            end
    end,

    State = start_gosecrets(GosecretsCfgPath),

    HiddenPass =
        case application:get_env(master_password) of
            {ok, P} ->
                ?log_info("Trying to recover the password from application "
                          "environment"),
                P;
            _ ->
                ?HIDE("")
        end,

    init_gosecrets(HiddenPass, _MaxRetries = 3, State),

    {ok, State}.

init_gosecrets(HiddenPass, MaxRetries, State) ->
    case call_init(HiddenPass, State) of
        ok -> ok;
        {wrong_password, _} ->
            try
                case prompt_the_password(State, MaxRetries) of
                    ok ->
                        ok;
                    {error, Error} ->
                        ?log_error("Stopping babysitter because gosecrets "
                                   "password prompting has failed: ~p",
                                   [Error]),
                        ns_babysitter_bootstrap:stop(),
                        shutdown
                end
            catch
                C:E:ST ->
                    ?log_error("Unhandled exception: ~p~n~p", [E, ST]),
                    erlang:raise(C, E, ST)
            end;
        {error, Error} ->
            erlang:error({gosecrets_init_failed, Error})
    end.

call_init(HiddenPass, State) ->
    case call_gosecrets({init, HiddenPass}, State) of
        ok ->
            application:set_env(ns_babysitter, master_password, HiddenPass),
            ?log_info("Init complete. Password (if used) accepted."),
            ok;
        {error, "key decrypt failed:" ++ _ = Error} ->
            ?log_error("Incorrect master password. Error: ~p", [Error]),
            {wrong_password, Error};
        {error, Error} ->
            ?log_error("Gosecrets initialization failed: ~s", [Error]),
            {error, Error}
    end.

handle_call({encrypt, Data}, _From, State) ->
    {reply, call_gosecrets({encrypt, Data}, State), State};
handle_call({decrypt, Data}, _From, State) ->
    {reply,
     case call_gosecrets({decrypt, Data}, State) of
         ok ->
             {ok, <<>>};
         Ret ->
             Ret
     end, State};
handle_call({change_password, HiddenPass}, _From, State) ->
    Reply = call_gosecrets({change_password, HiddenPass}, State),
    case Reply of
        ok ->
            application:set_env(ns_babysitter, master_password, HiddenPass),
            ok;
        {error, _} ->
            ok
    end,
    {reply, Reply, State};
handle_call(get_keys_ref, _From, State) ->
    {reply, call_gosecrets(get_keys_ref, State), State};
handle_call(get_state, _From, State) ->
    {reply, call_gosecrets(get_state, State), State};
handle_call(rotate_data_key, _From, State) ->
    {reply, call_gosecrets(rotate_data_key, State), State};
handle_call({maybe_clear_backup_key, DataKey}, _From, State) ->
    {reply, call_gosecrets({maybe_clear_backup_key, DataKey}, State), State};
handle_call(gosecrets_os_pid, _From, State) ->
    Res = case call_gosecrets({port_info, os_pid}, State) of
              {os_pid, P} -> P;
              undefined -> undefined
          end,
    {reply, Res, State};
handle_call(Call, _From, State) ->
    ?log_warning("Unhandled call: ~p", [Call]),
    {reply, {error, not_allowed}, State}.

handle_cast(Msg, State) ->
    ?log_warning("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(Info, State) ->
    ?log_warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

start_gosecrets(CfgPath) ->
    Parent = self(),
    {ok, Pid} =
        proc_lib:start_link(
          erlang, apply,
          [fun () ->
                   process_flag(trap_exit, true),
                   Path = path_config:component_path(bin, "gosecrets"),
                   Args = ["--config", CfgPath],
                   ?log_debug("Starting ~p with args: ~0p", [Path, Args]),
                   Port =
                       open_port(
                         {spawn_executable, Path},
                         [{packet, 4}, binary, hide, {args, Args}]),
                   proc_lib:init_ack({ok, self()}),
                   gosecrets_loop(Port, Parent)
           end, []]),
    ?log_debug("Gosecrets loop started with pid = ~p", [Pid]),
    Pid.

call_gosecrets(Msg, Pid) ->
    Pid ! {call, Msg},
    receive
        {reply, Resp} ->
            Resp
    end.

gosecrets_loop(Port, Parent) ->
    receive
        {call, {port_info, I}} ->
            Parent ! {reply, erlang:port_info(Port, I)},
            gosecrets_loop(Port, Parent);
        {call, Msg} ->
            Port ! {self(), {command, encode(Msg)}},
            wait_call_resp(Port, Parent),
            gosecrets_loop(Port, Parent);
        {Port, {data, <<"L", Data/binary>>}} ->
            handle_gosecrets_log(Data),
            gosecrets_loop(Port, Parent);
        Exit = {'EXIT', _, _} ->
            gosecret_process_exit(Port, Exit)
    end.

wait_call_resp(Port, Parent) ->
    receive
        Exit = {'EXIT', _, _} ->
            gosecret_process_exit(Port, Exit);
        {Port, {data, <<"L", Data/binary>>}} ->
            handle_gosecrets_log(Data),
            wait_call_resp(Port, Parent);
        {Port, {data, <<"S">>}} ->
            Parent ! {reply, ok};
        {Port, {data, <<"S", Data/binary>>}} ->
            Parent ! {reply, {ok, Data}};
        {Port, {data, <<"E", Data/binary>>}} ->
            Parent ! {reply, {error, binary_to_list(Data)}}
    end.

handle_gosecrets_log(Data) ->
    ?log_debug("gosecrets: ~s", [Data]).

gosecret_process_exit(Port, Exit) ->
    ?log_debug("Received exit ~p for port ~p", [Exit, Port]),
    gosecret_do_process_exit(Port, Exit).

gosecret_do_process_exit(Port, {'EXIT', Port, Reason}) ->
    exit({port_terminated, Reason});
gosecret_do_process_exit(_Port, {'EXIT', _, Reason}) ->
    exit(Reason).

encode({init, HiddenPass}) ->
    BinaryPassword = list_to_binary(?UNHIDE(HiddenPass)),
    <<1, BinaryPassword/binary>>;
encode(get_keys_ref) ->
    <<2>>;
encode({encrypt, Data}) ->
    <<3, Data/binary>>;
encode({decrypt, Data}) ->
    <<4, Data/binary>>;
encode({change_password, HiddenPass}) ->
    BinaryPassword = list_to_binary(?UNHIDE(HiddenPass)),
    <<5, BinaryPassword/binary>>;
encode(rotate_data_key) ->
    <<6>>;
encode({maybe_clear_backup_key, DataKey}) ->
    <<7, DataKey/binary>>;
encode(get_state) ->
    <<8>>.

save_port_file(Socket) ->
    {ok, {Addr, Port}} = inet:sockname(Socket),
    AFBin = case size(Addr) of
                4 -> <<"inet">>;
                8 -> <<"inet6">>
            end,
    PortBin = integer_to_binary(Port),
    misc:atomic_write_file(port_file_path(),
                           <<AFBin/binary, " ", PortBin/binary>>).

open_udp_socket() ->
    case open_udp_socket(inet) of
        {ok, S} ->
            {ok, S};
        {error, Reason1} ->
            ?log_warning("Failed to open TCPv4 UDP port: ~p", [Reason1]),
            case open_udp_socket(inet6) of
                {ok, S} ->
                    {ok, S};
                {error, Reason2} ->
                    ?log_error("Failed to open TCPv6 UDP port: ~p", [Reason2]),
                    {error, {Reason1, Reason2}}
            end
    end.

open_udp_socket(AFamily) ->
    gen_udp:open(0, [AFamily, {ip, loopback}, {active, true}]).

-ifdef(TEST).

default_config_encryption_test() ->
    with_gosecrets(
      undefined,
      fun (Pid) ->
          Data = rand:bytes(512),
          {ok, Encrypted1} = encrypt(Pid, Data),
          {ok, Encrypted2} = encrypt(Pid, Data),
          ?assert(Encrypted1 /= Encrypted2),
          {ok, Data} = decrypt(Pid, Encrypted1),
          {ok, Data} = decrypt(Pid, Encrypted2)
      end).

datakey_rotation_test() ->
    with_gosecrets(
      undefined,
      fun (Pid) ->
          Data = rand:bytes(512),
          Password = binary_to_list(rand:bytes(128)),
          {ok, Encrypted1} = encrypt(Pid, Data),
          ok = change_password(Pid, Password),
          {ok, Data} = decrypt(Pid, Encrypted1),
          {ok, Encrypted2} = encrypt(Pid, Data),
          ok = rotate_data_key(Pid),
          {ok, KeysRef} = get_keys_ref(Pid),
          {ok, Data} = decrypt(Pid, Encrypted1),
          {ok, Data} = decrypt(Pid, Encrypted2),
          {ok, Encrypted3} = encrypt(Pid, Data),
          {error, _} = rotate_data_key(Pid),
          maybe_clear_backup_key(Pid, KeysRef),
          {error, _} = decrypt(Pid, Encrypted1),
          {error, _} = decrypt(Pid, Encrypted2),
          {ok, Data} = decrypt(Pid, Encrypted3),
          ok = rotate_data_key(Pid)
      end).

with_gosecrets(Cfg, Fun) ->
    with_tmp_cfg(
      Cfg,
      fun (CfgPath) ->
          {ok, Pid} = start_link(CfgPath),
          try
              Fun(Pid)
          after
              unlink(Pid),
              exit(Pid, shutdown)
          end
      end).

with_tmp_cfg(Cfg, Fun) ->
    %% If previous tests finish ungracefully, they can leave default data key
    %% file on disk. Removing it here.
    file:delete(data_key_store_path()),
    CfgPath = path_config:tempfile("gosecrets", ".cfg"),
    try
        case Cfg of
            undefined -> ok;
            _ -> ok = misc:atomic_write_file(CfgPath, ejson:encode(Cfg))
        end,
        Fun(CfgPath)
    after
        file:delete(data_key_store_path()),
        file:delete(CfgPath)
    end.


-endif.
