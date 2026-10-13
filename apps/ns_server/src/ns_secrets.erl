%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(ns_secrets).

-behaviour(gen_server).

%% API
-export([start_link/0,
         get_pkey_pass/1,
         get_cert_and_pkey/1,
         format_error/1,
         load_pkey/2,
         extract_pkey_pass/1,
         is_pkey_pass_set/1,
         call_external_script/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% The loaded certs and keys are kept in this table, so that they can be read
%% without calling ns_secrets, which would make every TLS connection wait for
%% the others, and for a key being loaded.
-define(CERT_AND_PKEY_TABLE, ns_secrets_cert_and_pkey).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Loads the passphrase of the private key of Type, and the key itself, which
%% is decrypted here, so that it isn't decrypted for every TLS connection
%% that uses it, along with the certificate chain of Type, so that the chain
%% and the key that are used together always match. Is to be called whenever
%% the certificate, the key or its passphrase change.
%%
%% Caution: must be called by the ns_ssl_services_setup process only. That is
%% the process that writes the cert and key files, so they can't be written
%% while they are read here. Called by another process, it could read the
%% chain and the key of different certs.
load_pkey(Type, PassSettings) when is_list(PassSettings) ->
    gen_server:call(?MODULE,
                    {load_pkey, Type, fun () -> PassSettings end},
                    30000).

get_pkey_pass(Type) when Type == node_cert; Type == client_cert ->
    gen_server:call(?MODULE, {get_pkey_pass, Type}, 30000).

%% Returns a fun that returns {ok, {Chain, Key}}, Chain being the certificate
%% chain of Type, as a list of der encoded certificates, the way ssl's cert
%% option takes it, and Key being the decrypted private key of Type, loaded
%% along with Chain, as {KeyType, Der}, the way ssl's key option takes it. Or
%% {error, Reason} if they couldn't be loaded. They are hidden in a fun so
%% that the key doesn't get printed when the state of a process holding it
%% does.
get_cert_and_pkey(Type) when Type == node_cert; Type == client_cert ->
    try ets:lookup(?CERT_AND_PKEY_TABLE, Type) of
        [{Type, CertAndKeyFun}] -> CertAndKeyFun;
        [] -> ?HIDE({error, not_loaded})
    catch
        %% ns_secrets is not running
        error:badarg -> ?HIDE({error, not_loaded})
    end.

%% Describes Reason, an error that get_cert_and_pkey/1 can give, for error
%% messages
format_error(not_loaded) ->
    "The certificate and private key have not been loaded yet";
format_error({cannot_read_keyfile, File, Reason}) ->
    io_lib:format("Unable to read private key file ~s: ~s",
                  [File, file:format_error(Reason)]);
format_error({cannot_read_certfile, File, Reason}) ->
    io_lib:format("Unable to read certificate chain file ~s: ~s",
                  [File, file:format_error(Reason)]);
format_error({invalid_certfile, File, no_certificates}) ->
    io_lib:format("Certificate chain file ~s contains no certificates",
                  [File]);
format_error({invalid_certfile, File, Reason}) ->
    io_lib:format("Invalid certificate chain file ~s: ~p", [File, Reason]);
format_error(could_not_decrypt) ->
    "Failed to decrypt the private key. Check its passphrase settings";
format_error(malformed_pkey) ->
    "Malformed or unsupported private key format";
format_error(too_many_pkey_entries) ->
    "The private key file contains an incorrect number of entries";
format_error({invalid_pkey, Type}) ->
    io_lib:format("Invalid private key type: ~p", [Type]);
format_error({invalid_pkey_cipher, _}) ->
    "Invalid private key cipher. Only PKCS#5 v2.0 algorithms are supported";
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

is_pkey_pass_set(PassSettings) ->
    undefined /= proplists:get_value(type, PassSettings).

%%%===================================================================
%%% callbacks
%%%===================================================================

init([]) ->
    ?CERT_AND_PKEY_TABLE = ets:new(?CERT_AND_PKEY_TABLE,
                                   [named_table, protected, set,
                                    {read_concurrency, true}]),
    {ok, #{}}.

handle_call({load_pkey, Type, PassSettingsFun}, _From, State) ->
    Fun = case extract_pkey_pass(PassSettingsFun()) of
              {ok, F} -> F;
              {error, _} -> fun () -> undefined end
          end,
    %% The chain and the key read here match, as long as this is called by
    %% ns_ssl_services_setup only (see load_pkey/2)
    Key = read_pkey(ns_ssl_services_setup:pkey_file_path(Type), Fun),
    Chain = read_cert_chain(ns_ssl_services_setup:chain_file_path(Type)),
    CertAndKey = case {Chain, Key} of
                     {{ok, C}, {ok, K}} -> {ok, {C, K}};
                     {_, {error, _} = Error} -> Error;
                     {{error, _} = Error, _} -> Error
                 end,
    true = ets:insert(?CERT_AND_PKEY_TABLE, {Type, ?HIDE(CertAndKey)}),
    {reply, ok, State#{{pkey_passphrase_fun, Type} => Fun}};
handle_call({get_pkey_pass, Type}, _From, State) ->
    Res = maps:get({pkey_passphrase_fun, Type}, State, fun () -> undefined end),
    {reply, Res, State};
handle_call(_Request, _From, State) ->
    {reply, unhandled, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Returns {ok, Key}, Key being the private key in File, validated and
%% decrypted with the passphrase PassFun returns, or {error, Reason}.
read_pkey(File, PassFun) ->
    case file:read_file(File) of
        {ok, Pem} ->
            ns_server_cert:decrypt_pkey(Pem, PassFun);
        {error, Reason} ->
            {error, {cannot_read_keyfile, File, Reason}}
    end.

%% Returns {ok, Chain}, Chain being the certificates in File, der encoded, or
%% {error, Reason}.
read_cert_chain(File) ->
    case file:read_file(File) of
        {ok, Pem} ->
            case ns_server_cert:decode_cert_chain(Pem) of
                {ok, []} ->
                    {error, {invalid_certfile, File, no_certificates}};
                {ok, Chain} ->
                    {ok, Chain};
                {error, Reason} ->
                    {error, {invalid_certfile, File, Reason}}
            end;
        {error, Reason} ->
            {error, {cannot_read_certfile, File, Reason}}
    end.

extract_pkey_pass(PassSettings) ->
    case proplists:get_value(type, PassSettings) of
        plain ->
            P = proplists:get_value(password, PassSettings),
            {ok, fun () -> binary_to_list(P) end};
        script ->
            extract_pkey_pass_with_script(PassSettings);
        rest ->
            extract_pkey_pass_with_rest(PassSettings);
        undefined ->
            {ok, fun () -> undefined end}
    end.

extract_pkey_pass_with_rest(PassSettings) ->
    URL = binary_to_list(proplists:get_value(url, PassSettings)),
    Timeout = proplists:get_value(timeout, PassSettings),
    AddrSettings = case proplists:get_value(addressFamily, PassSettings) of
                       undefined -> [];
                       AF -> [AF]
                   end,
    HttpsOpts = proplists:get_value(httpsOpts, PassSettings),
    VerifySettings = case HttpsOpts of
                         undefined -> [];
                         _ ->
                             case proplists:get_value(verifyPeer, HttpsOpts,
                                                      true) of
                                 true ->
                                     CA = ns_ssl_services_setup:ca_file_path(),
                                     [{verify, verify_peer}, {cacertfile, CA}];
                                 false ->
                                     [{verify, verify_none}]
                             end
                     end,
    Options = AddrSettings ++ VerifySettings,
    Headers = proplists:get_value(headers, PassSettings, []),
    ?log_info("Calling REST API: ~s", [URL]),
    try rest_utils:request(<<"pkey_passphrase">>, URL, "GET", Headers, <<>>,
                           Timeout, [{connect_options, Options}]) of
        {ok, {{Status, _}, _RespHeaders, RespBody}} when Status == 200 ->
            ?log_info("PKey passphrase REST API call ~s succeded", [URL]),
            {ok, fun () -> binary_to_list(RespBody) end};
        {ok, {{Status, Reason}, _RespHeaders, _RespBody}} ->
            ?log_error("PKey passphrase REST API call ~s returned ~p ~p",
                       [URL, Status, Reason]),
            {error, {rest_failed, URL, {status, Status}}};
        {error, Reason} ->
            ?log_error("PKey passphrase REST API call ~s failed, reason:~n~p",
                       [URL, Reason]),
            {error, {rest_failed, URL, {error, Reason}}}
    catch
        _:E:ST ->
            ?log_error("PKey passphrase REST API call ~s crashed~n"
                       "Exception: ~p~n"
                       "Stacktrace: ~p", [URL, E, ST]),
            {error, {rest_failed, URL, exception}}
    end.

extract_pkey_pass_with_script(PassSettings) ->
    Path = proplists:get_value(path, PassSettings),
    Trim = proplists:get_value(trim, PassSettings),
    Args = proplists:get_value(args, PassSettings),
    Timeout = proplists:get_value(timeout, PassSettings),
    ?log_info("Calling external script to extract pkey passphrase: ~s~n"
              "Args: ~p~nTimeout: ~p", [Path, Args, Timeout]),
    try call_external_script(Path, Args, undefined, Timeout) of
        {0, P} ->
            MaybeTrimmed = case Trim of
                               true -> string:trim(P);
                               false -> P
                           end,
            ?log_info("Script executed successfully"),
            {ok, fun () -> binary_to_list(MaybeTrimmed) end};
        {Status, Output} ->
            ?log_error("External pkey passphrase script ~s ~p finished "
                       "with exit status: ~p:~n~s",
                       [Path, Args, Status, Output]),
            {error, {script_execution_failed, {status, Status, Output}}}
    catch
        _:E:ST when E =:= eacces ->
            ?log_error("Do not have permission to execute the file in ~s."
                       "~nArgs: ~p~nException: ~p~n"
                       "Stacktrace: ~p", [Path, Args, E, ST]),
            {error, {script_execution_failed, {reason, "Not "
                       "enough permission to run the file"}}};
        _:E:ST ->
            ?log_error("External pkey passphrase script execution "
                       "exception: ~s~nArgs: ~p~nException: ~p~n"
                       "Stacktrace: ~p", [Path, Args, E, ST]),
            {error, {script_execution_failed, exception}}
    end.

call_external_script(Path, Args, HiddenInput, Timeout) ->
    %% Execute on new process to contain the port exit after executable
    %% completes and exits
    misc:executing_on_new_process(
      fun() ->
              Port = erlang:open_port({spawn_executable, Path},
                                      [stderr_to_stdout, binary,
                                       stream, exit_status, hide,
                                       {args, Args}]),
              StartTime = erlang:system_time(millisecond),
              Deadline = StartTime + Timeout,
              case HiddenInput of
                  undefined -> ok;
                  _ -> port_command(Port, ?UNHIDE(HiddenInput))
              end,
              wait_for_exit(Port, <<>>, Deadline)
      end).

wait_for_exit(Port, Output, Deadline) ->
    Now = erlang:system_time(millisecond),
    Timeout = max(Deadline - Now, 0),
    receive
        {Port, {data, Data}} ->
            wait_for_exit(Port, <<Output/binary, Data/binary>>, Deadline);
        {Port, {exit_status, Status}} ->
            {Status, Output}
    after Timeout ->
        port_close(Port),
        error(timeout)
    end.

-ifdef(TEST).
read_pkey_test_() ->
    {foreach,
     fun () -> path_config:tempfile("read_pkey_test", ".pem") end,
     fun (File) -> file:delete(File) end,
     [fun (File) -> ?_test(read_pkey_encrypted(File)) end,
      fun (File) -> ?_test(read_pkey_not_encrypted(File)) end,
      fun (File) -> ?_test(read_pkey_wrong_passphrase(File)) end,
      fun (File) -> ?_test(read_pkey_no_file(File)) end]}.

read_pkey_test_key() ->
    public_key:generate_key({rsa, 2048, 65537}).

read_pkey_test_pem(Key) ->
    public_key:pem_encode(
      [public_key:pem_entry_encode('PrivateKeyInfo', Key)]).

read_pkey_test_assert_key(Key, {ok, {KeyType, KeyDer}}) ->
    ?assertEqual(Key, public_key:pem_entry_decode({KeyType, KeyDer,
                                                   not_encrypted})).

read_pkey_encrypted(File) ->
    Key = read_pkey_test_key(),
    ok = file:write_file(File,
                         ns_server_cert:encrypt_pkey(read_pkey_test_pem(Key),
                                                     ?HIDE("secret"))),
    read_pkey_test_assert_key(Key, read_pkey(File, ?HIDE("secret"))).

read_pkey_not_encrypted(File) ->
    Key = read_pkey_test_key(),
    ok = file:write_file(File, read_pkey_test_pem(Key)),
    read_pkey_test_assert_key(Key, read_pkey(File, ?HIDE(undefined))).

read_pkey_wrong_passphrase(File) ->
    ok = file:write_file(File,
                         ns_server_cert:encrypt_pkey(
                           read_pkey_test_pem(read_pkey_test_key()),
                           ?HIDE("secret"))),
    ?assertEqual({error, could_not_decrypt},
                 read_pkey(File, ?HIDE("wrong"))).

read_pkey_no_file(File) ->
    ?assertEqual({error, {cannot_read_keyfile, File, enoent}},
                 read_pkey(File, ?HIDE("secret"))).

cert_and_pkey_table_test() ->
    ChainFile = path_config:tempfile("cert_and_pkey_table_test", ".pem"),
    KeyFile = path_config:tempfile("cert_and_pkey_table_test", ".pem"),
    CertOpts = [{key, {rsa, 2048, 65537}}, {digest, sha256}],
    Chain = #{root => CertOpts, intermediates => [], peer => CertOpts},
    #{server_config := Config} =
        public_key:pkix_test_data(#{server_chain => Chain,
                                    client_chain => Chain}),
    Cert = proplists:get_value(cert, Config),
    {KeyType, KeyDer} = Key = proplists:get_value(key, Config),
    ok = file:write_file(ChainFile,
                         public_key:pem_encode(
                           [{'Certificate', Cert, not_encrypted}])),
    ok = file:write_file(KeyFile,
                         public_key:pem_encode(
                           [{KeyType, KeyDer, not_encrypted}])),
    meck:new(ns_ssl_services_setup, [passthrough]),
    try
        meck:expect(ns_ssl_services_setup, chain_file_path,
                    fun (node_cert) -> ChainFile end),
        meck:expect(ns_ssl_services_setup, pkey_file_path,
                    fun (node_cert) -> KeyFile end),
        %% ns_secrets is not running
        ?assertEqual({error, not_loaded}, (get_cert_and_pkey(node_cert))()),
        {ok, Pid} = gen_server:start({local, ?MODULE}, ?MODULE, [], []),
        try
            ?assertEqual({error, not_loaded},
                         (get_cert_and_pkey(node_cert))()),
            ok = load_pkey(node_cert, []),
            ?assertEqual({ok, {[Cert], Key}},
                         (get_cert_and_pkey(node_cert))()),
            ?assertEqual({error, not_loaded},
                         (get_cert_and_pkey(client_cert))()),
            %% Reading them doesn't involve ns_secrets
            ok = sys:suspend(Pid),
            ?assertEqual({ok, {[Cert], Key}},
                         (get_cert_and_pkey(node_cert))()),
            ok = sys:resume(Pid)
        after
            gen_server:stop(Pid)
        end
    after
        meck:unload(ns_ssl_services_setup),
        file:delete(ChainFile),
        file:delete(KeyFile)
    end.

read_cert_chain_test_() ->
    {foreach,
     fun () -> path_config:tempfile("read_cert_chain_test", ".pem") end,
     fun (File) -> file:delete(File) end,
     [fun (File) -> ?_test(read_cert_chain_ok(File)) end,
      fun (File) -> ?_test(read_cert_chain_invalid(File)) end,
      fun (File) -> ?_test(read_cert_chain_no_file(File)) end]}.

read_cert_chain_ok(File) ->
    CertOpts = [{key, {rsa, 2048, 65537}}, {digest, sha256}],
    #{server_config := Config} =
        public_key:pkix_test_data(
          #{server_chain => #{root => CertOpts, intermediates => [CertOpts],
                              peer => CertOpts},
            client_chain => #{root => CertOpts, intermediates => [],
                              peer => CertOpts}}),
    Cert = proplists:get_value(cert, Config),
    [Intermediate | _] = proplists:get_value(cacerts, Config),
    ok = file:write_file(File,
                         public_key:pem_encode(
                           [{'Certificate', Cert, not_encrypted},
                            {'Certificate', Intermediate, not_encrypted}])),
    ?assertEqual({ok, [Cert, Intermediate]}, read_cert_chain(File)).

read_cert_chain_invalid(File) ->
    ok = file:write_file(File, <<"not a certificate">>),
    ?assertMatch({error, {invalid_certfile, File, _}}, read_cert_chain(File)).

read_cert_chain_no_file(File) ->
    ?assertEqual({error, {cannot_read_certfile, File, enoent}},
                 read_cert_chain(File)).
format_error_test() ->
    F = fun (R) -> lists:flatten(format_error(R)) end,
    ?assertEqual("Failed to decrypt the private key. Check its passphrase "
                 "settings", F(could_not_decrypt)),
    ?assertEqual("Unable to read private key file /a/pkey.pem: no such file "
                 "or directory",
                 F({cannot_read_keyfile, "/a/pkey.pem", enoent})),
    ?assertEqual("Certificate chain file /a/chain.pem contains no "
                 "certificates",
                 F({invalid_certfile, "/a/chain.pem", no_certificates})),
    ?assertEqual("Invalid private key type: dsa", F({invalid_pkey, dsa})),
    ?assertEqual("{unknown,error}", F({unknown, error})).
-endif.
