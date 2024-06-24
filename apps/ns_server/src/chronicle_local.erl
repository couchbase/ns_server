%% @author Couchbase <info@couchbase.com>
%% @copyright 2018-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(chronicle_local).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include("ns_config.hrl").
-include_lib("ns_common/include/cut.hrl").
-include_lib("ale/include/ale.hrl").
-include("cb_cluster_secrets.hrl").

-export([start_link/0,
         init/1,
         handle_call/3,
         handle_info/2,
         prepare_join/1,
         join_cluster/1,
         leave_cluster/0,
         rename/1,
         get_snapshot/1,
         sync/0,
         get_encryption/1,
         set_active_dek/1]).

%% exported callbacks used by chronicle
-export([log/4, report_stats/1, encrypt_data/1, decrypt_data/1,
         external_decrypt/1]).

%% exported for log formatting
-export([format_msg/2, format_time/1]).

-define(CALL_TIMEOUT, ?get_timeout(call, 180000)).

% External term format always starts with 131, so
% it is important to not use 131 here, otherwise any
% number should work
-define(ENCRYPTION_MAGIC, 45).

start_link() ->
    gen_server2:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    application:set_env(chronicle, data_dir,
                        path_config:component_path(data, "config")),
    application:set_env(chronicle, logger_function, {?MODULE, log}),

    case misc:get_env_default(enable_chronicle_stats, true) of
        true ->
            application:set_env(chronicle,
                                stats_function, {?MODULE, report_stats});
        false ->
            ok
    end,

    ok = read_and_set_data_keys(),

    application:set_env(chronicle, encrypt_function, {?MODULE, encrypt_data}),
    application:set_env(chronicle, decrypt_function, {?MODULE, decrypt_data}),

    ?log_debug("Ensure chronicle is started"),
    ok = application:ensure_started(chronicle, permanent),

    ChronicleState = chronicle:get_system_state(),
    ?log_debug("Chronicle state is: ~p", [ChronicleState]),

    case ChronicleState of
        not_provisioned ->
            provision();
        _ ->
            ok
    end,

    case dist_manager:need_fixup() of
        {true, OldNode} ->
            ?log_info("Aborted rename from ~p was detected", [OldNode]),
            handle_rename(OldNode);
        false ->
            ok
    end,
    {ok, []}.

handle_call({prepare_join, Info}, _From, State) ->
    ?log_debug("Wiping chronicle before prepare join."),
    ok = chronicle:wipe(),
    case Info of
        undefined ->
            ?log_debug("Joining not chronicle enabled cluster"),
            provision();
        _ ->
            ?log_debug("Prepare join. Info: ~p", [Info]),
            ok = chronicle:prepare_join(Info)
    end,
    {reply, ok, State};
handle_call({join_cluster, Info}, _From, State) ->
    ?log_debug("Joining cluster. Info: ~p", [Info]),
    ok = chronicle:join_cluster(Info),
    {reply, ok, State};
handle_call(leave_cluster, _From, State) ->
    handle_leave(),
    {reply, ok, State};
handle_call({rename, OldNode}, _From, State) ->
    handle_rename(OldNode),
    {reply, ok, State};
handle_call(get_snapshot, _From, Pid) ->
    RV =
        try chronicle_kv:get_full_snapshot(kv) of
            {ok, {Snapshot, _}} ->
                {ok, Snapshot}
        catch T:E:S ->
                ?log_debug("Unable to obtain chronicle snapshot:~n~p",
                           [{T, E, S}]),
                {error, cannot_get_snapshot}
        end,
    {reply, RV, Pid};
handle_call({set_active_dek, NewActiveKey}, _From, State) ->
    set_active_dek_internal(NewActiveKey),
    {reply, ok, State};
handle_call(sync, _From, State) ->
    {reply, ok, State}.

handle_info(Message, State) ->
    ?log_debug("Ignoring unexpected message ~p", [Message]),
    {noreply, State}.

leave_cluster() ->
    gen_server2:call(?MODULE, leave_cluster, ?CALL_TIMEOUT).

prepare_join(Info) ->
    gen_server2:call(?MODULE, {prepare_join, Info}, ?CALL_TIMEOUT).

join_cluster(undefined) ->
    ok;
join_cluster(Info) ->
    gen_server2:call(?MODULE, {join_cluster, Info}, ?CALL_TIMEOUT).

rename(OldNode) ->
    gen_server2:call(?MODULE, {rename, OldNode}).

get_snapshot(Node) ->
    {ok, Snapshot} = gen_server2:call({?MODULE, Node}, get_snapshot,
                                      ?CALL_TIMEOUT),
    Snapshot.

sync() ->
    gen_server2:call(?MODULE, sync, ?CALL_TIMEOUT).

get_encryption(Snapshot) ->
    #{config_encryption := ConfigEncryptionSettings} =
        menelaus_web_encr_at_rest:get_settings(Snapshot),
    {ok, case ConfigEncryptionSettings of
             #{encryption := disabled} -> disabled;
             #{encryption := encryption_service} -> encryption_service;
             #{encryption := secret, secret_id := Id} -> {secret, Id}
         end}.

set_active_dek(ActiveDek) ->
    gen_server2:call(?MODULE, {set_active_dek, ActiveDek}, ?CALL_TIMEOUT).

provision() ->
    ?log_debug("Provision chronicle on this node"),
    try
        ok = chronicle:provision([{kv, chronicle_kv, []}]),
        chronicle_upgrade:maybe_initialize()
    catch
        E:T:S ->
            ?log_error("Provision chronicle failed on this node.~n"
                       "Error - ~p, Type - ~p, Stacktrace - ~p",
                       [E, T, S]),
            %% As a part of chronicle:provision/1, we do the following steps:
            %%
            %% 1. Add an entry to the append log with state = provisioned
            %% 2. Spawn all chronicle related processes such as
            %%    chronicle_leader, chronicle_server and
            %%    chronicle_single_rsm_sup'es (for chronicle_config_rsm and
            %%    chronicle_kv) etc via chronicle_secondary_sup.
            %% 3. Wait for the all the processes to be spawned in the step
            %%    above for 20 secs.
            %%
            %% And eventually seed the default keys in chronicle_kv.
            %%
            %% There is tight coupling between the internal state in
            %% chronicle_config and chronicle_secondary_sup and it's very hard
            %% to atomically perform all the above steps.
            %%
            %% If any of them fail, return to a clean slate and let retry do
            %% it's magic.
            ok = chronicle:wipe(),
            erlang:raise(E, T, S)
    end.

handle_leave() ->
    ?log_debug("Leaving cluster"),
    ok = chronicle:wipe(),
    provision().

handle_rename(OldNode) ->
    NewNode = node(),
    ?log_debug("Handle renaming from ~p to ~p", [OldNode, NewNode]),
    ok = chronicle:reprovision(),

    {ok, _} =
        chronicle_kv:rewrite(
          kv,
          fun (K, V) ->
                  case {misc:rewrite_value(OldNode, NewNode, K),
                        misc:rewrite_value(OldNode, NewNode, V)} of
                      {K, V} ->
                          keep;
                      {NewK, NewV} ->
                          {update, NewK, NewV}
                  end
          end).

log(Level, Fmt, Args, Info) ->
    AleLevel = case Level of
                   warning -> warn;
                   _ -> Level
               end,
    ale:xlog(?CHRONICLE_ALE_LOGGER, AleLevel, Info, Fmt, Args).

format_time(Time) ->
    ale_default_formatter:format_time(Time).

format_msg(#log_info{user_data = #{module := M, function := F, line := L}}
           = Info, UserMsg) ->
    ale_default_formatter:format_msg(
      Info#log_info{module = M, function = F, line = L}, UserMsg).

report_stats({histo, Metric, Max, Unit, Value}) ->
    ns_server_stats:notify_histogram(Metric, Max, Unit, Value);
report_stats({counter, Metric, By}) ->
    ns_server_stats:notify_counter(Metric, By);
report_stats({gauge, Metric, Value}) ->
    ns_server_stats:notify_gauge(Metric, Value);
report_stats({max, Metric, Window, Bucket, Value}) ->
    ns_server_stats:notify_max({Metric, Window, Bucket}, Value).

set_chronicle_encryption_keys(IVBase, IVAtomic, ActiveKey, Keys) ->
    ok = persistent_term:put(chronicle_encryption_keys,
                             {IVBase, IVAtomic, ActiveKey, Keys}).

get_chronicle_encryption_keys() ->
    persistent_term:get(chronicle_encryption_keys, undefined).

%% We assume that data is in erlang external term format, this is important
%% because that's how we determine if it is encrypted or not
encrypt_data(<<131, _/binary>> = D) ->
    {IVBase, IVAtomic, ActiveKey, _Keys} = get_chronicle_encryption_keys(),
    case ActiveKey of
        undefined -> D;
        #{type := 'raw-aes-gcm', info := #{key := K}} when is_function(K, 0) ->
            %% For GCM IV must be unique, and don't have to be unpredictable
            IVCounter = atomics:add_get(IVAtomic, 1, 1),
            IV = <<IVBase/binary, IVCounter:64/big-unsigned-integer>>,
            12 = size(IV),
            %% Tag size is 16 bytes as it is specified in requirements
            {Encrypted, Tag} = crypto:crypto_one_time_aead(
                                 aes_256_gcm, K(), IV, D, <<>>, 16, true),
            16 = size(Tag),
            Version = 1, % Version of encryption
            <<?ENCRYPTION_MAGIC, Version, IV/binary, Tag/binary,
              Encrypted/binary>>
    end.

decrypt_data(<<131, _/binary>> = D) -> {ok, D};
decrypt_data(<<?ENCRYPTION_MAGIC, 1, IV:12/binary, Tag:16/binary, D/binary>>) ->
    {_IVBase, _IVAtomic, _Active, Keys} = get_chronicle_encryption_keys(),
    try_decrypt(IV, Tag, D, Keys).

try_decrypt(_IV, _Tag, _D, []) ->
    {error, decrypt_error};
try_decrypt(IV, Tag, D, [#{type := 'raw-aes-gcm', info := #{key := K}} | T]) ->
    case crypto:crypto_one_time_aead(aes_256_gcm, K(), IV, D, <<>>, Tag,
                                     false) of
        error -> %% wrong key? try another one
            try_decrypt(IV, Tag, D, T);
        DecryptedData ->
            {ok, DecryptedData}
    end.

external_decrypt(Data) ->
    maybe
        ok ?= case get_chronicle_encryption_keys() of
                  undefined -> external_setup_keys();
                  {_, _, _, _} -> ok
              end,
        decrypt_data(Data)
    end.

external_setup_keys() ->
    %% In order to make path_config work
    application:load(ns_server),
    maybe
        {ok, _Active, KeyIdsBin, _, _} ?= cb_deks:external_list(chronicleDek),
        KeyIds = [binary_to_list(K) || K <- KeyIdsBin],
        {empty, [_ | _]} ?= {empty, KeyIds},
        ConfigDir =
            case os:getenv("CB_CONFIG_PATH") of
                false ->
                    path_config:component_path(data, "config");
                P ->
                    P
            end,
        GosecretsCfg = filename:join(ConfigDir, "gosecrets.cfg"),
        GosecretsPath = path_config:component_path(bin, "gosecrets"),
        Path = path_config:component_path(bin, "dump-keys"),
        {ok, DumpKeysPath} ?= case os:find_executable(Path) of
                                  false -> {error, {no_dump_keys, Path}};
                                  DKPath -> {ok, DKPath}
                              end,
        {0, Output} ?= ns_secrets:call_external_script(
                         DumpKeysPath,
                         ["--gosecrets", GosecretsPath,
                          "--config", GosecretsCfg,
                          "--key-kind", "chronicleDek",
                          "--key-ids"] ++ KeyIds,
                         60000),
        {JsonKeys} = ejson:decode(Output),
        Keys =
            lists:filtermap(
              fun ({Id, {Props}}) ->
                  case maps:from_list(Props) of
                      #{<<"result">> := <<"error">>,
                        <<"response">> := Error} ->
                          %% Not clear where to write the error; we can't use
                          %% logger here because this function can be called
                          %% from CLI
                          io:format("Error: ~s~n", [Error]),
                          false;
                      #{<<"result">> := <<"raw-aes-gcm">>,
                        <<"response">> := KeyProps} ->
                          {true, #{type => 'raw-aes-gcm',
                                   id => Id,
                                   info => encryption_service:decode_key_info(
                                             KeyProps)}}
                  end
              end, JsonKeys),
        set_chronicle_encryption_keys(undefined, undefined, not_needed, Keys),
        ok
    else
        {empty, []} ->
            set_chronicle_encryption_keys(undefined, undefined, not_needed, []),
            ok;
        {Status, ErrorsBin} when is_integer(Status) ->
            {error, {dump_keys_returned, Status, ErrorsBin}};
        {error, _} = Error ->
            Error
    end.

read_and_set_data_keys() ->
    maybe
        {ok, {ActiveId, Ids, IsEnabled}} ?= cb_deks:list(chronicleDek),
        {ok, Keys} ?= cb_deks:read(chronicleDek, Ids),
        {value, ActiveKey} =
            case IsEnabled of
                true ->
                    lists:search(fun (#{id := Id}) -> Id == ActiveId end, Keys);
                _ ->
                    {value, undefined}
            end,

        %% Random 4 byte base + unique 8 byte integer = unique 12 byte IV
        %% (note that atomics are 8 byte integers)
        IVBase = crypto:strong_rand_bytes(4),
        IVAtomic =
            case get_chronicle_encryption_keys() of
                undefined -> atomics:new(1, [{signed, false}]);
                {_OldIVBase, OldIVAtomic, _OldActive, _OldKeys} -> OldIVAtomic
            end,
        set_chronicle_encryption_keys(IVBase, IVAtomic, ActiveKey, Keys)
    else
        {error, Reason} ->
            ?log_error("Failed to set encryption keys for chronicle: ~p",
                       [Reason]),
            {error, Reason}
    end.

rewrite_chronicle_data() ->
    maybe
        %% The purpose of this function is to force chronicle to rewrite
        %% all files that contain sensitive data on disk.
        %% By doing so we can guarantee that all the chronicle data on disk
        %% is encrypted by the actual encryption key.
        %% The idea is to force snapshot creation two times. Since chronicle
        %% currently keeps last two logs on disk, creation of two snapshots
        %% should rewrite both of them.
        %% Modification of chronicle_key_snapshot_enforcer is needed just to
        %% make sure snapshot has changed since the last snapshot. Otherwise
        %% chronicle:force_snapshot() will do nothing.
        {ok, _} ?= chronicle_kv:set(kv, chronicle_key_snapshot_enforcer,
                                    crypto:strong_rand_bytes(8)),
        {ok, _} ?= chronicle:force_snapshot(),
        {ok, _} ?= chronicle_kv:set(kv, chronicle_key_snapshot_enforcer,
                                    crypto:strong_rand_bytes(8)),
        {ok, _} ?= chronicle:force_snapshot(),
        ok
    else
        {error, Reason} ->
            ?log_error("Failed to rewrite chronicle data: ~p", [Reason]),
            {error, Reason}
    end.

set_active_dek_internal(NewActive) ->
    {IVBase, IVAtomic, OldActive, OldKeys} = get_chronicle_encryption_keys(),
    GetId = fun (undefined) -> undefined;
                (#{id := Id}) -> Id
            end,
    OldId = GetId(OldActive),
    NewId = GetId(NewActive),
    case OldId == NewId of
        true -> %% nothing has changed
            ok;
        false ->
            NewKeys =
                case lists:search(fun (#{id := Id}) -> Id == NewId end,
                                  OldKeys) of
                    {value, _} -> OldKeys;
                    false -> [NewActive | OldKeys]
                end,
            ok = set_chronicle_encryption_keys(IVBase, IVAtomic, NewActive,
                                               NewKeys),
            ok = rewrite_chronicle_data(),
            case NewActive of
                undefined ->
                    ok = set_chronicle_encryption_keys(IVBase, IVAtomic,
                                                       undefined,
                                                       []);
                #{} ->
                    ok = set_chronicle_encryption_keys(IVBase, IVAtomic,
                                                       NewActive,
                                                       [NewActive])
            end
    end.
