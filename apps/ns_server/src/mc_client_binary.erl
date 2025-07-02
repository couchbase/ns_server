%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(mc_client_binary).

-include("ns_common.hrl").
-include("mc_constants.hrl").
-include("mc_entry.hrl").

-define(MAX_MC_TIMEOUT, 300000).
%% we normally speak to local memcached when issuing delete
%% vbucket. Thus timeout needs to only cover ep-engine going totally
%% insane.
-define(VB_DELETE_TIMEOUT, ?MAX_MC_TIMEOUT).
-define(NO_BUCKET, "@no bucket@").

-export([auth/2,
         cmd/5,
         cmd_quiet/3,
         cmd_vocal/3,
         respond/3,
         create_bucket/5,
         delete_bucket/3,
         delete_vbucket/2,
         delete_vbuckets/2,
         sync_delete_vbucket/2,
         flush/1,
         hello_features/1,
         hello_features_map/0,
         hello/3,
         refresh_isasl/1,
         noop/1,
         select_bucket/2,
         pause_bucket/2,
         unpause_bucket/2,
         deselect_bucket/1,
         set_vbucket/3,
         set_vbucket/4,
         set_vbuckets/2,
         stats/1,
         stats/4,
         get_meta/4,
         update_with_rev/7,
         set_engine_param/4,
         enable_traffic/1,
         disable_traffic/1,
         set_bucket_data_ingress/3,
         get_dcp_docs_estimate/3,
         map_status/1,
         get_mass_dcp_docs_estimate/2,
         get_all_vb_seqnos/1,
         ext/2,
         set_cluster_config/5,
         get_random_key/2,
         compact_vbucket/6,
         wait_for_seqno_persistence/3,
         vbucket_state_to_atom/1,
         config_validate/2,
         config_reload/1,
         audit_put/3,
         audit_config_reload/1,
         refresh_rbac/1,
         subdoc_multi_lookup/6,
         get_failover_log/2,
         update_user_permissions/2,
         set_collections_manifest/2,
         get_collections_manifest/1,
         set_tls_config/2,
         set_active_encryption_key/4,
         prune_log_or_audit_encr_keys/4,
         get_fusion_storage_snapshot/4,
         mount_fusion_vbucket/3,
         set_chronicle_auth_token/2,
         start_fusion_uploader/3,
         stop_fusion_uploader/2,
         sync_fusion_log_store/2]).

-type recv_callback() :: fun((_, _, _) -> any()) | undefined.
-type mc_timeout() :: undefined | infinity | non_neg_integer().
-type mc_opcode() :: ?GET | ?SET | ?ADD | ?REPLACE | ?DELETE | ?INCREMENT |
                     ?DECREMENT | ?QUIT | ?FLUSH | ?GETQ | ?NOOP | ?VERSION |
                     ?GETK | ?GETKQ | ?APPEND | ?PREPEND | ?STAT | ?SETQ |
                     ?ADDQ | ?REPLACEQ | ?DELETEQ | ?INCREMENTQ | ?DECREMENTQ |
                     ?QUITQ | ?FLUSHQ | ?APPENDQ | ?PREPENDQ |
                     ?CMD_SASL_LIST_MECHS | ?CMD_SASL_AUTH | ?CMD_SASL_STEP |
                     ?CMD_CREATE_BUCKET | ?CMD_DELETE_BUCKET |
                     ?CMD_EXPAND_BUCKET |
                     ?CMD_SELECT_BUCKET | ?CMD_PAUSE_BUCKET |
                     ?CMD_UNPAUSE_BUCKET | ?CMD_SET_PARAM | ?CMD_GET_REPLICA |
                     ?CMD_SET_VBUCKET | ?CMD_GET_VBUCKET | ?CMD_DELETE_VBUCKET |
                     ?CMD_ISASL_REFRESH | ?CMD_GET_META | ?CMD_GETQ_META |
                     ?CMD_SET_WITH_META | ?CMD_SETQ_WITH_META |
                     ?CMD_SETQ_WITH_META |
                     ?CMD_DEL_WITH_META | ?CMD_DELQ_WITH_META |
                     ?RGET | ?RSET | ?RSETQ | ?RAPPEND | ?RAPPENDQ | ?RPREPEND |
                     ?RPREPENDQ | ?RDELETE | ?RDELETEQ | ?RINCR | ?RINCRQ |
                     ?RDECR | ?RDECRQ | ?SYNC | ?CMD_CHECKPOINT_PERSISTENCE |
                     ?CMD_SEQNO_PERSISTENCE | ?CMD_GET_RANDOM_KEY |
                     ?CMD_COMPACT_DB | ?CMD_AUDIT_PUT | ?CMD_AUDIT_CONFIG_RELOAD |
                     ?CMD_RBAC_REFRESH | ?CMD_SUBDOC_MULTI_LOOKUP |
                     ?CMD_GET_FAILOVER_LOG |
                     ?CMD_COLLECTIONS_SET_MANIFEST |
                     ?CMD_COLLECTIONS_GET_MANIFEST |
                     ?CMD_GET_FUSION_STORAGE_SNAPSHOT |
                     ?CMD_MOUNT_FUSION_VBUCKET |
                     ?CMD_SET_CHRONICLE_AUTH_TOKEN |
                     ?CMD_START_FUSION_UPLOADER |
                     ?CMD_STOP_FUSION_UPLOADER |
                     ?CMD_SYNC_FUSION_LOGSTORE.


report_counter(Function) ->
    ns_server_stats:notify_counter({<<"memcached_cmd">>,
                                    [{<<"cmd">>, Function}]}).

%% A memcached client that speaks binary protocol.
-spec cmd(mc_opcode(), port(), recv_callback(), any(),
          {#mc_header{}, #mc_entry{}}) ->
                 {ok, #mc_header{}, #mc_entry{}, any()} | {ok, quiet}.
cmd(Opcode, Sock, RecvCallback, CBData, HE) ->
    cmd(Opcode, Sock, RecvCallback, CBData, HE, undefined).

-spec cmd(mc_opcode(), port(), recv_callback(), any(),
          {#mc_header{}, #mc_entry{}}, mc_timeout()) ->
                 {ok, #mc_header{}, #mc_entry{}, any()} | {ok, quiet}.
cmd(Opcode, Sock, RecvCallback, CBData, HE, Timeout) ->
    case is_quiet(Opcode) of
        true  -> cmd_quiet(Opcode, Sock, HE);
        false -> cmd_vocal(Opcode, Sock, RecvCallback, CBData, HE,
                                  Timeout)
    end.

-spec cmd_quiet(integer(), port(),
                {#mc_header{}, #mc_entry{}}) ->
                       {ok, quiet}.
cmd_quiet(Opcode, Sock, {Header, Entry}) ->
    ok = mc_binary:send(Sock, req,
              Header#mc_header{opcode = Opcode}, ext(Opcode, Entry)),
    {ok, quiet}.

-spec respond(integer(), port(),
              {#mc_header{}, #mc_entry{}}) ->
                     {ok, quiet}.
respond(Opcode, Sock, {Header, Entry}) ->
    ok = mc_binary:send(Sock, res,
                        Header#mc_header{opcode = Opcode}, Entry),
    {ok, quiet}.

-spec cmd_vocal(integer(), port(),
                {#mc_header{}, #mc_entry{}}) ->
                       {ok, #mc_header{}, #mc_entry{}}.
cmd_vocal(Opcode, Sock, HE) ->
    {ok, RecvHeader, RecvEntry, _NCB} = cmd_vocal(Opcode, Sock, undefined, undefined, HE, undefined),
    {ok, RecvHeader, RecvEntry}.

cmd_vocal(?STAT = Opcode, Sock, RecvCallback, CBData,
                 {Header, Entry}, Timeout) ->
    ok = mc_binary:send(Sock, req, Header#mc_header{opcode = Opcode}, Entry),
    stats_recv(Sock, RecvCallback, CBData, Timeout);

cmd_vocal(Opcode, Sock, RecvCallback, CBData, {Header, Entry},
                 Timeout) ->
    ok = mc_binary:send(Sock, req,
              Header#mc_header{opcode = Opcode}, ext(Opcode, Entry)),
    cmd_vocal_recv(Opcode, Sock, RecvCallback, CBData, Timeout).

cmd_vocal_recv(Opcode, Sock, RecvCallback, CBData, Timeout) ->
    {ok, RecvHeader, RecvEntry} = mc_binary:recv(Sock, res, Timeout),
    %% Assert Opcode is what we expect.
    Opcode = RecvHeader#mc_header.opcode,
    NCB = case is_function(RecvCallback) of
              true  -> RecvCallback(RecvHeader, RecvEntry, CBData);
              false -> CBData
          end,
    {ok, RecvHeader, RecvEntry, NCB}.

% -------------------------------------------------

stats_recv(Sock, RecvCallback, State, Timeout) ->
    {ok, #mc_header{opcode = ROpcode,
                    keylen = RKeyLen} = RecvHeader, RecvEntry} =
        mc_binary:recv(Sock, res, Timeout),
    case ?STAT =:= ROpcode andalso 0 =:= RKeyLen of
        true  -> {ok, RecvHeader, RecvEntry, State};
        false -> NCB = case is_function(RecvCallback) of
                           true  -> RecvCallback(RecvHeader, RecvEntry, State);
                           false -> State
                       end,
                 stats_recv(Sock, RecvCallback, NCB, Timeout)
    end.

% -------------------------------------------------

auth(_Sock, undefined) -> ok;

auth(Sock, {<<"PLAIN">>, {AuthName, undefined}}) ->
    auth(Sock, {<<"PLAIN">>, {<<>>, AuthName, <<>>}});

auth(Sock, {<<"PLAIN">>, {AuthName, AuthPswd}}) ->
    auth(Sock, {<<"PLAIN">>, {<<>>, AuthName, AuthPswd}});

auth(Sock, {<<"PLAIN">>, {ForName, AuthName, undefined}}) ->
    auth(Sock, {<<"PLAIN">>, {ForName, AuthName, <<>>}});

auth(Sock, {<<"PLAIN">>, {ForName, AuthName, AuthPswd}}) ->
    report_counter(?FUNCTION_NAME),
    BinForName  = mc_binary:bin(ForName),
    BinAuthName = mc_binary:bin(AuthName),
    BinAuthPswd = mc_binary:bin(AuthPswd),
    case cmd(?CMD_SASL_AUTH, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{key = <<"PLAIN">>,
                        data = <<BinForName/binary, 0:8,
                                 BinAuthName/binary, 0:8,
                                 BinAuthPswd/binary>>
                       }}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end;
auth(_Sock, _UnknownMech) ->
    {error, emech_unsupported}.

% -------------------------------------------------
create_bucket(Sock, BucketName, Engine, Config, Timeout) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_CREATE_BUCKET, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{key = BucketName,
                        data = list_to_binary([Engine, 0, Config])}},
             Timeout) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

%% This can take an arbitrary period of time.
delete_bucket(Sock, BucketName, Options) ->
    report_counter(?FUNCTION_NAME),
    Force = proplists:get_bool(force, Options),
    Config0 = [{force, Force}] ++
        case proplists:get_value(type, Options) of
            undefined ->
                [];
            Value ->
                [{type, Value}]
        end,
    Config = ejson:encode({Config0}),
    case cmd(?CMD_DELETE_BUCKET, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{key = BucketName,
                        data = Config}}, infinity) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

delete_vbucket(Sock, VBucket) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_DELETE_VBUCKET, Sock, undefined, undefined,
             construct_delete_vbucket_packet(VBucket),
             ?VB_DELETE_TIMEOUT) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

delete_vbuckets(Sock, VBs) ->
    pipeline_send_recv(Sock, ?CMD_DELETE_VBUCKET,
                       fun construct_delete_vbucket_packet/1, VBs).

construct_delete_vbucket_packet(VBucket) ->
    {#mc_header{vbucket = VBucket}, #mc_entry{}}.

sync_delete_vbucket(Sock, VBucket) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_DELETE_VBUCKET, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket}, #mc_entry{data = <<"async=0">>}},
             infinity) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

flush(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?FLUSH, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{}}) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

hello_features_map() ->
    [{xattr, ?MC_FEATURE_XATTR},
     {collections, ?MC_FEATURE_COLLECTIONS},
     {snappy, ?MC_FEATURE_SNAPPY},
     {duplex, ?MC_FEATURE_DUPLEX},
     {json, ?MC_FEATURE_JSON}].

hello_features(Features) ->
    FeaturesMap = hello_features_map(),
    [F || F <- Features, proplists:is_defined(F, FeaturesMap)].

hello(Sock, AgentName, ClientFeatures) ->
    report_counter(?FUNCTION_NAME),
    FeaturesMap = hello_features_map(),
    Features = [<<V:16>> || {F, V} <- FeaturesMap,
                            proplists:get_bool(F, ClientFeatures)],
    %% Key is the name of the client issuing the hello command.
    Key = list_to_binary("ns_server:" ++ AgentName),
    %% We truncate to 250 bytes as this is the longest key allowed by memcached
    KeyTrunc = binary:part(Key, 0, min(size(Key), 250)),
    case cmd(?CMD_HELLO, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{key = KeyTrunc, data = list_to_binary(Features)}}) of
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{data = undefined}, _NCB} ->
            {ok, []};
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{data = RetData}, _NCB} ->
            Negotiated = [V || <<V:16>> <= RetData],
            NegotiatedNames = [Name || {Name, Code} <- FeaturesMap,
                                       lists:member(Code, Negotiated)],
            {ok, NegotiatedNames};
        Response ->
            process_error_response(Response)
    end.

-spec vbucket_state_to_atom(int_vb_state()) -> atom().
vbucket_state_to_atom(?VB_STATE_ACTIVE) ->
    active;
vbucket_state_to_atom(?VB_STATE_REPLICA) ->
    replica;
vbucket_state_to_atom(?VB_STATE_PENDING) ->
    pending;
vbucket_state_to_atom(?VB_STATE_DEAD) ->
    dead;
vbucket_state_to_atom(_) ->
    unknown.

refresh_isasl(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_ISASL_REFRESH, Sock, undefined, undefined, {#mc_header{}, #mc_entry{}}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Response -> process_error_response(Response)
    end.

noop(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?NOOP, Sock, undefined, undefined, {#mc_header{}, #mc_entry{}}) of
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{}, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

issue_bucket_cmd(CmdOpCode, Sock, BucketName) ->
    case cmd(CmdOpCode, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{key = BucketName}}) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} ->
            ok;
        Response -> process_error_response(Response)
    end.

select_bucket(Sock, BucketName) ->
    report_counter(?FUNCTION_NAME),
    issue_bucket_cmd(?CMD_SELECT_BUCKET, Sock, BucketName).

pause_bucket(Sock, BucketName) ->
    report_counter(?FUNCTION_NAME),
    issue_bucket_cmd(?CMD_PAUSE_BUCKET, Sock, BucketName).

unpause_bucket(Sock, BucketName) ->
    report_counter(?FUNCTION_NAME),
    issue_bucket_cmd(?CMD_UNPAUSE_BUCKET, Sock, BucketName).

deselect_bucket(Sock) ->
    select_bucket(Sock, ?NO_BUCKET).

engine_param_type_to_int(flush) ->
    1;
engine_param_type_to_int(tap) ->
    2;
engine_param_type_to_int(checkpoint) ->
    3;
engine_param_type_to_int(dcp) ->
    4;
engine_param_type_to_int(vbucket) ->
    5.

-spec set_engine_param(port(), binary(), binary(),
                       flush | tap | checkpoint | dcp | vbucket) -> ok | mc_error().
set_engine_param(Sock, Key, Value, Type) ->
    report_counter(?FUNCTION_NAME),
    ParamType = engine_param_type_to_int(Type),
    Entry = #mc_entry{key = Key,
                      data = Value,
                      ext = <<ParamType:32/big>>},
    case cmd(?CMD_SET_PARAM, Sock, undefined, undefined,
             {#mc_header{}, Entry}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

encode_vbucket_state(active)  -> <<?VB_STATE_ACTIVE:8>>;
encode_vbucket_state(replica) -> <<?VB_STATE_REPLICA:8>>;
encode_vbucket_state(pending) -> <<?VB_STATE_PENDING:8>>;
encode_vbucket_state(dead)    -> <<?VB_STATE_DEAD:8>>.

set_vbucket(Sock, VBucket, VBucketState) ->
    set_vbucket(Sock, VBucket, VBucketState, undefined).

set_vbucket(Sock, VBucket, VBucketState, VBInfo) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_SET_VBUCKET, Sock, undefined, undefined,
             construct_set_vbucket_packet({VBucket, VBucketState, VBInfo})) of
        {ok, #mc_header{status=?SUCCESS}, _ME, _NCB} -> ok;
        Response -> process_error_response(Response)
    end.

construct_set_vbucket_packet({VBucket, VBucketState, VBInfo}) ->
    State = encode_vbucket_state(VBucketState),
    Header = #mc_header{vbucket = VBucket},
    Entry = case VBInfo of
                undefined -> #mc_entry{ext = State};
                _ -> #mc_entry{data = ejson:encode(VBInfo),
                               ext = State,
                               datatype = ?MC_DATATYPE_JSON}
            end,
    {Header, Entry}.

set_vbuckets(Sock, ToSet) ->
    pipeline_send_recv(Sock, ?CMD_SET_VBUCKET,
                       fun construct_set_vbucket_packet/1, ToSet).

pipeline_send_recv(Sock, Opcode, EncodeFun, Requests) ->
    pipeline_send_recv(Sock, Opcode, EncodeFun, Requests, ?MAX_MC_TIMEOUT).

pipeline_send_recv(Sock, Opcode, EncodeFun, Requests, Timeout) ->
    ToSend = [EncodeFun(R) || R <- Requests],
    RVs = do_pipeline_send_recv(Sock, Opcode, ToSend, Timeout),
    Bad = lists:filtermap(
            fun ({_, {#mc_header{status = ?SUCCESS}, _}}) ->
                    false;
                ({Req, {Header, Entry}}) ->
                    {true, {Req, process_error_response(Header, Entry)}}
            end, lists:zip(Requests, RVs)),
    case Bad of
        [] -> ok;
        _ -> {errors, Bad}
    end.

-spec do_pipeline_send_recv(port(), integer(), [{#mc_header{}, #mc_entry{}}],
                            integer()) -> [{#mc_header{}, #mc_entry{}}].
do_pipeline_send_recv(Sock, Opcode, Requests, Timeout) ->
    EncodedStream = lists:map(
                      fun ({Header, Entry}) ->
                              NewHeader = Header#mc_header{opcode = Opcode},
                              NewEntry = ext(Opcode, Entry),
                              mc_binary:encode(req, NewHeader, NewEntry)
                      end, Requests),
    ok = mc_binary:send(Sock, EncodedStream),
    TRef = make_ref(),
    Timer = erlang:send_after(Timeout, self(), TRef),
    try
        {RV, <<>>} = lists:foldl(
                       fun (_, {Acc, Rest}) ->
                               {ok, Header, Entry, Extra} =
                                   mc_binary:quick_active_recv(Sock, Rest,
                                                               TRef),
                               %% Assert we receive the same opcode.
                               Opcode = Header#mc_header.opcode,
                               {[{Header, Entry} | Acc], Extra}
                       end, {[], <<>>}, Requests),
        lists:reverse(RV)
    after
        erlang:cancel_timer(Timer),
        misc:flush(TRef)
    end.

compact_vbucket(Sock, VBucket, PurgeBeforeTS, PurgeBeforeSeqNo, DropDeletes,
                ObsoleteKeyIds) ->
    report_counter(?FUNCTION_NAME),
    DD = case DropDeletes of
             true ->
                 1;
             false ->
                 0
         end,
    Ext = <<PurgeBeforeTS:64, PurgeBeforeSeqNo:64, DD:8, 0:8, 0:16, 0:32>>,
    Data = case ObsoleteKeyIds of
               undefined -> undefined;
               KeyList when is_list(KeyList) -> ejson:encode(KeyList)
           end,
    case cmd(?CMD_COMPACT_DB, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket},
              #mc_entry{ext = Ext,
                        datatype = ?MC_DATATYPE_JSON,
                        data = Data}},
             infinity) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Response -> process_error_response(Response)
    end.

stats(Sock) ->
    stats(Sock, <<>>, fun (K, V, Acc) -> [{K, V}|Acc] end, []).

-spec stats(port(), binary(), recv_callback(), any()) ->
          {ok, any()} | mc_error().
stats(Sock, Key, CB, Acc) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?STAT, Sock,
             fun (_MH, ME, CD) ->
                     CB(ME#mc_entry.key, ME#mc_entry.data, CD)
             end,
             Acc,
             {#mc_header{}, #mc_entry{key=Key}}) of
        {ok, #mc_header{status=?SUCCESS}, _E, Stats} ->
            {ok, Stats};
        Response -> process_error_response(Response)
    end.

get_meta(Sock, Key, VBucket, Identity) ->
    report_counter(?FUNCTION_NAME),
    McHeader0 = #mc_header{vbucket = VBucket},
    McHeader =  ns_memcached:maybe_add_impersonate_user_frame_info(Identity,
                                                                   McHeader0),
    case cmd(?CMD_GET_META, Sock, undefined, undefined,
             {McHeader,
              #mc_entry{key = Key}}) of
        {ok, #mc_header{status=?SUCCESS},
             #mc_entry{ext = Ext, cas = CAS}, _NCB} ->
            <<MetaFlags:32/big, ItemFlags:32/big,
              Expiration:32/big, SeqNo:64/big>> = Ext,
            RevId = <<CAS:64/big, Expiration:32/big, ItemFlags:32/big>>,
            Rev = {SeqNo, RevId},
            {ok, Rev, CAS, MetaFlags};
        {ok, #mc_header{status=?KEY_ENOENT},
             #mc_entry{cas=CAS}, _NCB} ->
            {memcached_error, key_enoent, CAS};
        Response ->
            process_error_response(Response)
    end.

subdoc_multi_lookup(Sock, Key, VBucket, Paths, Options, Identity) ->
    report_counter(?FUNCTION_NAME),
    {SubDocFlags, SubDocDocFlags} = parse_subdoc_flags(Options),
    Ext = <<SubDocDocFlags:8>>,
    Header0 = #mc_header{vbucket = VBucket},
    Header = ns_memcached:maybe_add_impersonate_user_frame_info(Identity,
                                                                Header0),

    Specs = [<<?CMD_SUBDOC_GET:8, SubDocFlags:8, (byte_size(P)):16, P/binary>>
                || P <- Paths],
    Entry = #mc_entry{ext = Ext, key = Key, data = Specs},
    case cmd(?CMD_SUBDOC_MULTI_LOOKUP, Sock, undefined, undefined,
             {Header, Entry}) of
        {ok, #mc_header{status = ?SUCCESS},
             #mc_entry{cas = CAS, data = DataResp}, _NCB} ->
            {ok, CAS, parse_multiget_res(DataResp)};
        Other ->
            process_error_response(Other)
    end.

parse_subdoc_flags(Options) ->
    lists:foldl(
        fun (mkdir_p, {F, D}) -> {F bor ?SUBDOC_FLAG_MKDIR_P, D};
            (xattr_path, {F, D}) -> {F bor ?SUBDOC_FLAG_XATTR_PATH, D};
            (expand_macros, {F, D}) -> {F bor ?SUBDOC_FLAG_EXPAND_MACROS, D};
            (mkdoc, {F, D}) -> {F, D bor ?SUBDOC_DOC_MKDOC};
            (add, {F, D}) -> {F, D bor ?SUBDOC_DOC_ADD};
            (access_deleted, {F, D}) -> {F, D bor ?SUBDOC_DOC_ACCESS_DELETED}
        end, {?SUBDOC_FLAG_NONE, ?SUBDOC_DOC_NONE}, Options).

parse_multiget_res(Binary) -> parse_multiget_res(Binary, []).
parse_multiget_res(<<>>, Res) -> lists:reverse(Res);
parse_multiget_res(<<_Status:16, Len:32, Data/binary>>, Res) ->
    <<JSON:Len/binary, Tail/binary>> = Data,
    parse_multiget_res(Tail, [JSON|Res]).

-spec update_with_rev(Sock :: port(), VBucket :: vbucket_id(),
                      Key :: binary(), Value :: binary() | undefined,
                      Rev :: rev(),
                      Deleted :: boolean(),
                      Cas :: integer()) -> {ok, #mc_header{}, #mc_entry{}} |
                                           {memcached_error, atom(), binary()}.
update_with_rev(Sock, VBucket, Key, Value, Rev, Deleted, CAS) ->
    case Deleted of
        true ->
            do_update_with_rev(Sock, VBucket, Key, <<>>, Rev, CAS, ?CMD_DEL_WITH_META);
        false ->
            do_update_with_rev(Sock, VBucket, Key, Value, Rev, CAS, ?CMD_SET_WITH_META)
    end.

%% rev is a pair. First element is RevNum (aka SeqNo). It's is tracked
%% separately inside couchbase bucket. Second part -- RevId, is
%% actually concatenation of CAS, Flags and Expiration.
%%
%% HISTORICAL/PERSONAL PERSPECTIVE:
%%
%% It can be seen that couch, xdcr and rest of ns_server are working
%% with RevIds as opaque entities. Never assuming it has CAS,
%% etc. Thus it would be possible to avoid _any_ mentions of them
%% here. We're just (re)packing some bits in the end. But I believe
%% this "across-the-project" perspective is extremely valuable. Thus
%% this informational (and, presumably, helpful) comment.
%%
%% For xxx-with-meta they're re-assembled as shown below. Apparently
%% to make flags and expiration to 'match' normal set command
%% layout.
rev_to_mcd_ext({SeqNo, <<CASPart:64, Exp:32, Flg:32>>}) ->
    %% pack the meta data in consistent order with EP_Engine protocol
    %% 32-bit flag, 32-bit exp time, 64-bit seqno and CAS
    %%
    %% Final 4 bytes is options. Currently supported options is
    %% SKIP_CONFLICT_RESOLUTION_FLAG but because we don't want to
    %% disable it we pass 0.
    <<Flg:32, Exp:32, SeqNo:64, CASPart:64, 0:32>>.


do_update_with_rev(Sock, VBucket, Key, Value, Rev, CAS, OpCode) ->
    report_counter(?FUNCTION_NAME),
    Ext = rev_to_mcd_ext(Rev),
    Hdr = #mc_header{vbucket = VBucket},
    Entry = #mc_entry{key = Key, data = Value, ext = Ext, cas = CAS},
    Response = cmd(OpCode, Sock, undefined, undefined, {Hdr, Entry}),
    case Response of
        {ok, #mc_header{status=?SUCCESS} = RespHeader, RespEntry, _} ->
            {ok, RespHeader, RespEntry};
        _ ->
            process_error_response(Response)
    end.

enable_traffic(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_ENABLE_TRAFFIC, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.

disable_traffic(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_DISABLE_TRAFFIC, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.

-spec set_bucket_data_ingress(port(), bucket_name(), data_ingress_status()) ->
          ok | mc_error().
set_bucket_data_ingress(Sock, Bucket, Status) ->
    report_counter(?FUNCTION_NAME),
    StatusCode =
        case Status of
            ok -> ?SUCCESS;
            resident_ratio -> ?RR_TOO_LOW;
            data_size -> ?DATA_SIZE_TOO_BIG;
            disk_usage -> ?DISK_SPACE_TOO_LOW
        end,
    case cmd(?CMD_SET_BUCKET_DATA_INGRESS, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{key = list_to_binary(Bucket),
                                      ext = <<StatusCode:16>>}}) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.



%% -------------------------------------------------

is_quiet(?GETQ)       -> true;
is_quiet(?GETKQ)      -> true;
is_quiet(?SETQ)       -> true;
is_quiet(?ADDQ)       -> true;
is_quiet(?REPLACEQ)   -> true;
is_quiet(?DELETEQ)    -> true;
is_quiet(?INCREMENTQ) -> true;
is_quiet(?DECREMENTQ) -> true;
is_quiet(?QUITQ)      -> true;
is_quiet(?FLUSHQ)     -> true;
is_quiet(?APPENDQ)    -> true;
is_quiet(?PREPENDQ)   -> true;
is_quiet(?RSETQ)      -> true;
is_quiet(?RAPPENDQ)   -> true;
is_quiet(?RPREPENDQ)  -> true;
is_quiet(?RDELETEQ)   -> true;
is_quiet(?RINCRQ)     -> true;
is_quiet(?RDECRQ)     -> true;
is_quiet(?CMD_GETQ_META) -> true;
is_quiet(?CMD_SETQ_WITH_META) -> true;
is_quiet(?CMD_ADDQ_WITH_META) -> true;
is_quiet(?CMD_DELQ_WITH_META) -> true;
is_quiet(_)           -> false.

ext(?SET,        Entry) -> ext_flag_expire(Entry);
ext(?SETQ,       Entry) -> ext_flag_expire(Entry);
ext(?ADD,        Entry) -> ext_flag_expire(Entry);
ext(?ADDQ,       Entry) -> ext_flag_expire(Entry);
ext(?REPLACE,    Entry) -> ext_flag_expire(Entry);
ext(?REPLACEQ,   Entry) -> ext_flag_expire(Entry);
ext(?INCREMENT,  Entry) -> ext_arith(Entry);
ext(?INCREMENTQ, Entry) -> ext_arith(Entry);
ext(?DECREMENT,  Entry) -> ext_arith(Entry);
ext(?DECREMENTQ, Entry) -> ext_arith(Entry);
ext(_, Entry) -> Entry.

ext_flag_expire(#mc_entry{ext = Ext, flag = Flag, expire = Expire} = Entry) ->
    case Ext of
        undefined -> Entry#mc_entry{ext = <<Flag:32, Expire:32>>}
    end.

ext_arith(#mc_entry{ext = Ext, data = Data, expire = Expire} = Entry) ->
    case Ext of
        undefined ->
            Ext2 = case Data of
                       <<>>      -> <<1:64, 0:64, Expire:32>>;
                       undefined -> <<1:64, 0:64, Expire:32>>;
                       _         -> <<Data:64, 0:64, Expire:32>>
                   end,
            Entry#mc_entry{ext = Ext2, data = undefined}
    end.

map_status(?SUCCESS) ->
    success;
map_status(?KEY_ENOENT) ->
    key_enoent;
map_status(?KEY_EEXISTS) ->
    key_eexists;
map_status(?E2BIG) ->
    e2big;
map_status(?EINVAL) ->
    einval;
map_status(?NOT_STORED) ->
    not_stored;
map_status(?DELTA_BADVAL) ->
    delta_badval;
map_status(?NOT_MY_VBUCKET) ->
    not_my_vbucket;
map_status(?UNKNOWN_COLLECTION) ->
    unknown_collection;
map_status(?NO_COLL_MANIFEST) ->
    no_coll_manifest;
map_status(?UNKNOWN_COMMAND) ->
    unknown_command;
map_status(?ENOMEM) ->
    enomem;
map_status(?NOT_SUPPORTED) ->
    not_supported;
map_status(?EINTERNAL) ->
    internal;
map_status(?EBUSY) ->
    ebusy;
map_status(?ETMPFAIL) ->
    etmpfail;
map_status(?MC_AUTH_ERROR) ->
    auth_error;
map_status(?MC_AUTH_CONTINUE) ->
    auth_continue;
map_status(?ERANGE) ->
    erange;
map_status(?ROLLBACK) ->
    rollback;
map_status(?ENCR_KEY_NOT_AVAIL) ->
    encryption_key_not_available;
map_status(?SUBDOC_PATH_NOT_EXIST) ->
    subdoc_path_not_exist;
map_status(?SUBDOC_NOT_DICT) ->
    subdoc_not_dict;
map_status(?SUBDOC_BAD_PATH_SYNTAX) ->
    subdoc_bad_path_syntax;
map_status(?SUBDOC_PATH_TOO_LARGE) ->
    subdoc_path_too_large;
map_status(?SUBDOC_MANY_LEVELS) ->
    subdoc_many_levels;
map_status(?SUBDOC_INVALID_VALUE) ->
    subdoc_invalid_value;
map_status(?SUBDOC_DOC_NOT_JSON) ->
    subdoc_doc_not_json;
map_status(?SUBDOC_BAD_ARITH) ->
    subdoc_bad_arith;
map_status(?SUBDOC_INVALID_RES_NUM) ->
    subdoc_invalid_res_num;
map_status(?SUBDOC_PATH_EXISTS) ->
    subdoc_path_exists;
map_status(?SUBDOC_RES_TOO_DEEP) ->
    subdoc_res_too_deep;
map_status(?SUBDOC_INVALID_COMMANDS) ->
    subdoc_invalid_commands;
map_status(?SUBDOC_PATH_FAILED) ->
    subdoc_path_failed;
map_status(?SUBDOC_SUCC_ON_DELETED) ->
    subdoc_succ_on_deleted;
map_status(?SUBDOC_INVALID_FLAGS) ->
    subdoc_invalid_flags;
map_status(?SUBDOC_XATTR_COMB) ->
    subdoc_xattr_comb;
map_status(?SUBDOC_UNKNOWN_MACRO) ->
    subdoc_unknown_macro;
map_status(?SUBDOC_UNKNOWN_ATTR) ->
    subdoc_unknown_attr;
map_status(?SUBDOC_VIRT_ATTR) ->
    subdoc_virt_attr;
map_status(?SUBDOC_FAILED_ON_DELETED) ->
    subdoc_failed_on_deleted;
map_status(?SUBDOC_INVALID_XATTR_ORDER) ->
    subdoc_invalid_xattr_order;
map_status(_) ->
    unknown.

-spec process_error_response(any()) -> mc_error().
process_error_response({ok, Header, Entry, _NCB}) ->
    process_error_response(Header, Entry).

-spec process_error_response(#mc_header{}, #mc_entry{}) -> mc_error().
process_error_response(#mc_header{status=Status}, #mc_entry{data=Msg}) ->
    {memcached_error, map_status(Status), Msg}.

wait_for_seqno_persistence(Sock, VBucket, SeqNo) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_SEQNO_PERSISTENCE, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket},
              #mc_entry{key = <<"">>,
                        ext = <<SeqNo:64/big>>}},
             infinity),
    case RV of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.

-spec get_dcp_docs_estimate(port(), vbucket_id(), binary() | string()) ->
                                   {ok, {non_neg_integer(), non_neg_integer(), binary()}}.
get_dcp_docs_estimate(Sock, VBucket, ConnName) ->
    Default = {0, 0, <<"no_status_stat_seen">>},
    Key = iolist_to_binary([<<"dcp-vbtakeover ">>, integer_to_list(VBucket), $\s, ConnName]),

    RV = mc_binary:quick_stats(
           Sock, Key,
           fun (<<"estimate">>, V, {_, AccChkItems, AccStatus}) ->
                   {list_to_integer(binary_to_list(V)), AccChkItems, AccStatus};
               (<<"chk_items">>, V, {AccEstimate, _, AccStatus}) ->
                   {AccEstimate, list_to_integer(binary_to_list(V)), AccStatus};
               (<<"status">>, V, {AccEstimate, AccChkItems, _}) ->
                   {AccEstimate, AccChkItems, V};
               (_, _, Acc) ->
                   Acc
           end, Default),

    handle_docs_estimate_result(RV, Default).

handle_docs_estimate_result({ok, _} = RV, _) ->
    RV;
handle_docs_estimate_result({memcached_error, not_my_vbucket, _}, Default) ->
    {ok, Default}.

-spec get_mass_dcp_docs_estimate(port(), [vbucket_id()]) ->
                                        {ok, [{non_neg_integer(), non_neg_integer(), binary()}]}.
get_mass_dcp_docs_estimate(Sock, VBuckets) ->
    %% TODO: consider pipelining that stuff. For now it just does
    %% vbucket after vbucket sequentially
    {ok, [case get_dcp_docs_estimate(Sock, VB, <<>>) of
              {ok, V} -> V
          end || VB <- VBuckets]}.

-spec get_all_vb_seqnos(port()) ->
    {ok, [{vbucket_id(), non_neg_integer()}]} | mc_error().
get_all_vb_seqnos(Sock) ->
    RV = cmd(?CMD_GET_ALL_VB_SEQNOS, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}}, infinity),
    case RV of
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{data = undefined}, _} ->
            {ok, []};
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{data = Data}, _} ->
            {ok, [{VB, Seqno} || <<VB:16, Seqno:64>> <= Data]};
        Other ->
            process_error_response(Other)
    end.

set_cluster_config(Sock, Bucket, Rev, RevEpoch0, Blob) ->
    report_counter(?FUNCTION_NAME),

    %% The extra field towards memcached holds Rev and RevEpoch,
    %% which are already a part of the JSON Blob.
    %% RevEpoch = -1 in ext, implies that RevEpoch isn't present in
    %% the JSON Blob. The SDK clients will use ONLY the JSON blob.
    %%
    %% The -1 in ext is packed to conform with the memcached protocol,
    %% which has to be always 16 bytes and the first 8 bytes is
    %% revEpoch and second 8 bytes is Rev (Network order).

    RevEpoch = case RevEpoch0 of
                   not_present -> -1;
                   _ -> RevEpoch0
               end,
    RV = cmd(?CMD_SET_CLUSTER_CONFIG, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{key = list_to_binary(Bucket),
                                      data = Blob,
                                      ext = <<RevEpoch:64,Rev:64>>}}, infinity),
    case RV of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.

get_random_key(Sock, undefined) ->
    get_random_key(Sock, #mc_header{}, #mc_entry{});
get_random_key(Sock, CollectionsUid) ->
    RV = get_random_key(
           Sock, #mc_header{},
           #mc_entry{ext = <<CollectionsUid:32/unsigned-integer>>}),
    case RV of
        {ok, Key} ->
            {CollectionsUid, DKey} = misc:decode_unsigned_leb128(Key),
            {ok, DKey};
        Err ->
            Err
    end.

get_random_key(Sock, Header, Entry) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_GET_RANDOM_KEY, Sock, undefined, undefined,
             {Header, Entry},
             infinity),
    case RV of
        {ok, #mc_header{status=?SUCCESS}, #mc_entry{key = Key}, _} ->
            {ok, Key};
        Other ->
            process_error_response(Other)
    end.

config_validate(Sock, Body) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_CONFIG_VALIDATE, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{data = Body}},
             infinity),
    case process_error_response(RV) of
        {memcached_error, success, _} -> ok;
        Err -> Err
    end.

config_reload(Sock) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_CONFIG_RELOAD, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}},
             infinity),
    case process_error_response(RV) of
        {memcached_error, success, _} -> ok;
        Err -> Err
    end.

audit_put(Sock, Code, Body) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_AUDIT_PUT, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{data = Body, ext = <<Code:32>>}},
             infinity),
    case process_error_response(RV) of
        {memcached_error, success, _} -> ok;
        Err -> Err
    end.

audit_config_reload(Sock) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_AUDIT_CONFIG_RELOAD, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}},
             infinity),
    case process_error_response(RV) of
        {memcached_error, success, _} -> ok;
        Err -> Err
    end.

refresh_rbac(Sock) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_RBAC_REFRESH, Sock, undefined, undefined, {#mc_header{}, #mc_entry{}}),
    case process_error_response(RV) of
        {memcached_error, success, _} -> ok;
        Err -> Err
    end.

unpack_failover_log_loop(<<>>, Acc) ->
    Acc;
unpack_failover_log_loop(<<U:64/big, S:64/big, Rest/binary>>, Acc) ->
    unpack_failover_log_loop(Rest, [{U, S} | Acc]).

unpack_failover_log(Body) ->
    unpack_failover_log_loop(Body, []).

get_failover_log(Sock, VB) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_GET_FAILOVER_LOG, Sock, undefined, undefined,
             {#mc_header{vbucket = VB}, #mc_entry{}}) of
        {ok, #mc_header{status = ?SUCCESS}, ME, _NCB} ->
            unpack_failover_log(ME#mc_entry.data);
        Response ->
            process_error_response(Response)
    end.

set_collections_manifest(Sock, Blob) ->
    report_counter(?FUNCTION_NAME),
    RV = cmd(?CMD_COLLECTIONS_SET_MANIFEST, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{data = Blob}},
             infinity),
    case RV of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Other ->
            process_error_response(Other)
    end.

get_collections_manifest(Sock) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_COLLECTIONS_GET_MANIFEST, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{}}) of
        {ok, #mc_header{status = ?SUCCESS}, ME, _NCB} ->
            {ok, ME#mc_entry.data};
        Response ->
            process_error_response(Response)
    end.

update_user_permissions(Sock, RBACJson) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode(RBACJson),
    case cmd(?MC_UPDATE_USER_PERMISSIONS, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{data = Data}}) of
        {ok, #mc_header{status = ?SUCCESS}, _, _} -> ok;
        Response -> process_error_response(Response)
    end.

set_tls_config(Sock, TLSConfigJSON) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode(TLSConfigJSON),
    case cmd(?CMD_IFCONFIG, Sock, undefined, undefined,
             {#mc_header{}, #mc_entry{key = <<"tls">>, data = Data}}) of
        {ok, #mc_header{status = ?SUCCESS}, _, _} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

prune_log_or_audit_encr_keys(Sock, Type, KeyIds, Timeout) ->
    report_counter(?FUNCTION_NAME),
    Entry = #mc_entry{key = iolist_to_binary(Type),
                      data = ejson:encode(KeyIds)},
    case cmd(?CMD_PRUNE_ENCRYPTION_KEYS, Sock, undefined, undefined,
             {#mc_header{}, Entry}, Timeout) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

set_active_encryption_key(Sock, Bucket, DeksSnapshot, Timeout) ->
    report_counter(?FUNCTION_NAME),
    {ActiveDek, AllDeks} = cb_crypto:get_all_deks(DeksSnapshot),
    DeksJson = memcached_bucket_config:format_mcd_keys(ActiveDek, AllDeks),
    Entry = #mc_entry{key = iolist_to_binary(Bucket),
                      data = ejson:encode(DeksJson)},
    case cmd(?CMD_SET_ENCRYPTION_KEY, Sock, undefined, undefined,
             {#mc_header{}, Entry}, Timeout) of
        {ok, #mc_header{status=?SUCCESS}, _, _} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

-spec get_fusion_storage_snapshot(port(), vbucket_id(), string(),
                                  non_neg_integer()) ->
          {ok, binary()} | mc_error().
get_fusion_storage_snapshot(Sock, VBucket, SnapshotUUID, Validity) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode({[{snapshotUuid, list_to_binary(SnapshotUUID)},
                          {validity, Validity}]}),
    case cmd(?CMD_GET_FUSION_STORAGE_SNAPSHOT, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket},
              #mc_entry{data = Data,
                        datatype = ?MC_DATATYPE_JSON}}) of
        {ok, #mc_header{status = ?SUCCESS}, ME, _NCB} ->
            {ok, ME#mc_entry.data};
        Response ->
            process_error_response(Response)
    end.

-spec mount_fusion_vbucket(port(), vbucket_id(), [list()]) ->
          {ok, binary()} | mc_error().
mount_fusion_vbucket(Sock, VBucket, Volumes) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode({[{mountPaths, [list_to_binary(V) || V <- Volumes]}]}),
    case cmd(?CMD_MOUNT_FUSION_VBUCKET, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket},
              #mc_entry{data = Data,
                        datatype = ?MC_DATATYPE_JSON}}) of
        {ok, #mc_header{status = ?SUCCESS}, ME, _NCB} ->
            {ok, ME#mc_entry.data};
        Response ->
            process_error_response(Response)
    end.

-spec set_chronicle_auth_token(port(), binary()) -> ok | mc_error().
set_chronicle_auth_token(Sock, Token) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode({[{token, Token}]}),
    case cmd(?CMD_SET_CHRONICLE_AUTH_TOKEN, Sock, undefined, undefined,
             {#mc_header{},
              #mc_entry{data = Data,
                        datatype = ?MC_DATATYPE_JSON}}) of
        {ok, #mc_header{status = ?SUCCESS}, _ME, _NCB} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

-spec start_fusion_uploader(port(), vbucket_id(), integer()) ->
          ok | mc_error().
start_fusion_uploader(Sock, VBucket, Term) ->
    report_counter(?FUNCTION_NAME),
    Data = ejson:encode({[{term, list_to_binary(integer_to_list(Term))}]}),
    case cmd(?CMD_START_FUSION_UPLOADER, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket},
              #mc_entry{data = Data,
                        datatype = ?MC_DATATYPE_JSON}}) of
        {ok, #mc_header{status = ?SUCCESS}, _ME, _NCB} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

-spec stop_fusion_uploader(port(), vbucket_id()) ->
          ok | mc_error().
stop_fusion_uploader(Sock, VBucket) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_STOP_FUSION_UPLOADER, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket}, #mc_entry{}}) of
        {ok, #mc_header{status = ?SUCCESS}, _ME, _NCB} ->
            ok;
        Response ->
            process_error_response(Response)
    end.

-spec sync_fusion_log_store(port(), vbucket_id()) -> ok | mc_error().
sync_fusion_log_store(Sock, VBucket) ->
    report_counter(?FUNCTION_NAME),
    case cmd(?CMD_SYNC_FUSION_LOGSTORE, Sock, undefined, undefined,
             {#mc_header{vbucket = VBucket}, #mc_entry{}},
             infinity) of
        {ok, #mc_header{status=?SUCCESS}, _, _} -> ok;
        Response -> process_error_response(Response)
    end.
