%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_crypto).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(ENCRYPTED_FILE_HEADER_LEN, 80).
-define(IV_LEN, 12).
-define(TAG_LEN, 16).
-define(CHUNKSIZE_ATTR_SIZE, 4).
-define(ENCRYPTED_FILE_MAGIC, 0, "Couchbase Encrypted", 0).
-define(NO_COMPRESSION, 0).
-define(SNAPPY_COMPRESSION, 1).
-define(ZLIB_COMPRESSION, 2).
-define(GZIP_COMPRESSION, 3).
-define(ZSTD_COMPRESSION, 4).
-define(BZIP2_COMPRESSION, 5).

-export([%% Encryption/decryption functions:
         encrypt/3,
         decrypt/3,

         atomic_write_file/3,
         atomic_write_file/4,
         file_encrypt_init/1,
         file_encrypt_init/2,
         file_encrypt_cont/3,
         file_encrypt_chunk/2,
         file_encrypt_finish/1,

         read_file/2,
         read_file_chunks/5,
         file_encrypt_state_match/2,
         validate_encr_file_with_ds/2,
         is_file_encr_by_ds/2,
         is_file_encrypted/1,
         get_file_dek_ids/1,
         get_in_use_deks/1,
         file_decrypt_init/2,
         file_decrypt_next_chunk/2,
         file_decrypt_finish/1,

         new_aes_gcm_iv/1,

         %% Manage deks in persistent_term storage:
         fetch_deks_snapshot/1,
         create_deks_snapshot/3,
         reset_dek_cache/2,
         get_all_deks/1,
         get_dek_id/1,
         get_dek/1,
         without_historical_deks/1,
         same_snapshots/2,

         %% Other:
         get_encryption_method/2,
         get_dek_kind_lifetime/2,
         get_dek_rotation_interval/2,
         get_drop_keys_timestamp/2
        ]).

-export_type([dek_snapshot/0, encryption_type/0]).

-record(dek_snapshot, {iv_random :: binary(),
                       iv_atomic_counter :: atomics:atomics_ref(),
                       active_key :: cb_deks:dek() | undefined,
                       all_keys :: [cb_deks:dek()]}).

-record(file_encr_state, {ad_prefix = <<>> :: binary(),
                          key :: cb_deks:dek() | undefined,
                          iv_random :: binary(),
                          iv_atomic_counter :: atomics:atomics_ref() ,
                          offset :: non_neg_integer(),
                          compression_state :: undefined |
                                               {zlib, none | sync | full,
                                                zlib:zstream()}}).

-record(file_decr_state, {vsn :: non_neg_integer(),
                          ad_prefix = <<>> :: binary(),
                          key :: cb_deks:dek(),
                          offset = 0 :: non_neg_integer(),
                          decompression_state :: undefined |
                                                 {zlib, zlib:zstream()}}).

-type dek_snapshot() :: #dek_snapshot{}.
-type encryption_type() :: config_encryption | log_encryption |
                           audit_encryption.
-type fetch_deks_res() :: {ok, #dek_snapshot{}} | {error, term()}.
-type compression_cfg() :: {zlib,
                            Level :: pos_integer(),
                            Flush :: none | sync | full} | undefined.

%%%===================================================================
%%% API
%%%===================================================================

-spec encrypt(binary(), binary(), #dek_snapshot{}) ->
          {ok, binary()} | {error, term()}.
encrypt(_Data, _AD, #dek_snapshot{active_key = undefined}) ->
    {error, no_active_key};
encrypt(Data, AD, #dek_snapshot{active_key = ActiveDek,
                                iv_random = IVRandom,
                                iv_atomic_counter = IVAtomic}) ->
    {ok, encrypt_internal(Data, AD, IVRandom, IVAtomic, ActiveDek)}.

-spec decrypt(binary(), binary(), #dek_snapshot{}) ->
          {ok, binary()} | {error, term()}.
decrypt(Data, AD, #dek_snapshot{all_keys = AllKeys}) ->
    decrypt_internal(Data, AD, AllKeys).

-spec atomic_write_file(string(), binary() | iolist(), #dek_snapshot{}) ->
          ok | {error, term()}.
atomic_write_file(Path, Data, DekSnapshot) ->
    atomic_write_file(Path, Data, DekSnapshot, #{}).

-spec atomic_write_file(string(), binary() | iolist(), #dek_snapshot{},
                        #{max_chunk_size => pos_integer(),
                          compression => compression_cfg()}) ->
          ok | {error, term()}.
atomic_write_file(Path, List, DekSnapshot, Opts) when is_list(List) ->
    atomic_write_file(Path, iolist_to_binary(List), DekSnapshot, Opts);
atomic_write_file(Path, Bytes, DekSnapshot, Opts) when is_binary(Bytes) ->
    MaxChunkSize = maps:get(max_chunk_size, Opts, 65536),
    Compression = maps:get(compression, Opts, undefined),
    misc:atomic_write_file(
      Path,
      fun (IODevice) ->
          encrypt_to_file(IODevice, Bytes, MaxChunkSize, Compression, DekSnapshot)
      end).


-spec file_encrypt_init(#dek_snapshot{}) ->
          {binary(), #file_encr_state{}}.
file_encrypt_init(DekSnapshot) ->
    file_encrypt_init(DekSnapshot, #{}).

-spec file_encrypt_init(#dek_snapshot{}, #{compression => compression_cfg()}) ->
          {binary(), #file_encr_state{}}.
file_encrypt_init(#dek_snapshot{active_key = ActiveKey,
                                iv_random = IVRandom,
                                iv_atomic_counter = IVCounter}, Opts) ->

    Salt = crypto:strong_rand_bytes(16),
    {CompressionType, CompressionState} =
        case maps:get(compression, Opts, undefined) of
            undefined -> {?NO_COMPRESSION, undefined};
            {zlib, Level, Flush} ->
                Z = zlib:open(),
                zlib:deflateInit(Z, Level),
                {?ZLIB_COMPRESSION, {zlib, Flush, Z}}
        end,
    Header =
        case ActiveKey of
            undefined -> <<>>;
            #{id := Id} ->
                Len = size(Id),
                Vsn = 0,
                H = <<?ENCRYPTED_FILE_MAGIC, Vsn, CompressionType, 0, 0, 0, 0,
                      Len, Id/binary, Salt/binary>>,
                ?ENCRYPTED_FILE_HEADER_LEN = size(H),
                H
        end,
    {Header, #file_encr_state{ad_prefix = Header,
                              key = ActiveKey,
                              iv_random = IVRandom,
                              iv_atomic_counter = IVCounter,
                              offset = size(Header),
                              compression_state = CompressionState}}.

-spec file_encrypt_cont(string(), non_neg_integer(), #dek_snapshot{}) ->
          {ok, #file_encr_state{}} | {error, _}.

%% Note: We can't continue writing compressed file
file_encrypt_cont(Path, FileSize,
                  #dek_snapshot{active_key = ActiveKey,
                                iv_random = IVRandom,
                                iv_atomic_counter = IVCounter}) ->
    maybe
        {ok, Header} ?= read_file_header(Path),
        {ok, {_Vsn, KeyId, ADPrefix, _, CompressionType, <<>>}} ?=
            parse_header(Header),
        ok ?= case CompressionType of
                  ?NO_COMPRESSION -> ok;
                  _ -> {error, {unsupported_compression_type, CompressionType}}
              end,
        case ActiveKey of
            #{id := KeyId} ->
                {ok, #file_encr_state{ad_prefix = ADPrefix,
                                      key = ActiveKey,
                                      iv_random = IVRandom,
                                      iv_atomic_counter = IVCounter,
                                      offset = FileSize}};
            _ ->
                {error, key_mismatch}
        end
    else
        {error, unknown_magic} when ActiveKey == undefined ->
            %% File is not encrypted
            {ok, #file_encr_state{ad_prefix = <<>>,
                                  key = undefined,
                                  iv_random = IVRandom,
                                  iv_atomic_counter = IVCounter,
                                  offset = FileSize}};
        {error, _} = Error ->
            Error
    end.

-spec file_encrypt_chunk(erlang:iodata(), #file_encr_state{}) ->
          {erlang:iodata(), #file_encr_state{}}.
file_encrypt_chunk(Data, #file_encr_state{key = undefined} = State) ->
    {Data, State};
file_encrypt_chunk(Data, State) ->
    maybe
        {empty, false} ?= {empty, misc:iolist_is_empty(Data)},
        #file_encr_state{key = Dek,
                         iv_random = IVRandom,
                         iv_atomic_counter = IVAtomic,
                         offset = Offset,
                         compression_state = CompressionState} = State,
        AD = file_assoc_data(State),
        CompressedData = case CompressionState of
                             undefined -> Data;
                             {zlib, Flush, Z} -> zlib:deflate(Z, Data, Flush)
                         end,
        {empty, false} ?= {empty, misc:iolist_is_empty(CompressedData)},
        Chunk = encrypt_internal(CompressedData, AD, IVRandom, IVAtomic,
                                 Dek),
        ChunkSize = size(Chunk),
        ChunkWithSize = <<ChunkSize:32/big-unsigned-integer, Chunk/binary>>,
        NewOffset = Offset + size(ChunkWithSize),
        {ChunkWithSize, State#file_encr_state{offset = NewOffset}}
    else
        {empty, true} ->
            {<<>>, State}
    end.

-spec file_encrypt_finish(#file_encr_state{}) -> binary().
file_encrypt_finish(#file_encr_state{compression_state = undefined}) ->
    <<>>;
file_encrypt_finish(
        #file_encr_state{compression_state = {zlib, _, Z}} = State) ->
    FinalData = zlib:deflate(Z, <<>>, finish),
    ok = zlib:deflateEnd(Z),
    zlib:close(Z),
    NewState = State#file_encr_state{compression_state = undefined},
    {EncryptedData, _} = file_encrypt_chunk(FinalData, NewState),
    EncryptedData.

-spec file_encrypt_state_match(#dek_snapshot{},
                               #file_encr_state{}) -> boolean().
file_encrypt_state_match(#dek_snapshot{active_key = ActiveKey},
                         #file_encr_state{key = FileActiveKey}) ->
    get_key_id(ActiveKey) =:= get_key_id(FileActiveKey).

-spec validate_encr_file_with_ds(string(), #dek_snapshot{}) -> true | false.
validate_encr_file_with_ds(Path, #dek_snapshot{active_key = undefined}) ->
    not is_file_encrypted(Path);
validate_encr_file_with_ds(Path, DS) ->
    is_file_encr_by_ds(Path, DS) andalso validate_encr_file(Path).

-spec is_file_encr_by_ds(string(), #dek_snapshot{}) -> true | false.
is_file_encr_by_ds(Path, #dek_snapshot{active_key = undefined}) ->
    not is_file_encrypted(Path);
is_file_encr_by_ds(Path, #dek_snapshot{active_key = #{id := KeyId}}) ->
    header_key_match(read_file_header(Path), KeyId).

-spec is_file_encrypted(string()) -> true | false.
is_file_encrypted(Path) ->
    is_valid_encr_header(read_file_header(Path)).

-spec get_file_dek_ids(Path :: string()) ->
          {ok, [cb_deks:dek_id() | undefined]} | {error, _}.
get_file_dek_ids(Path) ->
    case read_file_header(Path) of
        {ok, Bin} ->
            case parse_header(Bin) of
                {ok, {_Vsn, KeyId, _ADPrefix, _Offset, _CompressionType,
                      _Rest}} ->
                    {ok, [KeyId]};
                incomplete_magic -> {ok, [undefined]};
                need_more_data -> {ok, [undefined]};
                {error, unknown_magic} -> {ok, [undefined]};
                {error, E} -> {error, E}
            end;
        eof -> {ok, []};
        {error, enoent} -> {ok, []};
        {error, R} -> {error, R}
    end.

-spec get_in_use_deks([string()]) -> [cb_deks:dek_id()].
get_in_use_deks(FilePaths) ->
    InUseDeks =
        lists:flatmap(
            fun(FilePath) ->
                {ok, DekIds} = get_file_dek_ids(FilePath),
                DekIds
            end, FilePaths),
    lists:usort(InUseDeks).

-spec read_file(string(),
                cb_deks:dek_kind() |
                #dek_snapshot{} |
                fun(() -> fetch_deks_res()) |
                fun((cb_deks:dek_id()) -> cb_deks:dek())) ->
          {decrypted, binary()} | {raw, binary()} | {error, term()}.
read_file(Path, GetDekSnapshotFun) when is_function(GetDekSnapshotFun) ->
    maybe
        {ok, Data} ?= file:read_file(Path),
        case decrypt_file_data(Data, GetDekSnapshotFun) of
            {ok, Decrypted} ->
                {decrypted, Decrypted};
            {error, unknown_magic} ->
                %% File is not encrypted?
                {raw, Data};
            {error, _} = Error ->
                Error
        end
    end;
read_file(Path, #dek_snapshot{} = DekSnapshot) ->
    read_file(Path, fun () -> {ok, DekSnapshot} end);
read_file(Path, DekKind) ->
    GetSnapshotFun = fun () -> fetch_deks_snapshot(DekKind) end,
    read_file(Path, GetSnapshotFun).

-spec read_file_chunks(Path, Fun, Acc, Deks, Opts) -> {ok, Acc} |
                                                      {error, _, Acc}
          when Path :: string(),
               Fun :: fun ( (erlang:iodata(), Acc) -> {ok, Acc} | {error, _} ),
               Acc :: term(),
               Deks :: #dek_snapshot{},
               Opts :: #{read_chunk_size => pos_integer()}.
read_file_chunks(Path, Fun, AccInit, Deks, Opts) ->
    ReadChunkSize = maps:get(read_chunk_size, Opts, 65536),
    F = fun (Data, {init, Acc}) ->
                case file_decrypt_init(Data, Deks) of
                    {ok, {EncrState, Rest}} ->
                        {ok, {process, EncrState, Acc}, Rest};
                    incomplete_magic -> need_more_data;
                    need_more_data -> need_more_data;
                    {error, _} = E -> E
                end;
            (Data, {process, EncrState, Acc}) ->
                maybe
                    {ok, {NewEncrState, Chunk, Rest}} ?=
                        file_decrypt_next_chunk(Data, EncrState),
                    {ok, NewAcc} ?= Fun(Chunk, Acc),
                    {ok, {process, NewEncrState, NewAcc}, Rest}
                end
        end,
    Finalize = fun ({init, Acc}) -> {ok, Acc};
                   ({process, DecrState, Acc}) ->
                       case file_decrypt_finish(DecrState) of
                           ok -> {ok, Acc};
                           {error, R} -> {error, R, Acc}
                       end
               end,
    FinalAcc = fun ({init, Acc}) -> Acc;
                   ({process, _, Acc}) -> Acc
               end,
    case misc:fold_file(Path, F, {init, AccInit}, ReadChunkSize) of
        {ok, ResAcc} ->
            Finalize(ResAcc);
        {unhandled_data, _Data, ResAcc} ->
            _ = Finalize(ResAcc),
            {error, invalid_file_encryption, FinalAcc(ResAcc)};
        {error, Reason, ResAcc} ->
            _ = Finalize(ResAcc),
            {error, Reason, FinalAcc(ResAcc)}
    end.

-spec file_decrypt_init(binary(),
                        #dek_snapshot{} |
                        fun(() -> fetch_deks_res()) |
                        fun((cb_deks:dek_id()) -> cb_deks:dek())) ->
          {ok, {#file_decr_state{}, RestData :: binary()}} |
          need_more_data |
          incomplete_magic |
          {error, term()}.
file_decrypt_init(Data, #dek_snapshot{} = DekSnapshot) ->
    file_decrypt_init(Data, fun () -> {ok, DekSnapshot} end);
file_decrypt_init(Data, GetDekSnapshotFun)
                                    when is_function(GetDekSnapshotFun, 0) ->
    GetKey = fun (Id) ->
                 maybe
                     {ok, DekSnapshot} ?= GetDekSnapshotFun(),
                     find_key(Id, DekSnapshot)
                 end
             end,
    file_decrypt_init(Data, GetKey);
file_decrypt_init(Data, GetKeyFun) when is_function(GetKeyFun, 1) ->
    maybe
        {ok, {Vsn, Id, ADPrefix, Offset, CompressionType, Chunks}} ?=
            parse_header(Data),
        {ok, DecompressionState} ?=
            case CompressionType of
                ?NO_COMPRESSION ->
                    {ok, undefined};
                ?ZLIB_COMPRESSION ->
                    Z = zlib:open(),
                    ok = zlib:inflateInit(Z),
                    {ok, {zlib, Z}};
                _ ->
                    {error, {unsupported_compression_type, CompressionType}}
            end,
        {ok, Dek} ?= GetKeyFun(Id),
        State = #file_decr_state{vsn = Vsn,
                                 ad_prefix = ADPrefix,
                                 key = Dek,
                                 offset = Offset,
                                 decompression_state = DecompressionState},
        {ok, {State, Chunks}}
    end.

-spec file_decrypt_next_chunk(binary(), #file_decr_state{}) ->
          {ok, {NewState :: #file_decr_state{},
                DecryptedChunk :: erlang:iodata(),
                RestData :: binary()}} |
          need_more_data | eof | {error, term()}.
file_decrypt_next_chunk(Data, State) ->
    #file_decr_state{vsn = 0,
                     key = Dek,
                     offset = Offset,
                     decompression_state = DecompressionState} = State,
    case bite_next_chunk(Data) of
        {ok, {SizeEaten, Chunk}, Rest} ->
            AD = file_assoc_data(State),
            case decrypt_internal(Chunk, AD, [Dek]) of
                {ok, DecryptedData} ->
                    NewOffset = Offset + SizeEaten,
                    NewState = State#file_decr_state{offset = NewOffset},
                    case DecompressionState of
                        undefined ->
                            {ok, {NewState, DecryptedData, Rest}};
                        {zlib, Z} ->
                            Inflated = zlib:inflate(Z, DecryptedData),
                            {ok, {NewState, Inflated, Rest}}
                    end;
                {error, _} = Error ->
                    Error
            end;
        eof -> eof;
        need_more_data -> need_more_data;
        {error, _} = Error -> Error
    end.

-spec file_decrypt_finish(#file_decr_state{}) -> ok | {error, incomplete_data}.
file_decrypt_finish(#file_decr_state{decompression_state = undefined}) ->
    ok;
file_decrypt_finish(#file_decr_state{decompression_state = {zlib, Z}}) ->
    try
        ok = zlib:inflateEnd(Z)
    catch
        error:data_error ->
            %% no end of stream was found meaning that not all data has been
            %% uncompressed
            {error, incomplete_data}
    after
        zlib:close(Z)
    end.

-spec new_aes_gcm_iv(#dek_snapshot{}) -> binary().
new_aes_gcm_iv(#dek_snapshot{iv_random = IVRandom,
                             iv_atomic_counter = IVAtomic}) ->
    new_aes_gcm_iv(IVRandom, IVAtomic).

-spec fetch_deks_snapshot(cb_deks:dek_kind()) -> fetch_deks_res().
fetch_deks_snapshot(DekKind) ->
    cb_atomic_persistent_term:get_or_set_if_undefined(
      {encryption_keys, DekKind},
      fun () ->
          read_deks(DekKind, undefined)
      end).

-spec create_deks_snapshot(cb_deks:dek() | undefined, [cb_deks:dek()],
                           #dek_snapshot{} | undefined) -> #dek_snapshot{}.
create_deks_snapshot(ActiveDek, AllDeks, PrevDekSnapshot) ->
    %% Random 4 byte base + unique 8 byte integer = unique 12 byte IV
    %% (note that atomics are 8 byte integers)
    IVBase = crypto:strong_rand_bytes(4),
    IVAtomic =
        case PrevDekSnapshot of
            undefined -> atomics:new(1, [{signed, false}]);
            #dek_snapshot{iv_atomic_counter = OldIVAtomic} -> OldIVAtomic
        end,
    #dek_snapshot{iv_random = IVBase,
                  iv_atomic_counter = IVAtomic,
                  active_key = ActiveDek,
                  all_keys = AllDeks}.

-spec reset_dek_cache(cb_deks:dek_kind(),
                      Reason :: {new_active, cb_deks:dek()} | cleanup) ->
          {ok, changed | unchanged} | {error, term()}.
reset_dek_cache(DekKind, Reason) ->
    %% Technically we can simply erase the persistent term, but it will result
    %% in two global GC's then (erase and set). So we read and set new value
    %% instead, which gives us only one global GC.
    cb_atomic_persistent_term:set(
      {encryption_keys, DekKind},
      fun (PrevSnapshot) ->
          Changed =
              case Reason of
                  {new_active, NewActiveDek} ->
                      get_dek_id(PrevSnapshot) =/= get_dek_id(NewActiveDek);
                  cleanup ->
                      true
              end,
          case Changed of
              true ->
                  case read_deks(DekKind, PrevSnapshot) of
                      {ok, NewSnapshot} -> {set, NewSnapshot, {ok, changed}};
                      {error, _} = Error -> {ignore, Error}
                  end;
              false ->
                  {ignore, {ok, unchanged}}
          end
      end).

-spec get_all_deks(#dek_snapshot{}) ->
          {cb_deks:dek() | undefined, [cb_deks:dek()]}.
get_all_deks(#dek_snapshot{active_key = ActiveKey, all_keys = AllKeys}) ->
    {ActiveKey, AllKeys}.

-spec get_dek_id(#dek_snapshot{} | cb_deks:dek() | undefined) ->
          cb_deks:dek_id() | undefined.
get_dek_id(#dek_snapshot{active_key = Key}) ->
    get_dek_id(Key);
get_dek_id(undefined) ->
    undefined;
get_dek_id(#{id := Id}) ->
    Id.

-spec get_dek(#dek_snapshot{}) -> cb_deks:dek() | undefined.
get_dek(#dek_snapshot{active_key = Key}) -> Key.

-spec without_historical_deks(#dek_snapshot{}) -> #dek_snapshot{}.
without_historical_deks(#dek_snapshot{active_key = undefined} = Snapshot) ->
    Snapshot#dek_snapshot{all_keys = []};
without_historical_deks(#dek_snapshot{active_key = Dek} = Snapshot) ->
    Snapshot#dek_snapshot{all_keys = [Dek]}.

-spec same_snapshots(#dek_snapshot{}, #dek_snapshot{}) -> boolean().
same_snapshots(#dek_snapshot{active_key = AK1, all_keys = All1},
               #dek_snapshot{active_key = AK2, all_keys = All2}) ->
    (AK1 == AK2) andalso (lists:usort(All1) == lists:usort(All2)).

-spec get_encryption_method(encryption_type(),
                            cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, cb_deks:encryption_method()} | {error, not_found}.
get_encryption_method(Type, Snapshot) ->
    case menelaus_web_encr_at_rest:get_settings(Snapshot) of
        #{Type := EncryptionSettings}  ->
            {ok, case EncryptionSettings of
                     #{encryption := disabled} -> disabled;
                     #{encryption := encryption_service} -> encryption_service;
                     #{encryption := secret, secret_id := Id} -> {secret, Id}
                 end};
        #{} ->
            {error, not_found}
    end.

-spec get_dek_kind_lifetime(encryption_type(),
                            cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, pos_integer()} | {error, not_found}.
get_dek_kind_lifetime(Type, Snapshot) ->
    case menelaus_web_encr_at_rest:get_settings(Snapshot) of
        #{Type := #{dek_lifetime_in_sec := ?DEK_INFINITY_LIFETIME}} ->
            {ok, undefined};
        #{Type := #{dek_lifetime_in_sec := Lifetime}} ->
            {ok, Lifetime};
        #{} ->
            {error, not_found}
    end.

-spec get_dek_rotation_interval(encryption_type(),
                                cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | pos_integer()} | {error, not_found}.
get_dek_rotation_interval(Type, Snapshot) ->
    case menelaus_web_encr_at_rest:get_settings(Snapshot) of
        #{Type := #{dek_rotation_interval_in_sec := 0}} -> {ok, undefined};
        #{Type := #{dek_rotation_interval_in_sec := Int}} -> {ok, Int};
        #{} -> {error, not_found}
    end.

-spec get_drop_keys_timestamp(encryption_type(),
                              cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | calendar:datetime()} | {error, not_found}.
get_drop_keys_timestamp(Type, Snapshot) ->
    case menelaus_web_encr_at_rest:get_settings(Snapshot) of
        #{Type := #{dek_drop_datetime := {set, DT},
                    encryption_last_toggle_datetime := TDT}} when TDT > DT ->
            {ok, undefined};
        #{Type := #{dek_drop_datetime := {set, DT}}} ->
            {ok, DT};
        #{Type := #{dek_drop_datetime := {not_set, _}}} ->
            {ok, undefined};
        #{} ->
            {error, not_found}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

is_valid_encr_header({ok, HeaderData}) ->
    case parse_header(HeaderData) of
        {ok, _Parsed} ->
            true;
        _ ->
            false
    end;
is_valid_encr_header({error, enoent}) ->
    false;
is_valid_encr_header(eof) ->
    false.

header_key_match({ok, HeaderData}, KeyId) ->
    case parse_header(HeaderData) of
        {ok, {_Vsn, KeyId, _ADPrefix, _Offset, _CompressionType, _Rest}} ->
            true;
        _ ->
            false
    end;
header_key_match({error, enoent}, _KeyId) ->
    false;
header_key_match(eof, _KeyId) ->
    false.

get_key_id(undefined) ->
    undefined;
get_key_id(#{id := KeyId} = _Key) ->
    KeyId.

check_next_chunk_exists(_File, {error, _}, _CurrentOffset) ->
    false;
check_next_chunk_exists(File, eof, CurrentExpectedOffset) ->
    case file:position(File, eof) of
        {ok, CurrentExpectedOffset} ->
            true;
        _ ->
            false
    end;
check_next_chunk_exists(File,
                        {ok, <<ChunkSize:32/big-unsigned-integer>>},
                        CurrentOffset) ->
    NewExpectedOffset = ChunkSize + CurrentOffset + ?CHUNKSIZE_ATTR_SIZE,
    NextSizeRead = file:pread(File, NewExpectedOffset, ?CHUNKSIZE_ATTR_SIZE),
    check_next_chunk_exists(File, NextSizeRead, NewExpectedOffset);
check_next_chunk_exists(_File, {ok, _}, _CurrExpectedOffset) ->
    false.

validate_encr_file(FilePath) ->
    {ok, File} = file:open(FilePath, [raw, binary, read]),
    try
        Header = file:read(File, ?ENCRYPTED_FILE_HEADER_LEN),
        case is_valid_encr_header(Header) of
            true ->
                NextSizeRead =  file:pread(File, ?ENCRYPTED_FILE_HEADER_LEN,
                                           ?CHUNKSIZE_ATTR_SIZE),
                check_next_chunk_exists(File, NextSizeRead,
                                        ?ENCRYPTED_FILE_HEADER_LEN);
            false ->
                false
        end
    after
        file:close(File)
    end.


encrypt_internal(Data, AD, IVRandom, IVAtomic, #{type := 'raw-aes-gcm',
                                                 info := #{key := KeyFun}}) ->
    IV = new_aes_gcm_iv(IVRandom, IVAtomic),
    %% Tag size is 16 bytes as it is specified in requirements
    {EncryptedData, Tag} =
        crypto:crypto_one_time_aead(
          aes_256_gcm, KeyFun(), IV, Data, AD, ?TAG_LEN, true),
    ?TAG_LEN = size(Tag),
    <<IV/binary, EncryptedData/binary, Tag/binary>>.

decrypt_internal(_Data, _AD, []) ->
    {error, decrypt_error};
decrypt_internal(Data, AD, DekList) ->
    DataSize = size(Data) - ?IV_LEN - ?TAG_LEN,
    case DataSize > 0 of
        true ->
            <<IV:?IV_LEN/binary,
              EncryptedData:DataSize/binary,
              Tag:?TAG_LEN/binary>> = Data,
            try_decrypt(IV, EncryptedData, Tag, AD, DekList);
        false ->
            {error, invalid_data_chunk}
    end.

try_decrypt(_IV, _Data, _Tag, _AD, []) -> {error, decrypt_error};
try_decrypt(IV, Data, Tag, AD, [#{type := 'raw-aes-gcm', info := #{key := K}} | T]) ->
    case crypto:crypto_one_time_aead(aes_256_gcm, K(), IV, Data, AD,
                                     Tag, false) of
        error -> try_decrypt(IV, Data, Tag, AD, T);
        Decrypted -> {ok, Decrypted}
    end.

-spec read_deks(cb_deks:dek_kind(), #dek_snapshot{} | undefined) ->
          {ok, #dek_snapshot{}} | {error, _}.
read_deks(DekKind, PrevDekSnapshot) ->
    maybe
        {ok, {ActiveId, Ids, IsEnabled}} ?= cb_deks:list(DekKind),
        {Keys, Errors} = cb_deks:read(DekKind, Ids),
        {value, ActiveKey} ?=
            case Errors of
                #{ActiveId := Error} when IsEnabled ->
                    {error, {read_active_key_error, Error}};
                #{} when IsEnabled ->
                    lists:search(fun (#{id := Id}) -> Id == ActiveId end, Keys);
                #{} ->
                    {value, undefined}
            end,
        {ok, create_deks_snapshot(ActiveKey, Keys, PrevDekSnapshot)}
    else
        {error, Reason} ->
            ?log_error("Failed to read and set encryption keys for ~p: ~p",
                       [DekKind, Reason]),
            {error, Reason}
    end.

encrypt_to_file(IODevice, Bytes, MaxChunkSize, Compression, DekSnapshot) ->
    WriteChunks =
        fun EncryptAndWrite(<<>>, StateAcc) ->
                FinalData = file_encrypt_finish(StateAcc),
                case file:write(IODevice, FinalData) of
                    ok -> ok;
                    {error, _} = Error -> Error
                end;
            EncryptAndWrite(DataToWrite, StateAcc) ->
                {Chunk, Rest} =
                    case DataToWrite of
                        <<C:MaxChunkSize/binary, R/binary>> -> {C, R};
                        <<R/binary>> -> {R, <<>>}
                    end,
                {EncryptedChunk, NewStateAcc} =
                    file_encrypt_chunk(Chunk, StateAcc),
                case file:write(IODevice, EncryptedChunk) of
                    ok ->
                        EncryptAndWrite(Rest, NewStateAcc);
                    {error, _} = Error ->
                        _ = file_encrypt_finish(NewStateAcc),
                        Error
                end
        end,
    {Header, State} = file_encrypt_init(DekSnapshot,
                                        #{compression => Compression}),
    maybe
        ok ?= file:write(IODevice, Header),
        ok ?= WriteChunks(Bytes, State)
    end.

new_aes_gcm_iv(IVRandom, IVAtomic) ->
    %% For GCM IV must be unique, and don't have to be unpredictable
    IVCounter = atomics:add_get(IVAtomic, 1, 1),
    IV = <<IVRandom/binary, IVCounter:64/big-unsigned-integer>>,
    ?IV_LEN = size(IV),
    IV.

file_assoc_data(State) ->
    {Prefix, Offset} =
        case State of
            #file_encr_state{ad_prefix = P, offset = O} -> {P, O};
            #file_decr_state{ad_prefix = P, offset = O} -> {P, O}
        end,
    <<Prefix/binary, Offset:64/big-unsigned-integer>>.

decrypt_file_data(Data, GetDekSnapshotFun) ->
    case file_decrypt_init(Data, GetDekSnapshotFun) of
        {ok, {State, Chunks}} -> decrypt_all_chunks(State, Chunks, []);
        incomplete_magic -> {error, unknown_magic};
        %% Header is incomplete, but we know there is no more data, so we treat
        %% it as bad header
        need_more_data -> {error, invalid_file_encryption};
        {error, _} = E -> E
    end.

decrypt_all_chunks(State, Data, Acc) ->
    case file_decrypt_next_chunk(Data, State) of
        {ok, {NewState, Chunk, Rest}} ->
            decrypt_all_chunks(NewState, Rest, [Chunk | Acc]);
        eof ->
            maybe
                ok ?= file_decrypt_finish(State),
                {ok, iolist_to_binary(lists:reverse(Acc))}
            end;
        need_more_data ->
            file_decrypt_finish(State),
            {error, invalid_file_encryption}
    end.

-spec parse_header(binary()) ->
    {ok, {Vsn, KeyId, ADPrefix, Offset, CompressionType, Rest}} |
    incomplete_magic |
    need_more_data |
    {error, unknown_magic |
            bad_header |
            {unsupported_encryption_version, _}} when
    Vsn :: non_neg_integer(),
    KeyId :: binary(),
    ADPrefix :: binary(),
    Offset :: non_neg_integer(),
    CompressionType :: non_neg_integer(),
    Rest :: binary().
parse_header(<<Header:?ENCRYPTED_FILE_HEADER_LEN/binary, Rest/binary>>) ->
    %% Full header is present
    case Header of
        <<?ENCRYPTED_FILE_MAGIC, 0, CompressionType, _, _, _, _,
          36, Key:36/binary, _Salt:16/binary>> ->
            {ok, {0, Key, Header, ?ENCRYPTED_FILE_HEADER_LEN, CompressionType,
                  Rest}};
        <<?ENCRYPTED_FILE_MAGIC, 0, _/binary>> ->
            {error, bad_header};
        <<?ENCRYPTED_FILE_MAGIC, V, _/binary>> ->
            {error, {unsupported_encryption_version, V}};
        _ ->
            {error, unknown_magic}
    end;
parse_header(<<?ENCRYPTED_FILE_MAGIC, _/binary>>) ->
    %% File is encrypted but header is incomplete
    need_more_data;
parse_header(Data) ->
    DataSize = byte_size(Data),
    case DataSize > byte_size(<<?ENCRYPTED_FILE_MAGIC>>) of
        true -> {error, unknown_magic};
        false ->
            CommonPrefixSize = binary:longest_common_prefix(
                                 [Data, <<?ENCRYPTED_FILE_MAGIC>>]),
            case CommonPrefixSize == DataSize of
                true -> incomplete_magic;
                false -> {error, unknown_magic}
            end
    end.

-ifdef(TEST).

parse_header_test() ->
    Salt = crypto:strong_rand_bytes(16),
    Key = "7c8b0d58-2977-429c-8c0c-f9adaaac0919",
    KeyBin = list_to_binary(Key),
    Header = <<?ENCRYPTED_FILE_MAGIC, 0, ?NO_COMPRESSION, 0, 0, 0, 0,
               36, KeyBin/binary, Salt/binary>>,
    HeaderSize = byte_size(Header),
    ?assertEqual(?ENCRYPTED_FILE_HEADER_LEN, HeaderSize),
    LongData = crypto:strong_rand_bytes(HeaderSize * 2),
    ?assertEqual({ok, {0, KeyBin, Header, HeaderSize, ?NO_COMPRESSION, <<>>}},
                 parse_header(Header)),
    ?assertEqual({ok, {0, KeyBin, Header, HeaderSize, ?NO_COMPRESSION,
                       <<"Rest">>}},
                 parse_header(<<Header/binary, "Rest">>)),

    ?assertEqual(incomplete_magic, parse_header(<<>>)),
    ?assertEqual(incomplete_magic, parse_header(<<0>>)),
    ?assertEqual(incomplete_magic, parse_header(<<0, "Couchbase">>)),
    ?assertEqual({error, unknown_magic}, parse_header(<<1>>)),
    ?assertEqual({error, unknown_magic}, parse_header(<<1, LongData/binary>>)),

    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0, 0, 0>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0, 0, 0, 0, 0, 36>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0, 0, 0, 0, 0, 36,
                                1>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0, 0, 0, 0, 0, 36,
                                KeyBin/binary>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 0, 0, 0, 0, 0, 36,
                                KeyBin/binary, 1,2,3>>)),

    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 2>>)),
    ?assertEqual({error, {unsupported_encryption_version, 2}},
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 2, LongData/binary>>)),
    ?assertEqual(need_more_data,
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 2>>)),
    ?assertEqual({error, bad_header},
                 parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, 2, 0, 0, 0, 0, 37,
                              LongData/binary>>)).

-endif.

bite_next_chunk(<<ChunkSize:32/big-unsigned-integer, Chunk:ChunkSize/binary,
                   Rest/binary>>) ->
    DataSize = ChunkSize - ?IV_LEN - ?TAG_LEN,
    case DataSize > 0 of
        true -> {ok, {ChunkSize + ?CHUNKSIZE_ATTR_SIZE, Chunk}, Rest};
        false -> {error, invalid_data_chunk}
    end;
bite_next_chunk(<<>>) ->
    eof;
bite_next_chunk(<<_/binary>>) ->
    need_more_data.

find_key(WantedId, #dek_snapshot{all_keys = AllDeks}) ->
    case lists:search(fun (#{id := Id}) -> Id == WantedId end, AllDeks) of
        {value, Key} -> {ok, Key};
        false -> {error, key_not_found}
    end.

read_file_header(Path) ->
    maybe
        {ok, File} ?= file:open(Path, [read, raw, binary]),
        try
            file:read(File, ?ENCRYPTED_FILE_HEADER_LEN)
        after
            file:close(File)
        end
    end.

-ifdef(TEST).

decrypt_file_data_test() ->
    DS = generate_test_deks(),
    Data1 = <<"123">>,
    Data2 = <<"456">>,
    LongData = crypto:strong_rand_bytes(?ENCRYPTED_FILE_HEADER_LEN * 2),
    {Header, State0} = file_encrypt_init(DS),
    {Chunk1, State1} = file_encrypt_chunk(Data1, State0),
    {Chunk2, _State2} = file_encrypt_chunk(Data2, State1),
    {ok, <<>>} = decrypt_file_data(Header, DS),
    {ok, Data1} = decrypt_file_data(<<Header/binary, Chunk1/binary>>, DS),
    Data1Data2 = <<Data1/binary, Data2/binary>>,
    {ok, Data1Data2} =
        decrypt_file_data(<<Header/binary, Chunk1/binary, Chunk2/binary>>, DS),

    {error, unknown_magic} = decrypt_file_data(<<>>, DS),
    {error, unknown_magic} = decrypt_file_data(<<0>>, DS),
    {error, unknown_magic} = decrypt_file_data(<<0, "Couch">>, DS),
    {error, unknown_magic} = decrypt_file_data(<<1, 2, 3>>, DS),
    {error, invalid_file_encryption} =
        decrypt_file_data(<<?ENCRYPTED_FILE_MAGIC>>, DS),
    {error, invalid_file_encryption} =
        decrypt_file_data(<<?ENCRYPTED_FILE_MAGIC, 123>>, DS),
    {error, invalid_file_encryption} =
        decrypt_file_data(<<?ENCRYPTED_FILE_MAGIC, 0, 123>>, DS),
    {error, invalid_file_encryption} =
        decrypt_file_data(<<?ENCRYPTED_FILE_MAGIC, 0, ?NO_COMPRESSION>>, DS),
    {error, {unsupported_compression_type, 23}} =
        decrypt_file_data(<<?ENCRYPTED_FILE_MAGIC, 0, 23, 0, 0, 0, 0, 36,
                            LongData/binary>>, DS).

read_write_file_test() ->
    Path = path_config:tempfile("cb_crypto_test", ".tmp"),
    Bin = iolist_to_binary(lists:seq(0,255)),
    DS = generate_test_deks(),
    try
        ok = misc:atomic_write_file(Path, Bin),
        {raw, Bin} = read_file(Path, DS),
        ok = atomic_write_file(Path, Bin, DS, #{max_chunk_size => 7}),
        {decrypted, Bin} = read_file(Path, DS),
        %% Note that chunks are actually reversed here:
        {ok, Chunks1} = read_file_chunks(Path,
                                         fun (C, Acc) -> {ok, [C | Acc]} end,
                                         [], DS, #{read_chunk_size => 11}),
        {ok, Chunks2} = read_file_chunks(Path,
                                         fun (C, Acc) -> {ok, [C | Acc]} end,
                                         [], DS, #{read_chunk_size => 7}),
        {ok, Chunks3} = read_file_chunks(Path,
                                         fun (C, Acc) -> {ok, [C | Acc]} end,
                                         [], DS, #{read_chunk_size => 3}),
        {ok, Chunks4} = read_file_chunks(Path,
                                         fun (C, Acc) -> {ok, [C | Acc]} end,
                                         [], DS,
                                         #{read_chunk_size => 1000000000}),
        %% All chunks should be the same. It should not matter how we read them
        Chunks1 = Chunks2,
        Chunks1 = Chunks3,
        Chunks1 = Chunks4,
        %% Last chunk should be 4 byte chunk, other chunks should be 7 bytes.
        [LastChunk | OtherChunks] = Chunks1,
        4 = byte_size(LastChunk),
        [7] = lists:uniq([byte_size(C) || C <- OtherChunks]),

        %% If we concatenate all chunks, we should get the original data
        Bin = iolist_to_binary(lists:reverse(Chunks1))
    after
        file:delete(Path)
    end.

read_write_compressed_file_test_() ->
    Bin = rand:bytes(1024 * 1024),
    DS = generate_test_deks(),
    Chunks = [1024, 1024 * 1024 * 2, 101],
    Levels = [1, 9],
    FlushTypes = [full, sync, none],
    [?_test(read_write_compressed_file_test_parametrized(Bin, DS, X, Y, Z, W))
     || X <- Chunks, Y <- Chunks, Z <- Levels, W <- FlushTypes].

read_write_compressed_file_test_parametrized(Bin, DS, WriteChunkSize,
                                             ReadChunkSize, Level, FlushType) ->
    Path = path_config:tempfile("cb_crypto_test", ".tmp"),
    try
        ok = atomic_write_file(Path, Bin, DS,
                               #{max_chunk_size => WriteChunkSize,
                                 compression => {zlib, Level, FlushType}}),
        {decrypted, Bin} = read_file(Path, DS),
        %% Note that chunks are actually reversed here:
        {ok, Chunks1} = read_file_chunks(
                          Path,
                          fun (C, Acc) -> {ok, [C | Acc]} end,
                          [], DS, #{read_chunk_size => ReadChunkSize}),
        %% If we concatenate all chunks, we should get the original data
        Bin = iolist_to_binary(lists:reverse(Chunks1))
    after
        file:delete(Path)
    end.

validate_encr_file_test() ->
    %% Generate valid header and chunk data and assemble and test for various
    %% cases
    Path = path_config:tempfile("cb_crypto_validate_encr_file_test", ".tmp"),
    try
        DS = generate_test_deks(),
        {ValidHeader, State} = file_encrypt_init(DS),

        Bin1 = iolist_to_binary(lists:seq(0,255)),
        {Data1, State1} = file_encrypt_chunk(Bin1, State),

        Bin2 = iolist_to_binary(lists:seq(0,1)),
        {Data2,State2} = file_encrypt_chunk(Bin2, State1),

        Bin3 = iolist_to_binary(lists:seq(0,64)),
        {Data3, _} = file_encrypt_chunk(Bin3, State2),

        %% File with just header is valid encrypted file
        ok = misc:atomic_write_file(Path, ValidHeader),
        ?assert(validate_encr_file(Path)),

        %% File with trash after header is invalid
        ok = misc:atomic_write_file(Path, <<ValidHeader/binary, "t">>),
        ?assertNot(validate_encr_file(Path)),

        %% Full valid file
        FullValid =
            <<ValidHeader/binary, Data1/binary, Data2/binary, Data3/binary>>,
        ok = misc:atomic_write_file(Path, FullValid),
        ?assert(validate_encr_file(Path)),

        %% Full valid file with trailing trash is invalid
        ok = misc:atomic_write_file(Path, <<FullValid/binary, "t">>),
        ?assertNot(validate_encr_file(Path)),

        %% Partial first chunk with everything else in place is invalid
        InvalidSize = byte_size(Data1) - 1,
        InvalidFileData =
            <<ValidHeader/binary, Data1:InvalidSize/binary, Data2/binary,
              Data3/binary>>,
        ok = misc:atomic_write_file(Path, InvalidFileData),
        ?assertNot(validate_encr_file(Path))
    after
        file:delete(Path)
    end.

generate_test_deks() ->
    KeyBin = cb_cluster_secrets:generate_raw_key(aes_256_gcm),
    Key = #{id => cb_cluster_secrets:new_key_id(),
            type => 'raw-aes-gcm',
            info => #{key => fun () -> KeyBin end,
                      encryption_key_id => <<"encryptionService">>,
                      creation_time => {{2024, 01, 01}, {22, 00, 00}}}},
    cb_crypto:create_deks_snapshot(Key, [Key], undefined).

-endif.
