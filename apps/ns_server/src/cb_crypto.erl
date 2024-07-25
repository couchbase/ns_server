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

-define(ENCRYPTED_FILE_HEADER_LEN, 64).
-define(IV_LEN, 12).
-define(TAG_LEN, 16).
-define(ENCRYPTED_FILE_MAGIC, 0, "Couchbase Encrypted File", 0).

-export([%% Encryption/decryption functions:
         encrypt/3,
         decrypt/3,

         atomic_write_file/3,
         atomic_write_file/4,
         file_encrypt_init/2,
         file_encrypt_chunk/2,

         read_file/2,
         file_decrypt_init/3,
         file_decrypt_next_chunk/2,

         new_aes_gcm_iv/1,

         %% Manage deks in persistent_term storage:
         fetch_deks_snapshot/1,
         create_deks_snapshot/3,
         reset_dek_cache/2,
         get_all_deks/1,
         get_dek_id/1,
         get_dek/1,
         without_historical_deks/1,

         %% Other:
         get_encryption_method/2
        ]).

-record(dek_snapshot, {iv_random :: binary(),
                       iv_atomic_counter :: atomics:atomics_ref(),
                       active_key :: cb_deks:dek() | undefined,
                       all_keys :: [cb_deks:dek()]}).

-record(file_encr_state, {filename = <<>> :: binary(),
                          key :: cb_deks:dek() | undefined,
                          iv_random :: binary(),
                          iv_atomic_counter :: atomics:atomics_ref() ,
                          offset :: non_neg_integer()}).

-record(file_decr_state, {vsn :: non_neg_integer(),
                          filename = <<>> :: binary(),
                          key :: cb_deks:dek(),
                          offset = 0 :: non_neg_integer()}).

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
                        #{max_chunk_size => pos_integer()}) ->
          ok | {error, term()}.
atomic_write_file(Path, List, DekSnapshot, Opts) when is_list(List) ->
    atomic_write_file(Path, iolist_to_binary(List), DekSnapshot, Opts);
atomic_write_file(Path, Bytes, DekSnapshot, Opts) when is_binary(Bytes) ->
    MaxChunkSize = maps:get(max_chunk_size, Opts, 65536),
    misc:atomic_write_file(
      Path,
      fun (IODevice) ->
          Filename = filename:basename(Path),
          encrypt_to_file(IODevice, Filename, Bytes, MaxChunkSize, DekSnapshot)
      end).

-spec file_encrypt_init(string(), #dek_snapshot{}) ->
          {binary(), #file_encr_state{}}.
file_encrypt_init(Filename,
                  #dek_snapshot{active_key = ActiveKey,
                                iv_random = IVRandom,
                                iv_atomic_counter = IVCounter}) ->
    Header =
        case ActiveKey of
            undefined -> <<>>;
            #{id := Id} ->
                Len = size(Id),
                Vsn = 0,
                H = <<?ENCRYPTED_FILE_MAGIC, Vsn, Len, Id/binary>>,
                ?ENCRYPTED_FILE_HEADER_LEN = size(H),
                H
        end,
    {Header, #file_encr_state{filename = iolist_to_binary(Filename),
                              key = ActiveKey,
                              iv_random = IVRandom,
                              iv_atomic_counter = IVCounter,
                              offset = size(Header)}}.

-spec file_encrypt_chunk(binary(), #file_encr_state{}) ->
          {binary(), #file_encr_state{}}.
file_encrypt_chunk(Data, #file_encr_state{key = undefined} = State) ->
    {Data, State};
file_encrypt_chunk(Data, #file_encr_state{key = Dek,
                                          iv_random = IVRandom,
                                          iv_atomic_counter = IVAtomic,
                                          offset = Offset} = State) ->
    AD = file_assoc_data(State),
    Chunk = encrypt_internal(Data, AD, IVRandom, IVAtomic, Dek),
    ChunkSize = size(Chunk),
    ChunkWithSize = <<ChunkSize:32/big-unsigned-integer, Chunk/binary>>,
    NewOffset = Offset + size(ChunkWithSize),
    {ChunkWithSize, State#file_encr_state{offset = NewOffset}}.

-spec read_file(string(), cb_deks:dek_kind()) -> {decrypted, binary()} |
                                                 {raw, binary()} |
                                                 {error, term()}.
read_file(Path, DekKind) ->
    maybe
        {ok, Data} ?= file:read_file(Path),
        Filename = filename:basename(Path),
        case decrypt_file_data(Data, Filename, DekKind) of
            {ok, Decrypted} ->
                {decrypted, Decrypted};
            {error, unknown_magic} ->
                %% File is not encrypted?
                {raw, Data};
            {error, _} = Error ->
                Error
        end
    end.

-spec file_decrypt_init(binary(), string(), #dek_snapshot{}) ->
          {ok, {#file_decr_state{}, RestData :: binary()}} |
          need_more_data |
          {error, term()}.
file_decrypt_init(Data, Filename, DekSnapshot) ->
    maybe
        {ok, {Vsn, Id, Offset, Chunks}} ?= parse_header(Data),
        {ok, Dek} ?= find_key(Id, DekSnapshot),
        State = #file_decr_state{vsn = Vsn,
                                 filename = iolist_to_binary(Filename),
                                 key = Dek,
                                 offset = Offset},
        {ok, {State, Chunks}}
    end.

-spec file_decrypt_next_chunk(binary(), #file_decr_state{}) ->
          {ok, {NewState :: #file_decr_state{},
                DecryptedChunk :: binary(),
                RestData :: binary()}} |
          need_more_data | eof | {error, term()}.
file_decrypt_next_chunk(Data, #file_decr_state{vsn = 0,
                                               key = Dek,
                                               offset = Offset} = State) ->
    case bite_next_chunk(Data) of
        {ok, {SizeEaten, Chunk}, Rest} ->
            AD = file_assoc_data(State),
            case decrypt_internal(Chunk, AD, [Dek]) of
                {ok, DecryptedData} ->
                    NewOffset = Offset + SizeEaten,
                    NewState = State#file_decr_state{offset = NewOffset},
                    {ok, {NewState, DecryptedData, Rest}};
                {error, _} = Error ->
                    Error
            end;
        eof -> eof;
        need_more_data -> need_more_data;
        {error, _} = Error -> Error
    end.

-spec new_aes_gcm_iv(#dek_snapshot{}) -> binary().
new_aes_gcm_iv(#dek_snapshot{iv_random = IVRandom,
                             iv_atomic_counter = IVAtomic}) ->
    new_aes_gcm_iv(IVRandom, IVAtomic).

-spec fetch_deks_snapshot(cb_deks:dek_kind()) -> {ok, #dek_snapshot{}} |
                                                 {error, term()}.
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

-spec reset_dek_cache(cb_deks:dek_kind(), cb_deks:dek()) ->
          {ok, changed | unchanged} | {error, term()}.
reset_dek_cache(DekKind, NewActiveDek) ->
    %% Technically we can simply erase the persistent term, but it will result
    %% in two global GC's then (erase and set). So we read and set new value
    %% instead, which gives us only one global GC.
    cb_atomic_persistent_term:set(
      {encryption_keys, DekKind},
      fun (PrevSnapshot) ->
          case get_dek_id(PrevSnapshot) =/= get_dek_id(NewActiveDek) of
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

-spec get_encryption_method(config_encryption,
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

%%%===================================================================
%%% Internal functions
%%%===================================================================

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
        {ok, Keys} ?= cb_deks:read(DekKind, Ids),
        {value, ActiveKey} =
            case IsEnabled of
                true ->
                    lists:search(fun (#{id := Id}) -> Id == ActiveId end, Keys);
                _ ->
                    {value, undefined}
            end,
        {ok, create_deks_snapshot(ActiveKey, Keys, PrevDekSnapshot)}
    else
        {error, Reason} ->
            ?log_error("Failed to read and set encryption keys for ~p: ~p",
                       [DekKind, Reason]),
            {error, Reason}
    end.

encrypt_to_file(IODevice, Filename, Bytes, MaxChunkSize, DekSnapshot) ->
    WriteChunks =
        fun EncryptAndWrite(<<>>, _StateAcc) ->
                ok;
            EncryptAndWrite(DataToWrite, StateAcc) ->
                {Chunk, Rest} =
                    case DataToWrite of
                        <<C:MaxChunkSize/binary, R/binary>> -> {C, R};
                        <<R/binary>> -> {R, <<>>}
                    end,
                {EncryptedChunk, NewStateAcc} =
                    file_encrypt_chunk(Chunk, StateAcc),
                case file:write(IODevice, EncryptedChunk) of
                    ok -> EncryptAndWrite(Rest, NewStateAcc);
                    {error, _} = Error -> Error
                end
        end,
    {Header, State} = file_encrypt_init(Filename, DekSnapshot),
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
    {Filename, Offset} =
        case State of
            #file_encr_state{filename = F, offset = O} -> {F, O};
            #file_decr_state{filename = F, offset = O} -> {F, O}
        end,
    <<Filename/binary, ":", (integer_to_binary(Offset))/binary>>.

decrypt_file_data(Data, Filename, DekKind) ->
    maybe
        {ok, DekSnapshot} ?= fetch_deks_snapshot(DekKind),
        {ok, {State, Chunks}} ?= file_decrypt_init(Data, Filename, DekSnapshot),
        {ok, _} ?= decrypt_all_chunks(State, Chunks, <<>>)
    else
        need_more_data ->
            {error, invalid_file_encryption};
        {error, Reason} ->
            {error, Reason}
    end.

decrypt_all_chunks(State, Data, Acc) ->
    case file_decrypt_next_chunk(Data, State) of
        {ok, {NewState, Chunk, Rest}} ->
            decrypt_all_chunks(NewState, Rest, <<Acc/binary, Chunk/binary>>);
        eof ->
            {ok, Acc};
        need_more_data ->
            {error, invalid_file_encryption}
    end.

parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, KeyLen, HeaderTail:36/binary,
             Rest/binary>>) ->
    case KeyLen =< 36 of
        true ->
            <<Key:KeyLen/binary, _/binary>> = HeaderTail,
            {ok, {0, Key, ?ENCRYPTED_FILE_HEADER_LEN, Rest}};
        false ->
            {error, invalid_encryption_header}
    end;
parse_header(<<?ENCRYPTED_FILE_MAGIC, 0, _/binary>>) ->
    need_more_data;
parse_header(<<?ENCRYPTED_FILE_MAGIC, V, _/binary>>) ->
    {error, {unsupported_encryption_version, V}};
parse_header(_) ->
    {error, unknown_magic}.

bite_next_chunk(<<ChunkSize:32/big-unsigned-integer, Chunk:ChunkSize/binary,
                   Rest/binary>>) ->
    DataSize = ChunkSize - ?IV_LEN - ?TAG_LEN,
    case DataSize > 0 of
        true -> {ok, {ChunkSize + 4, Chunk}, Rest};
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
