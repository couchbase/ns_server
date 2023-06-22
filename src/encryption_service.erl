-module(encryption_service).

-export([decrypt/1,
         encrypt/1,
         change_password/1,
         get_keys_ref/0,
         rotate_data_key/0,
         maybe_clear_backup_key/1,
         get_state/0,
         os_pid/0]).

-define(RUNNER, {cb_gosecrets_runner, ns_server:get_babysitter_node()}).

encrypt(Data) ->
    cb_gosecrets_runner:encrypt(?RUNNER, Data).

decrypt(Data) ->
    cb_gosecrets_runner:decrypt(?RUNNER, Data).

change_password(NewPassword) ->
    cb_gosecrets_runner:change_password(?RUNNER, NewPassword).

get_keys_ref() ->
    cb_gosecrets_runner:get_keys_ref(?RUNNER).

get_state() ->
    cb_gosecrets_runner:get_state(?RUNNER).

rotate_data_key() ->
    cb_gosecrets_runner:rotate_data_key(?RUNNER).

maybe_clear_backup_key(DataKey) ->
    cb_gosecrets_runner:maybe_clear_backup_key(?RUNNER, DataKey).

os_pid() ->
    cb_gosecrets_runner:os_pid(?RUNNER).
