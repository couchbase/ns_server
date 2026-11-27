%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_aws_kms_ear_key).

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([persist/3,
         test_props/3]).

-export_type([secret_props/0]).

-type secret_props() :: #{key_arn := string(),
                          region := string(),
                          profile := string(),
                          config_file := string(),
                          credentials_file := string(),
                          use_imds := boolean(),
                          req_timeout_ms => integer(),
                          stored_ids := [cb_kms_ear_key:key_props()],
                          last_rotation_time := calendar:datetime()}.

-spec persist(secret_props(), binary(), list()) -> ok | {error, _}.
persist(Props, _ExtraAD, _) ->
    ensure_aws_kek_on_disk(Props, false).

-spec test_props(secret_props(), binary(), list()) -> ok | {error, _}.
test_props(#{stored_ids := [StoredId | _]} = Props, _ExtraAD, _) ->
    %% We don't want to test all stored ids
    PropsWithoutHistKeys = Props#{stored_ids => [StoredId]},
    case ensure_aws_kek_on_disk(PropsWithoutHistKeys, true) of
        ok -> ok;
        {error, [{_, Reason}]} -> {error, Reason};
        {error, _} = E -> E
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

ensure_aws_kek_on_disk(#{stored_ids := StoredIds} = Props, TestOnly) ->
    %% Keys created before 8.5 have no req_timeout_ms
    Params = maps:merge(#{req_timeout_ms => ?AWSKMS_DEFAULT_REQ_TIMEOUT_MS},
                        maps:with([key_arn, region, profile, config_file,
                                   credentials_file, use_imds, req_timeout_ms],
                                  Props)),
    Res = lists:map(
            fun (#{id := Id, creation_time := CreationTime}) ->
                {Id, encryption_service:store_aws_key(Id, Params, CreationTime,
                                                      TestOnly)}
            end, StoredIds),
    misc:many_to_one_result(Res).

-ifdef(TEST).
persist_test_() ->
    Props80 = #{key_arn => "TEST_AWS_KEY_ARN", region => "", profile => "",
                config_file => "", credentials_file => "", use_imds => false,
                stored_ids => [#{id => <<"0d9c2c6e">>,
                                 creation_time => {{2025, 1, 1}, {0, 0, 0}}}],
                last_rotation_time => {{2025, 1, 1}, {0, 0, 0}}},
    StoredTimeout =
        fun (P) ->
                ok = persist(P, <<>>, []),
                KeyData = meck:capture(last, cb_gosecrets_runner, store_key,
                                       '_', 6),
                {Fields} = ejson:decode(KeyData),
                proplists:get_value(<<"reqTimeoutMs">>, Fields)
        end,
    {setup,
     fun () ->
             meck:new(ns_server, [passthrough]),
             meck:expect(ns_server, get_babysitter_node, fun () -> node() end),
             meck:new(cb_gosecrets_runner),
             meck:expect(cb_gosecrets_runner, store_key, 7,
                         fun (_, _, _, _, _, _, _) -> ok end)
     end,
     fun (_) -> meck:unload() end,
     [{"props stored before 8.5",
       ?_assertEqual(?AWSKMS_DEFAULT_REQ_TIMEOUT_MS, StoredTimeout(Props80))},
      {"props with req_timeout_ms",
       ?_assertEqual(5000, StoredTimeout(Props80#{req_timeout_ms => 5000}))}]}.
-endif.
