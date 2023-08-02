%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(menelaus_web_guardrails).

-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_test.hrl").
-endif.


-export([default_config/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------


%% Gets resource management configuration from the config profile, using default
%% values specified below
-spec default_config() -> proplists:proplist().
default_config() ->
    %% Override defaults with any values specified in the config profile
    [{resource_management,
      lists:foldl(
        fun update_sub_config/2, raw_default_config(),
        config_profile:get_value(resource_management, []))}].

%% Default config, without being overriden by config profile
raw_default_config() ->
    [].

update_sub_config({[], Value}, _) ->
    Value;
update_sub_config({[Key | Keys], Value}, []) ->
    [{Key, update_sub_config({Keys, Value}, [])}];
update_sub_config({[Key | Keys], Value}, SubConfig) ->
    lists:keyreplace(Key, 1, SubConfig,
                     {Key,
                      update_sub_config({Keys, Value},
                                        proplists:get_value(Key, SubConfig,
                                                            []))}).

-ifdef(TEST).

default_config_test() ->
    assert_config_equal([{resource_management, raw_default_config()}],
                        default_config()).

assert_config_equal(Expected, Found) when is_list(Expected)->
    ?assert(is_list(Found)),
    ?assertListsEqual(proplists:get_keys(Expected), proplists:get_keys(Found)),
    lists:foreach(
      fun (Key) ->
              case proplists:get_value(Key, Expected) of
                  ExpectedList when is_list(ExpectedList) ->
                      FoundList = proplists:get_value(Key, Found),
                      ?assert(is_list(FoundList)),
                      assert_config_equal(ExpectedList, FoundList);
                  Value ->
                      ?assertEqual(Value, proplists:get_value(Key, Found))
              end
      end, proplists:get_keys(Expected)).

update_configs_test() ->
    %% Test update_sub_config alone
    ?assertEqual(value1,
                 update_sub_config({[], value1}, [])),
    assert_config_equal([{key1, value1}],
                        update_sub_config({[key1], value1}, [])),
    assert_config_equal([{key1, [{key2, value2}]}],
                        update_sub_config({[key1, key2], value2}, [])),
    assert_config_equal([{key1, [{key2, value2}]}],
                        update_sub_config({[key1, key2], value2},
                                          [{key1, []}])),
    assert_config_equal([{key1, [{key2, value2}]},
                         {key3, [{key4, value4}]}],
                        update_sub_config({[key1, key2], value2},
                                          [{key1, []},
                                           {key3, [{key4, value4}]}])).

-endif.
