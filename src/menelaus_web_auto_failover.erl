%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_auto_failover).

-include("cut.hrl").
-include("ns_common.hrl").

-export([handle_settings_get/1,
         handle_settings_post/1,
         handle_settings_reset_count/1,
         get_failover_on_disk_issues/1,
         config_check_can_abort_rebalance/0,
         default_config/1,
         config_upgrade_to_elixir/1]).

-import(menelaus_util,
        [reply/2,
         reply_json/2]).

-define(AUTO_FAILOVER_MIN_TIMEOUT, ?get_param(auto_failover_min_timeout, 5)).
-define(AUTO_FAILOVER_MIN_CE_TIMEOUT, 30).
-define(AUTO_FAILOVER_MAX_TIMEOUT, 3600).

-define(CAN_ABORT_REBALANCE_CONFIG_KEY, can_abort_rebalance).
-define(DATA_DISK_ISSUES_CONFIG_KEY, failover_on_data_disk_issues).
-define(MIN_DATA_DISK_ISSUES_TIMEPERIOD, 5). %% seconds
-define(MAX_DATA_DISK_ISSUES_TIMEPERIOD, 3600). %% seconds

-define(FAILOVER_SERVER_GROUP_CONFIG_KEY, failover_server_group).

-define(DISABLE_MAX_COUNT_CONFIG_KEY, disable_max_count).
-define(MAX_EVENTS_CONFIG_KEY, max_count).
-define(MIN_EVENTS_ALLOWED, 1).
-define(DEFAULT_EVENTS_ALLOWED, 1).

default_config(IsEnterprise) ->
    [{auto_failover_cfg,
      [{enabled, true},
       % timeout is the time (in seconds) a node needs to be
       % down before it is automatically faileovered
       {timeout, 120},
       % count is the number of nodes that were auto-failovered
       {count, 0},
       {failover_on_data_disk_issues, [{enabled, false},
                                       {timePeriod, 120}]},
       {failover_server_group, false},
       {disable_max_count, config_profile:get_bool(failover_disable_max_count)},
       {max_count, 1},
       {failed_over_server_groups, []},
       {?CAN_ABORT_REBALANCE_CONFIG_KEY, IsEnterprise}]}].

max_events_allowed() ->
    case cluster_compat_mode:is_cluster_71() of
        true ->
            100;
        false ->
            3
    end.

config_upgrade_to_elixir(Config) ->
    [{set, auto_failover_cfg,
      proplists:delete(can_abort_rebalance, auto_failover:get_cfg(Config)) ++
      [{disable_max_count,
        config_profile:get_bool(failover_disable_max_count)}]}].

handle_settings_get(Req) ->
    Config = auto_failover:get_cfg(),
    Enabled = proplists:get_value(enabled, Config),
    Timeout = proplists:get_value(timeout, Config),
    Count = proplists:get_value(count, Config),
    Settings0 = [{enabled, Enabled}, {timeout, Timeout}, {count, Count}],
    Settings =  Settings0 ++ get_extra_settings(Config),
    reply_json(Req, {Settings}).

handle_settings_post_validated(Req, Props) ->
    Config = auto_failover:get_cfg(),
    case proplists:get_value(enabled, Props) of
        true ->
            Timeout = proplists:get_value(timeout, Props),
            case cluster_compat_mode:is_enterprise() of
                true ->
                    %% maxCount will not be set pre-upgrade so use the default.
                    CurrMax = proplists:get_value(?MAX_EVENTS_CONFIG_KEY,
                                                  Config,
                                                  ?DEFAULT_EVENTS_ALLOWED),
                    MaxCount = proplists:get_value(maxCount, Props, CurrMax);
                false ->
                    %% maxCount will not be set for CE so use the default.
                    MaxCount = proplists:get_value(maxCount, Props,
                                                   ?DEFAULT_EVENTS_ALLOWED)
            end,
            Extras = process_extras(Props, Config),
            auto_failover:enable(Timeout, MaxCount, Extras),
            ns_audit:enable_auto_failover(Req, Timeout, MaxCount, Extras);
        false ->
            auto_failover:disable(disable_extras(Config)),
            ns_audit:disable_auto_failover(Req)
    end,
    reply(Req, 200).

handle_settings_post(Req) ->
    validator:handle(
      handle_settings_post_validated(Req, _), Req, form,
      settings_validators() ++
      [validator:unsupported(_)]).

%% @doc Resets the number of nodes that were automatically failovered to zero
handle_settings_reset_count(Req) ->
    auto_failover:reset_count(),
    ns_audit:reset_auto_failover_count(Req),
    reply(Req, 200).

get_failover_on_disk_issues(Config) ->
    case proplists:get_value(?DATA_DISK_ISSUES_CONFIG_KEY, Config) of
        undefined ->
            undefined;
        Val ->
            Enabled = proplists:get_value(enabled, Val),
            TimePeriod = proplists:get_value(timePeriod, Val),
            {Enabled, TimePeriod}
    end.

%% Internal Functions
get_min_timeout() ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            ?AUTO_FAILOVER_MIN_TIMEOUT;
        false ->
            ?AUTO_FAILOVER_MIN_CE_TIMEOUT
    end.

validate_enabled_param(KeyEnabled, KeyTime, State) ->
    validator:validate_multiple(
      fun ([EVal, TVal]) ->
              case {EVal, TVal =:= undefined} of
                  {true, true} ->
                      {error,
                       io_lib:format("~s is true. A value must be supplied for "
                                     "~s", [KeyEnabled, KeyTime])};
                  {undefined, false} ->
                      {error,
                       io_lib:format("~s must be true for ~s to take effect",
                                     [KeyEnabled, KeyTime])};
                  {_, _} -> ok
              end
      end, [KeyEnabled, KeyTime], State).

validate_maxcount_param(State) ->
    ErrMsg = "disableMaxCount is true. Set it to false for maxCount to take "
             "effect.",
    validator:validate_multiple(
        fun ([Disabled, Count]) ->
            case {Disabled, Count =/= undefined} of
                {true, true} -> {error, ErrMsg};
                {undefined, true} ->
                    Config = auto_failover:get_cfg(),
                    DisabledMax = proplists:get_value(
                                    ?DISABLE_MAX_COUNT_CONFIG_KEY, Config),
                    case DisabledMax of
                        true -> {error, ErrMsg};
                        false -> ok
                    end;
                {_, _} -> ok
            end
        end, [disableMaxCount, maxCount], State).

settings_validators() ->
    [validator:required(enabled, _),
     validator:boolean(enabled, _),
     validator:integer(timeout, get_min_timeout(),
                       ?AUTO_FAILOVER_MAX_TIMEOUT, _),
     validate_enabled_param(enabled, timeout, _)] ++
    settings_extras_validators().

settings_extras_validators() ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            maxcount_validators() ++
            disk_issues_validators() ++
            server_group_validators() ++
            can_abort_rebalance_validators();
        false ->
            []
    end.

maxcount_validators() ->
    [validator:integer(maxCount, ?MIN_EVENTS_ALLOWED,
        max_events_allowed(), _)] ++
    case cluster_compat_mode:is_cluster_elixir() of
        true ->
            [validator:boolean(disableMaxCount, _),
             validate_maxcount_param(_)];
        false -> []
    end.

disk_issues_validators() ->
    KeyEnabled = 'failoverOnDataDiskIssues[enabled]',
    KeyTimePeriod = 'failoverOnDataDiskIssues[timePeriod]',
    [validator:boolean(KeyEnabled, _),
     validator:integer(KeyTimePeriod, ?MIN_DATA_DISK_ISSUES_TIMEPERIOD,
                       ?MAX_DATA_DISK_ISSUES_TIMEPERIOD, _),
     validate_enabled_param(KeyEnabled, KeyTimePeriod, _)].

server_group_validators() ->
    case cluster_compat_mode:is_cluster_71() of
        false ->
            [validator:boolean(failoverServerGroup, _)];
        true ->
            []
    end.

can_abort_rebalance_validators() ->
    case cluster_compat_mode:is_cluster_elixir() of
        false ->
            [validator:boolean(canAbortRebalance, _)];
        true ->
            []
    end.

process_failover_on_disk_issues(Props, Config, Extras) ->
    KeyEnabled = 'failoverOnDataDiskIssues[enabled]',
    KeyTimePeriod = 'failoverOnDataDiskIssues[timePeriod]',
    TimePeriod = proplists:get_value(KeyTimePeriod, Props),
    DiskEnabled = proplists:get_value(KeyEnabled, Props),
    case DiskEnabled of
        true ->
            Extra = set_failover_on_disk_issues(true, TimePeriod),
            add_extras(Extra, Extras);
        false ->
            {_, CurrTP} = get_failover_on_disk_issues(Config),
            Extra = disable_failover_on_disk_issues(CurrTP),
            add_extras(Extra, Extras);
        undefined ->
            Extras
    end.

process_boolean_extra(Props, Name, ConfigKey, Extras) ->
    CVal = proplists:get_value(Name, Props),
    case CVal of
        Val when is_boolean(Val) ->
            Extra = [{ConfigKey, Val}],
            add_extras(Extra, Extras);
        _ ->
            Extras
    end.

process_extras(Props, Config) ->
    BoolParams = [{failoverServerGroup, ?FAILOVER_SERVER_GROUP_CONFIG_KEY},
                  {canAbortRebalance, ?CAN_ABORT_REBALANCE_CONFIG_KEY},
                  {disableMaxCount, ?DISABLE_MAX_COUNT_CONFIG_KEY}],
    Extras = functools:chain(
               [{extras, []}],
               [process_failover_on_disk_issues(Props, Config, _) |
                [process_boolean_extra(Props, Name, ConfigKey, _) ||
                    {Name, ConfigKey} <- BoolParams]]),
    proplists:get_value(extras, Extras).

disable_failover_on_disk_issues(TP) ->
    set_failover_on_disk_issues(false, TP).

set_failover_on_disk_issues(Enabled, TP) ->
    [{?DATA_DISK_ISSUES_CONFIG_KEY, [{enabled, Enabled}, {timePeriod, TP}]}].

add_extras(Add, CurrRV) ->
    {extras, Old} = lists:keyfind(extras, 1, CurrRV),
    lists:keyreplace(extras, 1, CurrRV, {extras, Add ++ Old}).

config_check_can_abort_rebalance() ->
    proplists:get_value(?CAN_ABORT_REBALANCE_CONFIG_KEY,
                        auto_failover:get_cfg(),
                        cluster_compat_mode:is_cluster_elixir()).

get_extra_settings(Config) ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            DisableMaxCount = proplists:get_value(
                                ?DISABLE_MAX_COUNT_CONFIG_KEY, Config, false),
            {Enabled, TimePeriod} = get_failover_on_disk_issues(Config),
            lists:flatten(
              [{failoverOnDataDiskIssues,
                {[{enabled, Enabled}, {timePeriod, TimePeriod}]}},
               [{disableMaxCount, DisableMaxCount} ||
                   cluster_compat_mode:is_cluster_elixir()],
               [{maxCount, proplists:get_value(?MAX_EVENTS_CONFIG_KEY,
                                               Config)} ||
                   not DisableMaxCount],
               [{canAbortRebalance,
                 proplists:get_value(
                   ?CAN_ABORT_REBALANCE_CONFIG_KEY, Config)} ||
                   not cluster_compat_mode:is_cluster_elixir()],
               [{failoverServerGroup,
                 proplists:get_value(?FAILOVER_SERVER_GROUP_CONFIG_KEY,
                                     Config)} ||
                   not cluster_compat_mode:is_cluster_71()]]);
        false ->
            []
    end.

disable_extras(Config) ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            {_, CurrTP} = get_failover_on_disk_issues(Config),
            lists:flatten(
              [disable_failover_on_disk_issues(CurrTP),
               [{?CAN_ABORT_REBALANCE_CONFIG_KEY, false} ||
                   not cluster_compat_mode:is_cluster_elixir()],
               [{?FAILOVER_SERVER_GROUP_CONFIG_KEY, false} ||
                   not cluster_compat_mode:is_cluster_71()]]);
        false ->
            []
    end.
