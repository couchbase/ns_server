%% @author Couchbase <info@couchbase.com>
%% @copyright 2012-2021 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(ns_online_config_upgrader).

%% This module implements the online upgrade of a cluster.  "Online" here
%% means "when the cluster comes online"; in other words, when it is
%% formed.  This happens after the individual nodes have gone through the
%% node upgrade process.
%%
%% The online upgrade upgrades the configuration starting with the lowest
%% possible cluster version, regardless of a node's version.  This is done
%% both when we are upgrading a node running down-rev software and when we
%% are forming a cluster composed of nodes running up-rev code.
%%
%% If we are forming a cluster containing one or mode nodes running up-rev
%% code, a node's configuration may contain entries which are up-rev
%% relative to the cluster version being upgraded.  Consequently, the
%% functions used to perform the online upgrade must ensure that they are
%% not adding configuration information which is already present in the
%% node's configuration.  If this is not done, we can end up with duplicate
%% information in the configuration.

-include("cut.hrl").
-include("ns_common.hrl").

-export([upgrade_config/1]).

upgrade_config(NewVersion) ->
    true = (NewVersion =< ?LATEST_VERSION_NUM),

    ok = ns_config:upgrade_config_explicitly(
           do_upgrade_config(_, NewVersion)).

do_upgrade_config(Config, FinalVersion) ->
    case ns_config:search(Config, cluster_compat_version) of
        {value, FinalVersion} ->
            [];
        %% The following two cases don't actually correspond to upgrade from
        %% pre-2.0 clusters, we don't support those anymore. Instead, it's an
        %% upgrade from pristine ns_config_default:default(). I tried setting
        %% cluster_compat_version to the most up-to-date compat version in
        %% default config, but that uncovered issues that I'm too scared to
        %% touch at the moment.
        false ->
            upgrade_compat_version(?VERSION_60);
        {value, undefined} ->
            upgrade_compat_version(?VERSION_60);
        {value, Ver} ->
            {NewVersion, Upgrade} = upgrade(Ver, Config),
            ok = maybe_upgrade_to_cronicle(NewVersion, Config),

            ?log_info("Performing online config upgrade to ~p", [NewVersion]),
            upgrade_compat_version(NewVersion) ++
                maybe_final_upgrade(NewVersion) ++ Upgrade
    end.

upgrade_compat_version(NewVersion) ->
    [{set, cluster_compat_version, NewVersion}].

maybe_final_upgrade(?LATEST_VERSION_NUM) ->
    ns_audit_cfg:upgrade_descriptors();
maybe_final_upgrade(_) ->
    [].

maybe_upgrade_to_cronicle(?VERSION_CHESHIRECAT, Config) ->
    chronicle_compat:upgrade(Config);
maybe_upgrade_to_cronicle(_, _) ->
    ok.

%% Note: upgrade functions must ensure that they do not add entries to the
%% configuration which are already present.

upgrade(?VERSION_60, Config) ->
    {?VERSION_65,
     menelaus_web_auto_failover:config_upgrade_to_65(Config) ++
         ns_bucket:config_upgrade_to_65(Config) ++
         auto_rebalance_settings:config_upgrade_to_65() ++
         query_settings_manager:config_upgrade_to_65(Config) ++
         menelaus_web_settings:config_upgrade_to_65(Config)};

upgrade(?VERSION_65, Config) ->
    {?VERSION_66,
     menelaus_users:config_upgrade() ++
         ns_bucket:config_upgrade_to_66(Config)};

upgrade(?VERSION_66, Config) ->
    {?VERSION_CHESHIRECAT,
     menelaus_users:config_upgrade() ++
         collections:config_upgrade_to_cheshire_cat(Config) ++
         menelaus_web_alerts_srv:config_upgrade_to_cheshire_cat(Config) ++
         index_settings_manager:config_upgrade_to_cheshire_cat(Config) ++
         query_settings_manager:config_upgrade_to_cheshire_cat(Config)}.
