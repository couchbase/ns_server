%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc chronicle metakv
%%

-module(chronicle_metakv).

-include("ns_common.hrl").

-export([upgrade_to_morpheus/3]).

upgrade_to_morpheus(_, _, _) ->
    case chronicle_agent:get_info_for_rsm(metakv) of
        {error, no_rsm} ->
            ?log_debug("Add metakv rsm to chronicle"),
            ok = chronicle:put_rsm({metakv, chronicle_kv, []});
        _ ->
            ok
    end.
