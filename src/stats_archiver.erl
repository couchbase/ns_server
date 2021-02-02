%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2020 Couchbase, Inc.
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
%% @doc Store and aggregate statistics collected from stats_collector into a
%% collection of ETS tables, emitting 'sample_archived' events when aggregates
%% are created. The contents of ETS table is periodically dumped to files that
%% then used to restore ETS tables after restart.
%%

-module(stats_archiver).

-export([archives/0]).

%% This is old stats backward compat code
%% @doc the type of statistics collected
%% {Period, Seconds, Samples}
archives() ->
    [{minute, 1,     60},
     {hour,   4,     900},
     {day,    60,    1440}, % 24 hours
     {week,   600,   1152}, % eight days (computer weeks)
     {month,  1800,  1488}, % 31 days
     {year,   21600, 1464}]. % 366 days
