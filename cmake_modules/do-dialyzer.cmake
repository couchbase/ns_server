# Generate .plt file, if it doesn't exist
GET_FILENAME_COMPONENT (_couchdb_bin_dir "${COUCHDB_BIN_DIR}" REALPATH)

IF (NOT EXISTS "${COUCHBASE_PLT}")
  MESSAGE ("Generating ${COUCHBASE_PLT}...")
  EXECUTE_PROCESS (
    COMMAND_ECHO STDOUT
    COMMAND "${DIALYZER_EXECUTABLE}" --output_plt "${COUCHBASE_PLT}" --build_plt
    --apps compiler crypto erts inets kernel os_mon sasl ssl stdlib xmerl eldap
           public_key
    ${_couchdb_bin_dir}/src/couchdb
    ${_couchdb_bin_dir}/src/couch_set_view
    ${_couchdb_bin_dir}/src/couch_view_parser
    ${_couchdb_bin_dir}/src/couch_index_merger
    ${_couchdb_bin_dir}/src/mapreduce
    ${_couchdb_bin_dir}/src/mochiweb
    ${_couchdb_bin_dir}/src/snappy
    ${_couchdb_bin_dir}/src/etap
    ${_couchdb_bin_dir}/src/lhttpc
    ${_couchdb_bin_dir}/src/erlang-oauth
    ${_couchdb_bin_dir}/src/ejson
    # Deps that we must include to pick up functions, but do not want to analyse
    _build/default/lib/gen_smtp
    _build/default/lib/chronicle
    _build/default/lib/enacl
    _build/default/lib/esaml
    _build/default/lib/iso8601
    _build/default/lib/jose
    _build/default/lib/jiffy)
ENDIF (NOT EXISTS "${COUCHBASE_PLT}")

EXECUTE_PROCESS (RESULT_VARIABLE _failure
  COMMAND_ECHO STDOUT
  COMMAND "${DIALYZER_EXECUTABLE}" --plt "${COUCHBASE_PLT}" ${DIALYZER_FLAGS}
  --apps
        # TODO: MB-60458:
        # Ideally we would test chronicle here too (rather than just include it
        # in the plt above) but it has a couple of issues to solve first
        _build/default/lib/ns_server/
        _build/default/lib/ale/
        _build/default/lib/ns_common/
        _build/default/lib/ns_babysitter/
        _build/default/lib/ns_couchdb/
)
IF (_failure)
  MESSAGE (FATAL_ERROR "failed running dialyzer")
ENDIF (_failure)
