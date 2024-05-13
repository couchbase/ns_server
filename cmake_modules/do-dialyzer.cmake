# Generate .plt file, if it doesn't exist
GET_FILENAME_COMPONENT (_couchdb_bin_dir "${COUCHDB_BIN_DIR}" REALPATH)

IF (NOT EXISTS "${COUCHBASE_PLT}")
  MESSAGE ("Generating ${COUCHBASE_PLT}...")
  EXECUTE_PROCESS (
    COMMAND_ECHO STDOUT
    COMMAND "${DIALYZER_EXECUTABLE}" --output_plt "${COUCHBASE_PLT}" --build_plt
    --apps compiler crypto erts inets kernel os_mon sasl ssl stdlib xmerl eldap
           public_key
    ${_couchdb_bin_dir}/couch
    ${_couchdb_bin_dir}/couch_set_view
    ${_couchdb_bin_dir}/couch_view_parser
    ${_couchdb_bin_dir}/couch_index_merger
    ${_couchdb_bin_dir}/mapreduce
    ${_couchdb_bin_dir}/mochiweb
    ${_couchdb_bin_dir}/snappy
    ${_couchdb_bin_dir}/lhttpc
    ${_couchdb_bin_dir}/oauth
    ${_couchdb_bin_dir}/ejson
    # Deps that we must include to pick up functions, but do not want to analyse
    ${REBAR_BUILD_DIR}/default/lib/gen_smtp
    ${REBAR_BUILD_DIR}/default/lib/chronicle
    ${REBAR_BUILD_DIR}/default/lib/enacl
    ${REBAR_BUILD_DIR}/default/lib/esaml
    ${REBAR_BUILD_DIR}/default/lib/iso8601
    ${REBAR_BUILD_DIR}/default/lib/jose
    ${REBAR_BUILD_DIR}/default/lib/jiffy
    ${REBAR_BUILD_DIR}/default/lib/oidcc)
ENDIF (NOT EXISTS "${COUCHBASE_PLT}")

EXECUTE_PROCESS (RESULT_VARIABLE _failure
  COMMAND_ECHO STDOUT
  COMMAND "${DIALYZER_EXECUTABLE}" --plt "${COUCHBASE_PLT}" ${DIALYZER_FLAGS}
  --apps
        # TODO: MB-60458:
        # Ideally we would test chronicle here too (rather than just include it
        # in the plt above) but it has a couple of issues to solve first
        ${REBAR_BUILD_DIR}/default/lib/ns_server/
        ${REBAR_BUILD_DIR}/default/lib/ale/
        ${REBAR_BUILD_DIR}/default/lib/ns_common/
        ${REBAR_BUILD_DIR}/default/lib/ns_babysitter/
        ${REBAR_BUILD_DIR}/default/lib/ns_couchdb/
        ${REBAR_BUILD_DIR}/default/lib/cb_dets/
)
IF (_failure)
  MESSAGE (FATAL_ERROR "failed running dialyzer")
ENDIF (_failure)
