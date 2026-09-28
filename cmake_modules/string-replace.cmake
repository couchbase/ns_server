SET ("${SEARCH}" "${REPLACE}")

# CONFIGURE_FILE substitutes the empty string for an @VAR@ whose variable is
# unset, and cmake runs this script as its own process, so the only variables
# defined here are the ones the caller passed with -D.  Insist on a value
# before configuring, so a placeholder nobody wired up stops the build rather
# than being blanked out of the generated file.
FILE (READ "${INPUT_FILE}" _input_contents)
STRING (REGEX MATCHALL "@[A-Za-z0-9_]+@" _placeholders "${_input_contents}")
FOREACH (_placeholder IN LISTS _placeholders)
  STRING (REGEX REPLACE "^@|@$" "" _placeholder_var "${_placeholder}")
  IF (NOT DEFINED ${_placeholder_var} OR "${${_placeholder_var}}" STREQUAL "")
    GET_FILENAME_COMPONENT (_input_name "${INPUT_FILE}" NAME)
    MESSAGE (FATAL_ERROR
             "${_input_name} substitutes ${_placeholder}, which is unset or "
             "empty here.  This script only sees what the caller passes with "
             "-D, so a new placeholder has to be added there too.")
  ENDIF ()
ENDFOREACH ()

CONFIGURE_FILE ("${INPUT_FILE}" "${OUTPUT_FILE}" @ONLY)
