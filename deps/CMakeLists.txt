ADD_SUBDIRECTORY (gen_smtp)
ADD_SUBDIRECTORY (ale)

# These two need to go before any of our apps that have tests.
ADD_SUBDIRECTORY (triq)
ADD_SUBDIRECTORY (meck)

# Common deps to much of our code, they need to be included before anything
# using them.
ADD_SUBDIRECTORY(ns_common)

ADD_SUBDIRECTORY (ns_babysitter)
ADD_SUBDIRECTORY (ns_couchdb)
ADD_SUBDIRECTORY (gocode)
ADD_SUBDIRECTORY (gomodules)
ADD_SUBDIRECTORY (chronicle)
ADD_SUBDIRECTORY (enacl)
ADD_SUBDIRECTORY (esaml)
ADD_SUBDIRECTORY (iso8601)
