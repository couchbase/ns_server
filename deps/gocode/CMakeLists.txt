GoInstall (TARGET ns_goport PACKAGE goport
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin)

GoInstall (TARGET ns_generate_cert PACKAGE generate_cert
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin)

GoInstall (TARGET ns_godu PACKAGE godu
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin/priv)

GoInstall (TARGET ns_gosecrets PACKAGE gosecrets
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}" "${GODEPSDIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin)

GoInstall (TARGET ns_generate_hash PACKAGE generate_hash
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}" "${GODEPSDIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin)

GoInstall (TARGET chunked_reader PACKAGE chunked_reader
  GOPATH "${CMAKE_CURRENT_SOURCE_DIR}"
  GOVERSION SUPPORTED_NEWER
  INSTALL_PATH bin/priv)

ADD_CUSTOM_TARGET (gocode-clean
  COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_CURRENT_SOURCE_DIR}/bin")
ADD_DEPENDENCIES (ns_realclean gocode-clean)
