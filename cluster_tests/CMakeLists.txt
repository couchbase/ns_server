ADD_CUSTOM_TARGET(api_test_python_requirements
        COMMAND ${PYTHON_EXE} -m ensurepip
        COMMAND ${PYTHON_EXE} -m pip
        install -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt)
ADD_CUSTOM_TARGET(api_test
        COMMAND JAVA_HOME=${Java_JAVA_HOME} ${PYTHON_EXE} ${CMAKE_CURRENT_SOURCE_DIR}/run.py
        DEPENDS api_test_python_requirements)

ADD_TEST(api_test
        "${CMAKE_COMMAND}"
        --build "${CMAKE_BINARY_DIR}"
        --target api_test)
