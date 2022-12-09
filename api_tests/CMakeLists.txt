find_package(Python3 COMPONENTS Interpreter)
ADD_TEST(NAME api_test
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run.py)
