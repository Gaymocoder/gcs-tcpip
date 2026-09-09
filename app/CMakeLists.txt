project(GCS_TcpIp_Apps LANGUAGES C)

add_executable(gcs_replay_exe gcs_replay.c)
target_link_libraries(gcs_replay_exe PRIVATE gcsll::tcpip)
set_target_properties(gcs_replay_exe PROPERTIES OUTPUT_NAME "GCS.Replay")
gcst_binary_prepare(gcs_replay_exe)
gcs_target_c_tuning(gcs_replay_exe)

# Живой TAP-драйвер собирается только под Linux.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(gcs_tapd_exe gcs_tapd.c)
    target_link_libraries(gcs_tapd_exe PRIVATE gcsll::tcpip)
    set_target_properties(gcs_tapd_exe PROPERTIES OUTPUT_NAME "GCS.Tapd")
    gcst_binary_prepare(gcs_tapd_exe)
    gcs_target_c_tuning(gcs_tapd_exe)
endif()
