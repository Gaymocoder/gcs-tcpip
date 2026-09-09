# Проектный слой поверх шаблонного cmake/gcst/warnings.cmake.
#
# Шаблон рассчитан на C++. Пять его диагностик в C-режиме не просто бесполезны:
# GCC считает ошибкой само их присутствие в командной строке, причём и в форме
# "-Wno-", поэтому отрицанием проблема не решается. Флаги приходится убирать
# из списка опций цели.

set(GCS_WARN_CXX_ONLY
    -Wnon-virtual-dtor
    -Woverloaded-virtual
    -Wzero-as-null-pointer-constant
    -Wextra-semi
    -Wold-style-cast
)

function(gcs_target_c_tuning target_name)
    if(NOT MSVC)
        get_target_property(opts "${target_name}" COMPILE_OPTIONS)
        if(opts)
            foreach(flag IN LISTS GCS_WARN_CXX_ONLY)
                list(REMOVE_ITEM opts "${flag}")
            endforeach()
            # тот же флаг попадает и в чёрный список -Werror
            list(REMOVE_ITEM opts "-Wno-error=old-style-cast")
            set_target_properties("${target_name}" PROPERTIES COMPILE_OPTIONS "${opts}")
        endif()

        target_compile_options("${target_name}" PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
        target_link_options("${target_name}" PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
    endif()

    # Шаблон линкует stdc++exp через фичу cxx_std_23. У целей с LANGUAGES C
    # компилятора C++ нет, и CMake на такой запрос падает при генерации.
    if(MINGW)
        foreach(prop LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(libs "${target_name}" ${prop})
            if(libs)
                list(REMOVE_ITEM libs "$<$<COMPILE_FEATURES:cxx_std_23>:stdc++exp>")
                set_target_properties("${target_name}" PROPERTIES ${prop} "${libs}")
            endif()
        endforeach()
    endif()
endfunction()
