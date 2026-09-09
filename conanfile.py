from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMakeDeps


class gcstcpipConan(ConanFile):
    """Внешних зависимостей у стека нет: conan нужен только ради
    conan_toolchain.cmake, на который ссылаются пресеты."""

    settings = "os", "arch", "compiler", "build_type"

    def generate(self):
        CMakeToolchain(self).generate()
        CMakeDeps(self).generate()
