HOST_GCC=g++
TARGET_GCC=gcc
PLUGIN_SOURCE_FILES= struct_san.c
GCCPLUGINS_DIR:= $(shell $(TARGET_GCC) -print-file-name=plugin)
CXXFLAGS+= -I$(GCCPLUGINS_DIR)/include -fPIC -fno-rtti -g

struct_san.so: $(PLUGIN_SOURCE_FILES)
	   $(HOST_GCC) -shared $(CXXFLAGS) $^ -o $@

.PHONY:clean
clean:
	rm *.so
