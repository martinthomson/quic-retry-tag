ifneq (,$(DEBUG))
  NSS_TARGET := Debug
  OPT := -g
else
  NSS_TARGET := Release
  OPT := -O3
endif

NSS_INCLUDES := \
  ../dist/$(NSS_TARGET)/include/nspr \
  ../dist/public/nss \
  ../dist/private/nss \
  ../nss/lib/freebl \
  ../nss/lib/freebl/mpi
CFLAGS := -Wall -Werror -std=c99 $(OPT) $(addprefix -I,$(NSS_INCLUDES))
FREEBL_LIBS := $(addprefix ../dist/$(NSS_TARGET)/lib/,libfreebl_static.a libgcm-aes-x86_c_lib.a)
OTHER_LIBS := $(addprefix -l,nssutil3 nspr4 pthread)

.PHONY: all
all: bench
bench: bench.c
	$(CC) -m64 $(CFLAGS) -o $@ $^ $(FREEBL_LIBS) $(OTHER_LIBS)
clean:
	git clean -fX
