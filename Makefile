VERSION    := 0.1.1

# Git info for versioning
GIT_HASH   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY  := $(shell git status --porcelain 2>/dev/null)
BUILD_TYPE ?= dev
ifeq ($(BUILD_TYPE),stable)
RELEASE_VERSION := v$(VERSION)-$(if $(GIT_DIRTY),$(shell date +"%Y%m%d%H%M%S"),$(GIT_HASH))
else
RELEASE_VERSION := v$(VERSION)-$(BUILD_TYPE)-$(if $(GIT_DIRTY),$(shell date +"%Y%m%d%H%M%S"),$(GIT_HASH))
endif

# Target directory name in the zip
ZIP_DIR_NAME := ps5-yarpe-autoloader-$(RELEASE_VERSION)
ZIP_FILE     := $(ZIP_DIR_NAME).zip

SRC_FILES := $(shell find payloads src savegame_container -type f)
ELFLDR_FILE := $(shell basename $(shell ls src/elfldr-ps5-*.elf 2>/dev/null | head -n 1) 2>/dev/null)
KEXP_FILE := $(shell basename $(shell ls src/kexp-*.bin 2>/dev/null | head -n 1) 2>/dev/null)
UNIFIED_AUTOLOADER_FILE := $(shell basename $(shell ls src/ps5-unified-autoloader*.elf 2>/dev/null | head -n 1) 2>/dev/null)

# Version string baked into the save at build time
YARPE_VERSION = $(RELEASE_VERSION)
export YARPE_VERSION

all: $(ZIP_FILE)

# Stage the master payload scripts into src/ and bake in
# the dependency filenames (the staged copies are gitignored)
stage: payloads/elf_loader.py payloads/lapse.py payloads/kexp.py payloads/kexp_dispatch.py payloads/relapse.py payloads/relapse_offsets.py payloads/persistent_bootstrap.py
	cp -f payloads/elf_loader.py payloads/lapse.py payloads/kexp.py payloads/kexp_dispatch.py payloads/relapse.py payloads/relapse_offsets.py payloads/persistent_bootstrap.py src/
	echo "$(RELEASE_VERSION)" > src/version.txt
	# Replace elfldr filename in elf_loader.py, kexp.py, relapse.py
	sed -i.bak "s/@@ELFLDR_FILE@@/$(ELFLDR_FILE)/g" src/elf_loader.py && rm src/elf_loader.py.bak
	sed -i.bak "s/@@ELFLDR_FILE@@/$(ELFLDR_FILE)/g" src/kexp.py && rm src/kexp.py.bak
	sed -i.bak "s/@@ELFLDR_FILE@@/$(ELFLDR_FILE)/g" src/relapse.py && rm src/relapse.py.bak
	# Replace kexp filename in kexp.py, relapse.py
	sed -i.bak "s/@@KEXP_FILE@@/$(KEXP_FILE)/g" src/kexp.py && rm src/kexp.py.bak
	sed -i.bak "s/@@KEXP_FILE@@/$(KEXP_FILE)/g" src/relapse.py && rm src/relapse.py.bak
	# Replace unified autoloader filename in the autoload.txt template
	sed "s/@@UNIFIED_AUTOLOADER_FILE@@/$(UNIFIED_AUTOLOADER_FILE)/g" payloads/autoload.txt.in > src/autoload.txt

$(ZIP_FILE): stage $(SRC_FILES)
	python3 pack_savegame.py
	python3 pack_unzipper.py
	rm -rf build_dir $(ZIP_FILE)
	mkdir -p build_dir/$(ZIP_DIR_NAME)
	cp save.zip build_dir/$(ZIP_DIR_NAME)/
	mv 1-1-LT1_unzipper.save build_dir/$(ZIP_DIR_NAME)/1-1-LT1.save
	cp README.md SETUP.md UPDATE.md DONATE.md LICENSE build_dir/$(ZIP_DIR_NAME)/
	(cd build_dir && zip -r ../$(ZIP_FILE) $(ZIP_DIR_NAME))
	rm -rf build_dir
	echo "Created $(ZIP_FILE)"

clean:
	rm -rf build_dir ps5-yarpe-autoloader-*.zip
	rm -rf ps5-yarpe-autoloader-*/
	rm -f save.zip 1-1-LT1.save 1-1-LT1_unzipper.save ./-saveindex persistent
	rm -f src/elf_loader.py src/lapse.py src/kexp.py src/kexp_dispatch.py src/relapse.py src/relapse_offsets.py src/persistent_bootstrap.py
	rm -f src/autoload.txt src/version.txt
	rm -f src/elfldr*.elf src/kexp*.bin
	rm -f src/ps5-unified-autoloader*.elf

.PHONY: all stage clean print-version
print-version:
	@echo $(RELEASE_VERSION)
