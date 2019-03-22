PROJECTPATH = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ifndef CHARM_BUILD_DIR
    CHARM_BUILD_DIR := $(PROJECTPATH)/builds
    $(warning Warning CHARM_BUILD_DIR was not set, defaulting to $(CHARM_BUILD_DIR))
endif

help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the unittests and lint"
	@echo " make unittest - run the tests defined in the unittest subdirectory"
	@echo " make functional - run the tests defined in the functional subdirectory"
	@echo " make release - build the charm"
	@echo " make clean - remove unneeded files"
	@echo ""

lint:
	@echo "Running flake8"
	@cd src && tox -e lint

test: unittest functional lint

unittest:
	@cd src && tox -e unit

functional: build
	@cd src && CHARM_BUILD_DIR=$(CHARM_BUILD_DIR) tox -e functional

functional_preserve: build
		@cd src && test_preserve_model=1 CHARM_BUILD_DIR=$(CHARM_BUILD_DIR) tox -e functional

build:
	@echo "Building charm to base directory $(CHARM_BUILD_DIR)"
	@CHARM_LAYERS_DIR=./layers CHARM_INTERFACES_DIR=./interfaces TERM=linux\
		CHARM_BUILD_DIR=$(CHARM_BUILD_DIR) charm build $(PROJECTPATH)/src --force

release: clean build
	@echo "Charm is built at $(CHARM_BUILD_DIR)"

clean:
	@echo "Cleaning files"
	@if [ -d $(CHARM_BUILD_DIR) ] ; then rm -r $(CHARM_BUILD_DIR) ; fi
	@if [ -d $(PROJECTPATH)/src/.tox ] ; then rm -r $(PROJECTPATH)/src/.tox ; fi
	@if [ -d $(PROJECTPATH)/src/.pytest_cache ] ; then rm -r $(PROJECTPATH)/src/.pytest_cache ; fi

# The targets below don't depend on a file
.PHONY: lint test unittest functional functional_preserve build release clean help
